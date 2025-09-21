// Sources:
// - https://dubeyko.com/development/FileSystems/NTFS/ntfsdoc.pdf
// - https://en.wikipedia.org/wiki/NTFS
// TODO: include more logs and error handling.

use log::{debug, error};
use mft::{Attribute, AttributeType, DirectoryEntry, MFTRecord};
use pbs::PartitionBootSector;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::error::Error;
use std::io::{Read, Seek, SeekFrom};
use usnjrn::{ReuseReason, ReusedElement, UsnRecord};

pub mod mft;
pub mod pbs;
pub mod usnjrn;

#[derive(Clone, Copy, Debug)]
pub enum ReuseCheck {
    Off,           // no reuse detection, fastest
    JournalOnly,   // journal-only (cheap)
    JournalAndMFT, // journal + current MFT cross-check (most accurate, slower)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NTFS<T: Read + Seek> {
    pub pbs: PartitionBootSector,
    pub body: T,
    mft_runs: Option<Vec<(i64, u64)>>, // Cached DATA run-list of the MFT itself
}

impl<T: Read + Seek> NTFS<T> {
    /// Create a new NTFS Object
    pub fn new(mut body: T) -> Result<Self, String> {
        let mut sp_data = vec![0u8; 0x400];
        body.read_exact(&mut sp_data).map_err(|e| e.to_string())?;
        let pbs = PartitionBootSector::from_bytes(&sp_data).map_err(|e| e.to_string())?;
        if pbs.oem_id_is_valid() {
            Ok(Self {
                pbs,
                body,
                mft_runs: None,
            })
        } else {
            error!("The OEM Identifier is not valid.");
            Err("The OEM Identifier is not valid.".into())
        }
    }

    /// Load MFT run-list if not loaded yet
    fn ensure_mft_runs(&mut self) -> Result<(), Box<dyn Error>> {
        if self.mft_runs.is_some() {
            debug!("Using Cached MFT run-list.");
            return Ok(());
        }
        debug!("Loading MFT run-list (not loaded).");

        // record 0 is always in the first extent
        let off0 = self.pbs.mft_address();
        self.body.seek(SeekFrom::Start(off0))?;
        let mut buf = vec![0u8; self.pbs.file_record_size() as usize];
        self.body.read_exact(&mut buf)?;
        let rec0 = MFTRecord::from_bytes(&buf, None)?;

        /* locate the non-resident DATA attribute of $MFT */
        let run_list_raw = rec0
            .attributes
            .iter()
            .find_map(|a| {
                if let mft::Attribute::NonResident {
                    header, run_list, ..
                } = a
                {
                    (header.attr_type == mft::AttributeType::Data).then_some(run_list)
                } else {
                    None
                }
            })
            .ok_or("non-resident DATA attribute not found in $MFT record 0")?;

        self.mft_runs = Some(decode_run_list(run_list_raw));
        Ok(())
    }

    pub fn mft_records_count(&mut self) -> Result<u64, Box<dyn Error>> {
        self.ensure_mft_runs()?; // make sure we have the run‑list
        let runs = self.mft_runs.as_ref().unwrap();

        let total_clusters: u64 = runs.iter().map(|(_, len)| *len as u64).sum();
        let total_bytes = total_clusters * self.pbs.cluster_size() as u64;

        Ok(total_bytes / self.pbs.file_record_size() as u64)
    }

    pub fn get_file_id(&mut self, file_id: u64) -> Result<MFTRecord, Box<dyn Error>> {
        // Making sure we know where every extent of $MFT lives
        self.ensure_mft_runs()?;
        let runs = self.mft_runs.as_ref().unwrap();

        let rec_size = self.pbs.file_record_size() as u64;
        let clu_size = self.pbs.cluster_size() as u64;
        let recs_per_clu = clu_size / rec_size;

        // Look for which virtual cluster holds this record
        let vcn = file_id / recs_per_clu;
        let idx_in_clu = file_id % recs_per_clu;

        // Walk the run-list to find the physical LCN for that VCN
        let mut base_vcn = 0u64;
        let (lcn, _run_len) = runs
            .iter()
            .find(|(_, len)| {
                let hit = vcn < base_vcn + *len as u64;
                if !hit {
                    base_vcn += *len as u64;
                }
                hit
            })
            .ok_or("VCN out of range for $MFT")?;

        let cluster_delta = (vcn - base_vcn) as u64;
        let phys_off = (*lcn as u64) * clu_size + // start of the right extent
            cluster_delta   * clu_size + // inside that extent
            idx_in_clu      * rec_size; // inside the cluster

        self.body.seek(SeekFrom::Start(phys_off))?;
        let mut buf = vec![0u8; rec_size as usize];
        self.body.read_exact(&mut buf)?;

        debug!("MFT entry {} read from LBA 0x{:X}", file_id, phys_off);
        Ok(MFTRecord::from_bytes(&buf, Some(file_id))?)
    }

    /// List every child entry of the directory whose MFT record is "dir_id".
    /// Works for both small (resident) and large (non-resident) directories.
    pub fn list_dir(&mut self, dir_id: u64) -> Result<Vec<DirectoryEntry>, Box<dyn Error>> {
        let rec = self.get_file_id(dir_id)?;

        let mut entries = rec.directory_entries().unwrap_or_default();

        let idx_alloc_attr = rec.attributes.iter().find_map(|a| {
            if let mft::Attribute::NonResident {
                header, run_list, ..
            } = a
            {
                (header.attr_type == mft::AttributeType::IndexAllocation).then_some(run_list)
            } else {
                None
            }
        });

        if let Some(run_list) = idx_alloc_attr {
            debug!("Directory {:} uses non-resident index – walking it", dir_id);

            let bytes_per_sec = self.pbs.bytes_per_sector as usize;
            let bytes_per_clu = self.pbs.cluster_size() as usize;
            let idx_rec_size = rec.index_record_size(bytes_per_clu as u32) as usize;

            // Parse every index-record we can find
            for (lcn, len) in decode_run_list(run_list) {
                let start = lcn as u64 * bytes_per_clu as u64;
                for clu in 0..len {
                    let off = start + clu * bytes_per_clu as u64;
                    self.body.seek(SeekFrom::Start(off))?;
                    let mut buf = vec![0u8; idx_rec_size];
                    self.body.read_exact(&mut buf)?;

                    if &buf[0..4] != b"INDX" {
                        continue;
                    }

                    let usa_off = u16::from_le_bytes([buf[4], buf[5]]) as usize;
                    let usa_count = u16::from_le_bytes([buf[6], buf[7]]) as usize;

                    let usn = [buf[usa_off], buf[usa_off + 1]];

                    for i in 1..usa_count {
                        let fix_offset = usa_off + 2 * i as usize;
                        let fix = [buf[fix_offset], buf[fix_offset + 1]];

                        let sec_end = i as usize * bytes_per_sec - 2;

                        if buf[sec_end] == usn[0] && buf[sec_end + 1] == usn[1] {
                            buf[sec_end] = fix[0];
                            buf[sec_end + 1] = fix[1];
                        } else {
                            // Bad signature → skip this index-record
                            continue;
                        }
                    }
                    // parse INDEX_HEADER inside
                    use byteorder::{LittleEndian, ReadBytesExt};
                    let mut cur = std::io::Cursor::new(&buf[0x18..]);
                    let ent_off = cur.read_u32::<LittleEndian>()? as usize;
                    let ent_tot = cur.read_u32::<LittleEndian>()? as usize;
                    let mut off = 0x18 + ent_off;

                    while off + 0x10 <= buf.len() && off < 0x18 + ent_off + ent_tot {
                        let slice = &buf[off..];
                        if let Some((dirent, consumed)) = mft::DirectoryEntry::from_slice(slice) {
                            let flags = dirent.flags;
                            if dirent.name != "." && dirent.name != ".." {
                                entries.push(dirent);
                            }
                            if flags & 0x02 != 0 {
                                break;
                            } // last entry
                            off += consumed;
                        } else {
                            break;
                        }
                    }
                }
            }
        }

        let mut seen = HashSet::<(u64, String)>::new();
        entries.retain(|e| seen.insert((e.file_id, e.name.clone())));

        Ok(entries)
    }

    /// Read the $DATA stream of rec and return its raw bytes.
    pub fn read_file(&mut self, record: &MFTRecord) -> Result<Vec<u8>, Box<dyn Error>> {
        // Locate the unnamed $DATA attribute
        let data_attr = record
            .attributes
            .iter()
            .find(|a| match a {
                Attribute::Resident { header, .. } | Attribute::NonResident { header, .. } => {
                    header.attr_type == AttributeType::Data && header.name_length == 0
                }
            })
            .ok_or("unnamed $DATA attribute not found")?;

        match data_attr {
            //  Resident
            Attribute::Resident { value, .. } => Ok(value.clone()),

            //  Non‑resident
            Attribute::NonResident {
                non_resident,
                run_list,
                ..
            } => {
                let cluster_size = self.pbs.cluster_size() as usize;
                let mut out = Vec::with_capacity(non_resident.real_size as usize);

                for (lcn, len) in decode_run_list(run_list) {
                    let byte_len = len as usize * cluster_size;

                    if lcn < 0 {
                        out.extend(std::iter::repeat(0u8).take(byte_len)); // sparse
                    } else {
                        let off = lcn as u64 * cluster_size as u64;
                        self.body.seek(SeekFrom::Start(off))?;
                        let mut buf = vec![0u8; byte_len];
                        self.body.read_exact(&mut buf)?;
                        out.extend_from_slice(&buf);
                    }
                }

                out.truncate(non_resident.real_size as usize);
                Ok(out)
            }
        }
    }

    /// Read `length` bytes from the unnamed $DATA stream of `record`,
    /// starting at `offset`.  Holes (sparse clusters) are returned as 0x00.
    pub fn read_file_slice(
        &mut self,
        record: &MFTRecord,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        // Locate the unnamed $DATA attribute
        let data_attr = record
            .attributes
            .iter()
            .find(|a| match a {
                Attribute::Resident { header, .. } | Attribute::NonResident { header, .. } => {
                    header.attr_type == AttributeType::Data && header.name_length == 0
                }
            })
            .ok_or("unnamed $DATA attribute not found")?;

        // 1. Small, resident file – trivial slice
        if let Attribute::Resident { value, .. } = data_attr {
            if offset >= value.len() as u64 || length == 0 {
                return Ok(Vec::new());
            }
            let start = offset as usize;
            let end = std::cmp::min(start + length, value.len());
            return Ok(value[start..end].to_vec());
        }

        // 2. Non-resident file – walk the run-list on demand
        let Attribute::NonResident {
            non_resident,
            run_list,
            ..
        } = data_attr
        else {
            unreachable!();
        };

        let file_size = non_resident.real_size;
        if offset >= file_size || length == 0 {
            return Ok(Vec::new());
        }

        let wanted = std::cmp::min(length as u64, file_size - offset) as usize;
        let mut out = vec![0u8; wanted];

        let cluster_size = self.pbs.cluster_size() as u64;
        let first_vcn = offset / cluster_size;
        let last_vcn = (offset + wanted as u64 - 1) / cluster_size;

        // Closure: copy bytes from one full cluster buffer into our slice ----
        let copy_from_cluster =
            |dst: &mut [u8], cluster_buf: &[u8], cluster_global_off: u64, req_off: u64| {
                let rel_start = if req_off > cluster_global_off {
                    (req_off - cluster_global_off) as usize
                } else {
                    0
                };
                let dst_off = (cluster_global_off + rel_start as u64 - req_off) as usize;
                let copy_len = std::cmp::min(cluster_buf.len() - rel_start, dst.len() - dst_off);
                dst[dst_off..dst_off + copy_len]
                    .copy_from_slice(&cluster_buf[rel_start..rel_start + copy_len]);
            };

        // Walk the run-list
        let mut cur_vcn = 0u64;
        for (lcn, run_len) in decode_run_list(run_list) {
            let run_first = cur_vcn;
            let run_last = cur_vcn + run_len - 1;
            if run_last < first_vcn || run_first > last_vcn {
                cur_vcn += run_len;
                continue; // no overlap
            }

            for i in 0..run_len {
                let vcn = cur_vcn + i;
                if vcn < first_vcn || vcn > last_vcn {
                    continue;
                }

                let global_byte_off = vcn * cluster_size;
                let cluster_off_in_out = global_byte_off.saturating_sub(offset);
                if cluster_off_in_out as usize >= wanted {
                    continue;
                }

                if lcn < 0 {
                    // sparse cluster
                    // already zero-initialised – nothing to copy
                    continue;
                }

                let phys_off = (lcn as u64 + i) * cluster_size;
                self.body.seek(SeekFrom::Start(phys_off))?;
                let mut buf = vec![0u8; cluster_size as usize];
                self.body.read_exact(&mut buf)?;
                copy_from_cluster(&mut out, &buf, global_byte_off, offset);
            }
            cur_vcn += run_len;
            if cur_vcn > last_vcn {
                break; // done
            }
        }

        Ok(out)
    }

    /// Convenience wrapper: read the first `length` bytes of the file.
    pub fn read_file_prefix(
        &mut self,
        record: &MFTRecord,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        self.read_file_slice(record, 0, length)
    }

    /// Read a named $DATA stream (Alternate Data Stream) by its name (e.g., "$J").
    pub fn read_named_stream(
        &mut self,
        record: &MFTRecord,
        stream_name: &str,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        use crate::mft::{Attribute, AttributeType};

        let data_attr = record
            .attributes
            .iter()
            .find(|a| match a {
                Attribute::Resident { header, .. } | Attribute::NonResident { header, .. } => {
                    header.attr_type == AttributeType::Data
                        && header.name_length > 0
                        && header
                            .name
                            .as_deref()
                            .map(|n| n.eq_ignore_ascii_case(stream_name))
                            .unwrap_or(false)
                }
            })
            .ok_or_else(|| format!("named $DATA stream '{}' not found", stream_name))?;

        match data_attr {
            Attribute::Resident { value, .. } => Ok(value.clone()),
            Attribute::NonResident {
                non_resident,
                run_list,
                ..
            } => {
                let cluster_size = self.pbs.cluster_size() as usize;
                let mut out = Vec::with_capacity(non_resident.real_size as usize);

                for (lcn, len) in decode_run_list(run_list) {
                    let byte_len = len as usize * cluster_size;

                    if lcn < 0 {
                        out.extend(std::iter::repeat(0u8).take(byte_len)); // sparse
                    } else {
                        let off = lcn as u64 * cluster_size as u64;
                        self.body.seek(SeekFrom::Start(off))?;
                        let mut buf = vec![0u8; byte_len];
                        self.body.read_exact(&mut buf)?;
                        out.extend_from_slice(&buf);
                    }
                }

                out.truncate(non_resident.real_size as usize);
                Ok(out)
            }
        }
    }

    /// Return raw bytes of $UsnJrnl:$J, where `$UsnJrnl` is provided via its **MFT record id**.
    pub fn usn_journal_raw_from_file_id(
        &mut self,
        file_id: u64,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let rec = self.get_file_id(file_id)?;
        // The named stream for the journal data is **"$J"**
        self.read_named_stream(&rec, "$J")
    }

    pub fn usn_journal_from_file_id(
        &mut self,
        file_id: u64,
        mode: ReuseCheck,
    ) -> Result<Vec<crate::usnjrn::UsnRecord>, Box<dyn std::error::Error>> {
        let raw = self.usn_journal_raw_from_file_id(file_id)?;
        let mut recs = crate::usnjrn::parse_usn_journal(&raw);

        match mode {
            ReuseCheck::Off => {
                // Just build paths; no reuse computation
                self.enrich_usn_paths_from_parent_ref(&mut recs);
            }
            ReuseCheck::JournalOnly => {
                let reuse_index = crate::usnjrn::build_reuse_index(&recs);
                self.enrich_usn_paths_from_parent_ref(&mut recs);
                for r in recs.iter_mut() {
                    // enrich *without* current MFT seq comparisons
                    self.enrich_paths_with_reuse(r, &reuse_index); // ensure this helper avoids “CurrentSeqDiffersFromUsn”
                }
            }
            ReuseCheck::JournalAndMFT => {
                let reuse_index = crate::usnjrn::build_reuse_index(&recs);
                self.enrich_usn_paths_from_parent_ref(&mut recs);
                // Optional: also mark via current MFT first (use your helper if you added it)
                // self.mark_reuse_via_current_mft(&mut recs);
                for r in recs.iter_mut() {
                    // enrich WITH current MFT seq comparisons
                    self.enrich_paths_with_reuse(r, &reuse_index); // make sure this helper includes CurrentSeqDiffersFromUsn
                }
            }
        }

        Ok(recs)
    }

    /// Build a full NTFS path (e.g., `\Windows\System32`) starting from a **directory** MFT id.
    /// This follows the *parent* links only. It does not append a filename.
    fn build_parent_path_from_parent_ref(&mut self, mut parent_id: u64) -> Option<String> {
        // Quick guards
        if parent_id == 0 {
            return Some("\\".to_string()); // unknown -> treat as root-ish
        }

        let mut parts: Vec<String> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut steps = 0usize;

        loop {
            steps += 1;
            if steps > 8192 {
                break;
            } // safety
            if parent_id == 5 {
                // prepend root and stop
                parts.reverse();
                let mut p = String::from("\\");
                p.push_str(&parts.join("\\"));
                return Some(p);
            }
            if !seen.insert(parent_id) {
                break; // cycle guard
            }

            let rec = match self.get_file_id(parent_id) {
                Ok(r) => r,
                Err(_) => break,
            };

            if let Some(name) = rec.primary_name() {
                if !name.is_empty() && name != "." && name != ".." {
                    parts.push(name);
                }
            }

            match rec.parent_file_id() {
                Some(pid) if pid != parent_id => parent_id = pid,
                _ => break,
            }
        }

        // If we got here without hitting root, we still return what we have.
        parts.reverse();
        let mut p = String::from("\\");
        if !parts.is_empty() {
            p.push_str(&parts.join("\\"));
        }
        Some(p)
    }

    /// Get the current primary file name for an MFT record id.
    fn current_name_from_file_ref(&mut self, file_id: u64) -> Option<String> {
        self.get_file_id(file_id).ok()?.primary_name()
    }

    /// Enrich USN records strictly from parent_ref and file_ref:
    /// - parent_path: walk from parent_ref up to root
    /// - name: use USN name if present, otherwise fetch from MFT
    /// - full_path: parent_path + name (or entire path from file_ref if resolvable)
    pub fn enrich_usn_paths_from_parent_ref(&mut self, recs: &mut [UsnRecord]) {
        for r in recs.iter_mut() {
            // 1) Parent path from parent_ref
            if r.parent_path.is_none() {
                let parent_id = r.parent_ref_u64(); // mask to 48 bits already
                r.parent_path = self.build_parent_path_from_parent_ref(parent_id);
            }

            // 2) Ensure we have the component name
            if r.name.is_none() {
                r.name = self.current_name_from_file_ref(r.file_ref_u64());
            }

            // 3) Full path
            if r.full_path.is_none() {
                // Prefer reconstructing via file_ref (gets correct component even for v4)
                if let Some(fp) = self
                    .build_parent_path_from_parent_ref(r.parent_ref_u64())
                    .and_then(|pp| r.name.as_deref().map(|n| join_parent_and_name(&pp, n)))
                {
                    r.full_path = Some(fp);
                } else if let Some(fp) =
                    self.current_name_from_file_ref(r.file_ref_u64())
                        .and_then(|n| {
                            self.build_parent_path_from_parent_ref(r.parent_ref_u64())
                                .map(|pp| join_parent_and_name(&pp, &n))
                        })
                {
                    r.full_path = Some(fp);
                }
            }
        }
    }

    /// Current MFT sequence for a record id (48-bit index).
    fn current_mft_seq(&mut self, file_id: u64) -> Option<u16> {
        let rec = self.get_file_id(file_id).ok()?;
        Some(rec.header.sequence_number)
    }

    /// Enrich a single USN record with paths and a list of reused elements encountered while
    /// walking the parent chain. Uses:
    ///   - journal-wide reuse index (multiple sequences seen) for *any* path component
    ///   - direct USN vs current MFT sequence check for the *file itself* and *immediate parent*
    fn enrich_paths_with_reuse(
        &mut self,
        r: &mut UsnRecord,
        reuse_index: &std::collections::HashMap<u64, std::collections::HashSet<u16>>,
    ) {
        // 1) Build parent path via current MFT (your existing logic)
        if r.parent_path.is_none() || r.full_path.is_none() || r.name.is_none() {
            // Use existing function to populate parent_path/name/full_path.
            // It already prefers current MFT for missing bits.
            self.enrich_usn_paths_from_parent_ref(std::slice::from_mut(r));
        }

        // 2) Walk the chain again (via current MFT) to collect reused elements.
        let mut reused: Vec<ReusedElement> = Vec::new();

        // Helper to push a reused element if conditions match
        let mut maybe_push = |index: u64,
                              name: Option<String>,
                              journal_seqs: Option<&std::collections::HashSet<u16>>,
                              reasons: Vec<ReuseReason>,
                              cur_seq: Option<u16>| {
            let mut rs = reasons;
            let mut seen = Vec::<u16>::new();
            if let Some(s) = journal_seqs {
                if s.len() > 1 {
                    if !rs
                        .iter()
                        .any(|r| matches!(r, ReuseReason::MultipleSequencesInJournal))
                    {
                        rs.push(ReuseReason::MultipleSequencesInJournal);
                    }
                    seen.extend(s.iter().copied());
                    seen.sort_unstable();
                    seen.dedup();
                }
            }
            if !rs.is_empty() {
                reused.push(ReusedElement {
                    index,
                    current_seq: cur_seq,
                    seen_sequences: seen,
                    name,
                    reason: rs,
                });
            }
        };

        // 2a) File itself
        let file_idx = r.file_ref_u64();
        let file_cur_seq = self.current_mft_seq(file_idx);
        let mut file_reasons = Vec::new();
        if let Some(cur) = file_cur_seq {
            if cur != r.file_ref_seq() {
                file_reasons.push(ReuseReason::CurrentSeqDiffersFromUsn);
            }
        }
        let file_journal_seqs = reuse_index.get(&file_idx);
        maybe_push(
            file_idx,
            r.name.clone(),
            file_journal_seqs,
            file_reasons,
            file_cur_seq,
        );

        // 2b) Immediate parent
        let parent_idx = r.parent_ref_u64();
        let parent_cur_seq = self.current_mft_seq(parent_idx);
        let mut parent_reasons = Vec::new();
        if let Some(cur) = parent_cur_seq {
            if cur != r.parent_ref_seq() {
                parent_reasons.push(ReuseReason::CurrentSeqDiffersFromUsn);
            }
        }
        // Name for the immediate parent (try current MFT)
        let parent_name = self
            .get_file_id(parent_idx)
            .ok()
            .and_then(|rec| rec.primary_name());
        let parent_journal_seqs = reuse_index.get(&parent_idx);
        maybe_push(
            parent_idx,
            parent_name,
            parent_journal_seqs,
            parent_reasons,
            parent_cur_seq,
        );

        // 2c) All higher ancestors: we don’t have USN-time sequences on this record,
        // but if the journal-wide map says the index had multiple sequences, flag it.
        // We reuse your parent-walk (current MFT) to climb up and collect names.
        let mut chain_names: Vec<(u64, Option<String>)> = Vec::new();
        // Re-walk parent chain using your helper (stop at root)
        if let Some(mut pid) = Some(parent_idx) {
            let mut seen = std::collections::HashSet::new();
            let mut steps = 0usize;
            while pid != 0 && pid != 5 && steps < 8192 && seen.insert(pid) {
                steps += 1;
                // Record this ancestor
                let name = self
                    .get_file_id(pid)
                    .ok()
                    .and_then(|rec| rec.primary_name());
                chain_names.push((pid, name.clone()));

                // Next parent
                if let Some(next) = self
                    .get_file_id(pid)
                    .ok()
                    .and_then(|rec| rec.parent_file_id())
                {
                    pid = next;
                } else {
                    break;
                }
            }
        }
        // For each ancestor (excluding immediate parent—we already did it), push if journal says reused
        for (idx, name) in chain_names.into_iter().skip(1) {
            if let Some(seqs) = reuse_index.get(&idx) {
                if seqs.len() > 1 {
                    maybe_push(idx, name, Some(seqs), vec![], self.current_mft_seq(idx));
                }
            }
        }

        if !reused.is_empty() {
            r.reused_records = Some(reused);
        } else {
            r.reused_records = Some(Vec::new());
        }
    }
}

/// Combine a parent path and a file name safely.
fn join_parent_and_name(parent: &str, name: &str) -> String {
    if parent.is_empty() || parent == "\\" {
        format!("\\{}", name)
    } else if parent.ends_with('\\') {
        format!("{}{}", parent, name)
    } else {
        format!("{}\\{}", parent, name)
    }
}

// helper: decode the run-list into (LCN, length_in_clusters) pairs
fn decode_run_list(raw: &[u8]) -> Vec<(i64, u64)> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    let mut cur_lcn: i64 = 0;
    while pos < raw.len() && raw[pos] != 0 {
        let hdr = raw[pos];
        pos += 1;
        let len_sz = (hdr & 0x0F) as usize;
        let ofs_sz = (hdr >> 4) as usize;

        let mut run_len = 0u64;
        for i in 0..len_sz {
            run_len |= (raw[pos + i] as u64) << (8 * i);
        }
        pos += len_sz;

        let mut ofs = 0i64;
        for i in 0..ofs_sz {
            ofs |= (raw[pos + i] as i64) << (8 * i);
        }
        // sign-extend negative offsets
        if ofs_sz > 0 && (raw[pos + ofs_sz - 1] & 0x80) != 0 {
            ofs |= !0 << (ofs_sz * 8);
        }
        pos += ofs_sz;

        cur_lcn += ofs;
        out.push((cur_lcn, run_len));
    }
    out
}
