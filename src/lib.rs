// Sources:
// - https://dubeyko.com/development/FileSystems/NTFS/ntfsdoc.pdf
// - https://en.wikipedia.org/wiki/NTFS
// TODO: include more logs and error handling.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::error::Error;
use std::io::{Read, Seek, SeekFrom};

use log::{debug, error, info};
use mft::{Attribute, AttributeType, DirectoryEntry, MFTRecord};
use pbs::PartitionBootSector;

pub mod mft;
pub mod pbs;

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
            info!("Directory {:} uses non-resident index – walking it", dir_id);

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
        // --- Locate the unnamed $DATA attribute ----------------------------
        let data_attr = record
            .attributes
            .iter()
            .find(|a| match a {
                Attribute::Resident { header, .. } | Attribute::NonResident { header, .. } => {
                    header.attr_type == AttributeType::Data && header.name_length == 0
                }
            })
            .ok_or("unnamed $DATA attribute not found")?;

        // --------------------------------------------------------------------
        // 1. Small, resident file – trivial slice
        // --------------------------------------------------------------------
        if let Attribute::Resident { value, .. } = data_attr {
            if offset >= value.len() as u64 || length == 0 {
                return Ok(Vec::new());
            }
            let start = offset as usize;
            let end = std::cmp::min(start + length, value.len());
            return Ok(value[start..end].to_vec());
        }

        // --------------------------------------------------------------------
        // 2. Non-resident file – walk the run-list on demand
        // --------------------------------------------------------------------
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

        // Walk the run-list ---------------------------------------------------
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
