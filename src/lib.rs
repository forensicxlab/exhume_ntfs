// Sources:
// - https://dubeyko.com/development/FileSystems/NTFS/ntfsdoc.pdf
// - https://en.wikipedia.org/wiki/NTFS
// TODO: include more logs and error handling.

use std::collections::HashSet;
use std::error::Error;
use std::io::{Read, Seek, SeekFrom};

use log::{debug, info};
use mft::{DirectoryEntry, MftRecord};
use pbs::PartitionBootSector;

pub mod mft;
pub mod pbs;

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
            Err("The OEM Identifier is not valid".into())
        }
    }

    /// Load MFT run-list if not loaded yet
    fn ensure_mft_runs(&mut self) -> Result<(), Box<dyn Error>> {
        if self.mft_runs.is_some() {
            return Ok(());
        }

        // record 0 is always in the first extent
        let off0 = self.pbs.mft_address();
        self.body.seek(SeekFrom::Start(off0))?;
        let mut buf = vec![0u8; self.pbs.file_record_size() as usize];
        self.body.read_exact(&mut buf)?;
        let rec0 = MftRecord::from_bytes(&buf)?;

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

    pub fn get_file_id(&mut self, file_id: u64) -> Result<MftRecord, Box<dyn Error>> {
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
        let (lcn, run_len) = runs
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
        let phys_off = (*lcn as u64) * clu_size                  +  // start of the right extent
            cluster_delta   * clu_size                +  // inside that extent
            idx_in_clu      * rec_size; // inside the cluster

        self.body.seek(SeekFrom::Start(phys_off))?;
        let mut buf = vec![0u8; rec_size as usize];
        self.body.read_exact(&mut buf)?;

        info!("MFT entry {} read from LBA 0x{:X}", file_id, phys_off);
        Ok(MftRecord::from_bytes(&buf)?)
    }

    /// List every child entry of the directory whose MFT record is `dir_id`.
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
                    // ─ parse INDEX_HEADER inside ─
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
