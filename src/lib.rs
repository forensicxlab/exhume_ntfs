// Sources:
// - https://dubeyko.com/development/FileSystems/NTFS/ntfsdoc.pdf
// - https://en.wikipedia.org/wiki/NTFS
// TODO: include more logs and error handling.

use log::{debug, error, warn};
use mft::{Attribute, AttributeListEntry, AttributeType, DirectoryEntry, MFTRecord};
use pbs::PartitionBootSector;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::io::{Read, Seek, SeekFrom};
use usnjrn::{ReuseReason, ReusedElement, UsnRecord};

pub mod bitlocker;
pub mod mft;
pub mod pbs;
pub mod usnjrn;

const MAX_ATTRIBUTE_LIST_BYTES: usize = 16 * 1024 * 1024;
const MAX_ATTRIBUTE_LIST_ENTRIES: usize = 131_072;
const MAX_ATTRIBUTE_LIST_RECORDS: usize = 4_096;
const MAX_ACTIVE_INDEX_RECORDS: usize = 4_194_304;
/// Whole-stream APIs materialize a single `Vec`. Larger files remain fully
/// accessible through `read_file_slice`, without trusting evidence-controlled
/// sizes to trigger an unbounded allocation.
const MAX_EAGER_STREAM_BYTES: usize = 1024 * 1024 * 1024;

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
            validate_ntfs_geometry(&pbs)?;
            Ok(Self {
                pbs,
                body,
                mft_runs: None,
            })
        } else if pbs.is_bitlocker() {
            error!(
                "The partition is BitLocker-encrypted (OEM ID: -FVE-FS-). \
                 NTFS metadata cannot be read without decryption."
            );
            Err("The partition is BitLocker-encrypted (OEM ID: -FVE-FS-). \
                 NTFS metadata cannot be read without decryption."
                .into())
        } else {
            error!(
                "The OEM Identifier is not valid (found: {:?}).",
                String::from_utf8_lossy(&pbs.oem_id).trim()
            );
            Err(format!(
                "The OEM Identifier is not valid (found: {:?}).",
                String::from_utf8_lossy(&pbs.oem_id).trim()
            ))
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
        let off0 = self
            .pbs
            .checked_mft_address()
            .ok_or("MFT byte address overflow")?;
        let volume_size = self
            .pbs
            .total_sectors
            .checked_mul(u64::from(self.pbs.bytes_per_sector))
            .ok_or("NTFS volume size overflow")?;
        let record_end = off0
            .checked_add(u64::from(self.pbs.file_record_size()))
            .ok_or("MFT bootstrap-record end overflow")?;
        if record_end > volume_size {
            return Err("MFT bootstrap record lies outside the NTFS volume".into());
        }
        self.body.seek(SeekFrom::Start(off0))?;
        let mut buf = vec![0u8; self.pbs.file_record_size() as usize];
        self.body.read_exact(&mut buf)?;
        let rec0 = MFTRecord::from_bytes_with_sector_size(
            &buf,
            None,
            usize::from(self.pbs.bytes_per_sector),
        )?;

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

        self.mft_runs = Some(decode_run_list(run_list_raw)?);
        Ok(())
    }

    pub fn mft_records_count(&mut self) -> Result<u64, Box<dyn Error>> {
        self.ensure_mft_runs()?; // make sure we have the run‑list
        let runs = self.mft_runs.as_ref().unwrap();

        let total_clusters = runs.iter().try_fold(0u64, |total, (_, length)| {
            total
                .checked_add(*length)
                .ok_or("MFT cluster count overflow")
        })?;
        let total_bytes = total_clusters
            .checked_mul(self.pbs.cluster_size() as u64)
            .ok_or("MFT byte size overflow")?;

        Ok(total_bytes / self.pbs.file_record_size() as u64)
    }

    /// Read and parse one physical MFT record without following
    /// `$ATTRIBUTE_LIST`. Most callers should use [`Self::get_file_id`].
    pub fn get_file_id_raw(&mut self, file_id: u64) -> Result<MFTRecord, Box<dyn Error>> {
        let file_id = file_id & 0x0000_FFFF_FFFF_FFFF;
        // Making sure we know where every extent of $MFT lives
        self.ensure_mft_runs()?;
        let runs = self.mft_runs.as_ref().unwrap();

        let rec_size = self.pbs.file_record_size() as u64;
        let clu_size = self.pbs.cluster_size() as u64;
        if rec_size == 0 || clu_size == 0 {
            return Err("invalid zero NTFS record/cluster size".into());
        }
        let logical_offset = file_id
            .checked_mul(rec_size)
            .ok_or("MFT record offset overflow")?;
        let mut remaining = usize::try_from(rec_size).map_err(|_| "MFT record too large")?;
        let mut logical_cursor = logical_offset;
        let mut mft_stream_offset = 0u64;
        let mut buf = Vec::with_capacity(remaining);

        for (lcn, run_clusters) in runs {
            let run_bytes = run_clusters
                .checked_mul(clu_size)
                .ok_or("MFT run byte size overflow")?;
            let run_end = mft_stream_offset
                .checked_add(run_bytes)
                .ok_or("MFT run offset overflow")?;
            if logical_cursor >= run_end {
                mft_stream_offset = run_end;
                continue;
            }
            if logical_cursor < mft_stream_offset {
                return Err("overlapping MFT run mapping".into());
            }
            if *lcn < 0 {
                return Err("$MFT contains a sparse record extent".into());
            }

            let within_run = logical_cursor - mft_stream_offset;
            let available = run_bytes - within_run;
            let take = usize::try_from(available.min(remaining as u64))
                .map_err(|_| "MFT read size overflow")?;
            let physical_offset = (*lcn as u64)
                .checked_mul(clu_size)
                .and_then(|offset| offset.checked_add(within_run))
                .ok_or("MFT physical offset overflow")?;
            self.body.seek(SeekFrom::Start(physical_offset))?;
            let old_len = buf.len();
            buf.resize(old_len + take, 0);
            self.body.read_exact(&mut buf[old_len..])?;
            remaining -= take;
            logical_cursor = logical_cursor
                .checked_add(take as u64)
                .ok_or("MFT logical read overflow")?;
            mft_stream_offset = run_end;
            if remaining == 0 {
                break;
            }
        }
        if remaining != 0 {
            return Err("MFT record extends beyond the $MFT data stream".into());
        }

        debug!(
            "MFT entry {} read from logical offset 0x{:X}",
            file_id, logical_offset
        );
        Ok(MFTRecord::from_bytes_with_sector_size(
            &buf,
            Some(file_id),
            usize::from(self.pbs.bytes_per_sector),
        )?)
    }

    /// Read a logical MFT record, resolving and validating any extension
    /// records named by `$ATTRIBUTE_LIST`.
    pub fn get_file_id(&mut self, file_id: u64) -> Result<MFTRecord, Box<dyn Error>> {
        let raw = self.get_file_id_raw(file_id)?;
        self.hydrate_attribute_list(raw)
    }

    fn hydrate_attribute_list(
        &mut self,
        mut logical: MFTRecord,
    ) -> Result<MFTRecord, Box<dyn Error>> {
        // An extension segment has no independent logical identity. Keep raw
        // access available for forensic inspection, but do not recursively
        // reinterpret it as a base record.
        if logical.header.base_file_record != 0
            || !logical
                .attributes
                .iter()
                .any(|attribute| attribute.header().attr_type == AttributeType::AttributeList)
        {
            return Ok(logical);
        }

        let base_id = logical.id;
        let base_sequence = logical.header.sequence_number;
        let base_attribute_count = logical.attributes.len();
        let mut extension_cache = HashMap::<u64, MFTRecord>::new();
        let mut merged = HashSet::<(u64, AttributeType, Option<String>, u64, u16)>::new();

        for _round in 0..=MAX_ATTRIBUTE_LIST_RECORDS {
            let list_extents = logical
                .attributes
                .iter()
                .filter(|attribute| {
                    attribute.header().attr_type == AttributeType::AttributeList
                        && attribute.header().name.is_none()
                })
                .cloned()
                .collect::<Vec<_>>();
            if list_extents.is_empty() {
                break;
            }
            let list_bytes = self.read_attribute_stream_bounded_policy(
                &list_extents,
                MAX_ATTRIBUTE_LIST_BYTES,
                true,
            )?;
            let entries = mft::parse_attribute_list(&list_bytes, MAX_ATTRIBUTE_LIST_ENTRIES)?;
            let mut added_attribute = false;

            for entry in entries {
                if entry.segment_reference == base_id {
                    if entry.segment_sequence != base_sequence {
                        return Err(format!(
                            "ATTRIBUTE_LIST base sequence mismatch for record {base_id}: expected {base_sequence}, found {}",
                            entry.segment_sequence
                        )
                        .into());
                    }
                    let matches = logical.attributes[..base_attribute_count]
                        .iter()
                        .filter(|attribute| attribute_matches_list_entry(attribute, &entry))
                        .count();
                    if matches != 1 {
                        return Err(format!(
                            "ATTRIBUTE_LIST base tuple resolves to {matches} attributes in record {base_id}"
                        )
                        .into());
                    }
                    continue;
                }
                if entry.segment_reference == 0 {
                    return Err("ATTRIBUTE_LIST contains a null extension reference".into());
                }

                if !extension_cache.contains_key(&entry.segment_reference) {
                    if extension_cache.len() >= MAX_ATTRIBUTE_LIST_RECORDS {
                        return Err("ATTRIBUTE_LIST extension-record limit exceeded".into());
                    }
                    let extension = self.get_file_id_raw(entry.segment_reference)?;
                    if extension.header.sequence_number != entry.segment_sequence {
                        return Err(format!(
                            "ATTRIBUTE_LIST sequence mismatch for extension {}: expected {}, found {}",
                            entry.segment_reference,
                            entry.segment_sequence,
                            extension.header.sequence_number
                        )
                        .into());
                    }
                    if extension.header.flags & 0x0001 == 0 {
                        return Err(format!(
                            "ATTRIBUTE_LIST extension {} is not in use",
                            entry.segment_reference
                        )
                        .into());
                    }
                    let (extension_base, extension_base_sequence) =
                        split_file_reference(extension.header.base_file_record);
                    if extension_base != base_id || extension_base_sequence != base_sequence {
                        return Err(format!(
                            "extension {} belongs to base {} (seq {}), not {} (seq {})",
                            entry.segment_reference,
                            extension_base,
                            extension_base_sequence,
                            base_id,
                            base_sequence
                        )
                        .into());
                    }
                    extension_cache.insert(entry.segment_reference, extension);
                }

                let extension = extension_cache
                    .get(&entry.segment_reference)
                    .ok_or("ATTRIBUTE_LIST extension cache inconsistency")?;
                if extension.header.sequence_number != entry.segment_sequence {
                    return Err(format!(
                        "ATTRIBUTE_LIST cached sequence mismatch for extension {}: expected {}, found {}",
                        entry.segment_reference,
                        entry.segment_sequence,
                        extension.header.sequence_number
                    )
                    .into());
                }
                let matching = extension
                    .attributes
                    .iter()
                    .filter(|attribute| attribute_matches_list_entry(attribute, &entry))
                    .collect::<Vec<_>>();
                if matching.len() != 1 {
                    return Err(format!(
                        "ATTRIBUTE_LIST tuple resolves to {} attributes in extension {}",
                        matching.len(),
                        entry.segment_reference
                    )
                    .into());
                }

                let key = (
                    entry.segment_reference,
                    entry.attr_type,
                    entry.name.clone(),
                    entry.lowest_vcn,
                    entry.attribute_id,
                );
                if merged.insert(key) {
                    logical.attributes.push((*matching[0]).clone());
                    added_attribute = true;
                }
                if !logical
                    .extension_record_ids
                    .contains(&entry.segment_reference)
                {
                    logical.extension_record_ids.push(entry.segment_reference);
                }
            }

            if !added_attribute {
                // Discovery may temporarily tolerate a missing tail so an
                // ATTRIBUTE_LIST can name its own later extents. At the fixed
                // point, require full stream coverage before accepting it.
                self.read_attribute_stream_bounded(&list_extents, MAX_ATTRIBUTE_LIST_BYTES)?;
                logical.extension_record_ids.sort_unstable();
                return Ok(logical);
            }
        }

        Err("ATTRIBUTE_LIST hydration did not converge within its record limit".into())
    }

    fn read_attribute_stream_bounded(
        &mut self,
        attributes: &[Attribute],
        maximum_size: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        self.read_attribute_stream_bounded_policy(attributes, maximum_size, false)
    }

    fn read_attribute_stream_bounded_policy(
        &mut self,
        attributes: &[Attribute],
        maximum_size: usize,
        allow_missing_tail: bool,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        if attributes.is_empty() {
            return Err("attribute stream has no extents".into());
        }
        let resident = attributes
            .iter()
            .filter_map(|attribute| match attribute {
                Attribute::Resident { value, .. } => Some(value),
                Attribute::NonResident { .. } => None,
            })
            .collect::<Vec<_>>();
        if !resident.is_empty() {
            if resident.len() != 1 || attributes.len() != 1 {
                return Err("attribute stream mixes resident and non-resident extents".into());
            }
            if resident[0].len() > maximum_size {
                return Err("attribute stream exceeds configured size limit".into());
            }
            return Ok(resident[0].clone());
        }

        let size = nonresident_stream_size(attributes, self.pbs.cluster_size() as u64)?;
        let size_usize = usize::try_from(size).map_err(|_| "attribute stream is too large")?;
        let volume_size = self
            .pbs
            .total_sectors
            .checked_mul(u64::from(self.pbs.bytes_per_sector))
            .ok_or("NTFS volume size overflow")?;
        if size > volume_size {
            return Err("attribute stream is larger than its NTFS volume".into());
        }
        if size_usize > maximum_size {
            return Err(format!(
                "attribute stream exceeds configured {maximum_size}-byte size limit; use a slice/streaming reader"
            )
            .into());
        }
        self.read_nonresident_stream_slice_policy(attributes, 0, size_usize, allow_missing_tail)
    }

    fn read_attribute_stream_slice(
        &mut self,
        attributes: &[Attribute],
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        if attributes.is_empty() {
            return Err("attribute stream has no extents".into());
        }
        let resident = attributes
            .iter()
            .filter_map(|attribute| match attribute {
                Attribute::Resident { value, .. } => Some(value),
                Attribute::NonResident { .. } => None,
            })
            .collect::<Vec<_>>();
        if !resident.is_empty() {
            if resident.len() != 1 || attributes.len() != 1 {
                return Err("attribute stream mixes resident and non-resident extents".into());
            }
            if length == 0 || offset >= resident[0].len() as u64 {
                return Ok(Vec::new());
            }
            let start = usize::try_from(offset).map_err(|_| "resident slice offset too large")?;
            let end = start.saturating_add(length).min(resident[0].len());
            return Ok(resident[0][start..end].to_vec());
        }
        self.read_nonresident_stream_slice(attributes, offset, length)
    }

    fn read_nonresident_stream_slice(
        &mut self,
        attributes: &[Attribute],
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        self.read_nonresident_stream_slice_policy(attributes, offset, length, false)
    }

    fn read_nonresident_stream_slice_policy(
        &mut self,
        attributes: &[Attribute],
        offset: u64,
        length: usize,
        allow_missing_tail: bool,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let cluster_size = self.pbs.cluster_size() as u64;
        if cluster_size == 0 {
            return Err("NTFS cluster size is zero".into());
        }
        let mut extents = attributes
            .iter()
            .map(|attribute| match attribute {
                Attribute::NonResident {
                    header,
                    non_resident,
                    run_list,
                } => Ok((header, non_resident, run_list)),
                Attribute::Resident { .. } => {
                    Err("resident attribute passed to non-resident reader")
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        extents.sort_by_key(|(_, non_resident, _)| non_resident.lowest_vcn);
        validate_nonresident_extents(&extents)?;

        let file_size = nonresident_stream_size(attributes, cluster_size)?;
        if offset >= file_size || length == 0 {
            return Ok(Vec::new());
        }
        let wanted_u64 = (length as u64).min(file_size - offset);
        let wanted = usize::try_from(wanted_u64).map_err(|_| "requested stream slice too large")?;
        let request_end = offset
            .checked_add(wanted_u64)
            .ok_or("requested stream range overflow")?;
        let initialized_size = extents
            .iter()
            .find(|(_, non_resident, _)| non_resident.lowest_vcn == 0)
            .map(|(_, non_resident, _)| non_resident.initialized_size.min(file_size))
            .unwrap_or(file_size);
        let readable_end = request_end.min(initialized_size);
        if !allow_missing_tail {
            ensure_nonresident_coverage(&extents, offset, readable_end, cluster_size)?;
        }
        let mut output = try_zeroed_buffer(wanted)?;

        for (_, non_resident, run_list) in extents {
            let mut run_vcn = non_resident.lowest_vcn;
            for (lcn, run_clusters) in decode_run_list(run_list)? {
                let run_start = run_vcn
                    .checked_mul(cluster_size)
                    .ok_or("run logical offset overflow")?;
                let run_bytes = run_clusters
                    .checked_mul(cluster_size)
                    .ok_or("run byte length overflow")?;
                let run_end = run_start
                    .checked_add(run_bytes)
                    .ok_or("run logical end overflow")?;
                let copy_start = run_start.max(offset);
                let copy_end = run_end.min(readable_end);
                if copy_start < copy_end && lcn >= 0 {
                    let physical_offset = (lcn as u64)
                        .checked_mul(cluster_size)
                        .and_then(|physical| physical.checked_add(copy_start - run_start))
                        .ok_or("run physical offset overflow")?;
                    let destination_start = usize::try_from(copy_start - offset)
                        .map_err(|_| "stream destination offset overflow")?;
                    let copy_length = usize::try_from(copy_end - copy_start)
                        .map_err(|_| "stream copy length overflow")?;
                    let destination_end = destination_start
                        .checked_add(copy_length)
                        .ok_or("stream destination end overflow")?;
                    self.body.seek(SeekFrom::Start(physical_offset))?;
                    self.body
                        .read_exact(&mut output[destination_start..destination_end])?;
                    // Sparse runs remain zero-filled.
                }
                run_vcn = run_vcn
                    .checked_add(run_clusters)
                    .ok_or("run VCN overflow")?;
            }
        }
        Ok(output)
    }

    /// List every child entry of the directory whose MFT record is "dir_id".
    /// Works for both small (resident) and large (non-resident) directories.
    pub fn list_dir(&mut self, dir_id: u64) -> Result<Vec<DirectoryEntry>, Box<dyn Error>> {
        let rec = self.get_file_id(dir_id)?;

        let mut entries = rec.directory_entries().unwrap_or_default();
        let index_extents = rec
            .attributes
            .iter()
            .filter(|attribute| {
                attribute.header().attr_type == AttributeType::IndexAllocation
                    && attribute.header().name.as_deref() == Some("$I30")
            })
            .cloned()
            .collect::<Vec<_>>();

        if !index_extents.is_empty() {
            debug!("Directory {:} uses non-resident index – walking it", dir_id);

            let bytes_per_sec = self.pbs.bytes_per_sector as usize;
            let bytes_per_clu = self.pbs.cluster_size() as usize;
            let idx_rec_size = rec.index_record_size(bytes_per_clu as u32) as usize;
            if bytes_per_sec < 2 || idx_rec_size < bytes_per_sec {
                return Err("invalid NTFS index-record geometry".into());
            }
            let stream_size =
                nonresident_stream_size(&index_extents, self.pbs.cluster_size() as u64)?;
            if stream_size % idx_rec_size as u64 != 0 {
                return Err("INDEX_ALLOCATION size is not a whole number of index records".into());
            }
            let volume_size = self
                .pbs
                .total_sectors
                .checked_mul(u64::from(self.pbs.bytes_per_sector))
                .ok_or("NTFS volume size overflow")?;
            if stream_size > volume_size {
                return Err("INDEX_ALLOCATION is larger than its NTFS volume".into());
            }
            let record_count = stream_size / idx_rec_size as u64;

            let bitmap_extents = rec
                .attributes
                .iter()
                .filter(|attribute| {
                    attribute.header().attr_type == AttributeType::Bitmap
                        && attribute.header().name.as_deref() == Some("$I30")
                })
                .cloned()
                .collect::<Vec<_>>();
            if bitmap_extents.is_empty() {
                return Err("INDEX_ALLOCATION has no matching $I30 bitmap".into());
            }
            let required_bitmap_bytes = usize::try_from(record_count.div_ceil(8))
                .map_err(|_| "index bitmap size overflow")?;
            if required_bitmap_bytes > 64 * 1024 * 1024 {
                return Err("index bitmap exceeds configured size limit".into());
            }
            let bitmap = self.read_attribute_stream_bounded(&bitmap_extents, 64 * 1024 * 1024)?;
            if bitmap.len() < required_bitmap_bytes {
                return Err("$I30 bitmap is shorter than INDEX_ALLOCATION".into());
            }

            let mut active_records = 0usize;
            for (byte_index, byte) in bitmap.iter().take(required_bitmap_bytes).enumerate() {
                let mut set_bits = *byte;
                while set_bits != 0 {
                    let bit = set_bits.trailing_zeros() as usize;
                    set_bits &= !(1u8 << bit);
                    let index = (byte_index as u64)
                        .checked_mul(8)
                        .and_then(|base| base.checked_add(bit as u64))
                        .ok_or("active index-record number overflow")?;
                    if index >= record_count {
                        continue;
                    }
                    active_records += 1;
                    if active_records > MAX_ACTIVE_INDEX_RECORDS {
                        return Err("active index-record limit exceeded".into());
                    }
                    let logical_offset = index
                        .checked_mul(idx_rec_size as u64)
                        .ok_or("index-record offset overflow")?;
                    let buf = self.read_nonresident_stream_slice(
                        &index_extents,
                        logical_offset,
                        idx_rec_size,
                    )?;
                    if buf.len() != idx_rec_size {
                        warn!(
                            "Skipping truncated INDX block {} for directory {}",
                            index, dir_id
                        );
                        continue;
                    }
                    match mft::parse_index_record(&buf, bytes_per_sec) {
                        Ok(mut block_entries) => entries.append(&mut block_entries),
                        Err(error) => warn!(
                            "Skipping invalid INDX block {} for directory {}: {}",
                            index, dir_id, error
                        ),
                    }
                }
            }
        }

        // Reject keys whose embedded parent reference does not point at the
        // directory being walked. This prevents a stale B-tree entry from
        // being attached to a reused directory record.
        entries.retain(|entry| {
            entry.parent_ref == rec.id && entry.parent_seq == rec.header.sequence_number
        });

        canonicalize_directory_entries(&mut entries);

        Ok(entries)
    }

    /// Read the $DATA stream of rec and return its raw bytes.
    pub fn read_file(&mut self, record: &MFTRecord) -> Result<Vec<u8>, Box<dyn Error>> {
        let attributes = record
            .attributes
            .iter()
            .filter(|attribute| {
                attribute.header().attr_type == AttributeType::Data
                    && attribute.header().name.is_none()
            })
            .cloned()
            .collect::<Vec<_>>();
        if attributes.is_empty() {
            return Err("unnamed $DATA attribute not found".into());
        }
        self.read_attribute_stream_bounded(&attributes, MAX_EAGER_STREAM_BYTES)
    }

    /// Read `length` bytes from the unnamed $DATA stream of `record`,
    /// starting at `offset`.  Holes (sparse clusters) are returned as 0x00.
    pub fn read_file_slice(
        &mut self,
        record: &MFTRecord,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let attributes = record
            .attributes
            .iter()
            .filter(|attribute| {
                attribute.header().attr_type == AttributeType::Data
                    && attribute.header().name.is_none()
            })
            .cloned()
            .collect::<Vec<_>>();
        if attributes.is_empty() {
            return Err("unnamed $DATA attribute not found".into());
        }
        self.read_attribute_stream_slice(&attributes, offset, length)
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
        let attributes = record
            .attributes
            .iter()
            .filter(|attribute| {
                attribute.header().attr_type == AttributeType::Data
                    && attribute
                        .header()
                        .name
                        .as_deref()
                        .is_some_and(|name| name.eq_ignore_ascii_case(stream_name))
            })
            .cloned()
            .collect::<Vec<_>>();
        if attributes.is_empty() {
            return Err(format!("named $DATA stream '{}' not found", stream_name).into());
        }
        self.read_attribute_stream_bounded(&attributes, MAX_EAGER_STREAM_BYTES)
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

            if let Some(name) = rec.primary_name()
                && !name.is_empty()
                && name != "."
                && name != ".."
            {
                parts.push(name);
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
            if let Some(s) = journal_seqs
                && s.len() > 1
            {
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
        if let Some(cur) = file_cur_seq
            && cur != r.file_ref_seq()
        {
            file_reasons.push(ReuseReason::CurrentSeqDiffersFromUsn);
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
        if let Some(cur) = parent_cur_seq
            && cur != r.parent_ref_seq()
        {
            parent_reasons.push(ReuseReason::CurrentSeqDiffersFromUsn);
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
            if let Some(seqs) = reuse_index.get(&idx)
                && seqs.len() > 1
            {
                maybe_push(idx, name, Some(seqs), vec![], self.current_mft_seq(idx));
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

fn validate_ntfs_geometry(pbs: &PartitionBootSector) -> Result<(), String> {
    let sector_size = u32::from(pbs.bytes_per_sector);
    if !(256..=4096).contains(&sector_size) || !sector_size.is_power_of_two() {
        return Err("invalid NTFS bytes-per-sector geometry".into());
    }
    let sectors_per_cluster = u32::from(pbs.sectors_per_cluster);
    if sectors_per_cluster == 0 || !sectors_per_cluster.is_power_of_two() {
        return Err("invalid NTFS sectors-per-cluster geometry".into());
    }
    let cluster_size = sector_size
        .checked_mul(sectors_per_cluster)
        .ok_or("NTFS cluster-size overflow")?;
    if cluster_size > 2 * 1024 * 1024 {
        return Err("NTFS cluster size exceeds supported bounds".into());
    }
    if pbs.total_sectors == 0 {
        return Err("NTFS volume declares zero sectors".into());
    }
    let volume_size = pbs
        .total_sectors
        .checked_mul(u64::from(pbs.bytes_per_sector))
        .ok_or("NTFS volume byte size overflow")?;
    let volume_clusters = pbs.total_sectors / u64::from(sectors_per_cluster);
    if pbs.mft_cluster >= volume_clusters || pbs.mft_mirror_cluster >= volume_clusters {
        return Err("NTFS MFT location lies outside the volume".into());
    }
    let mft_address = pbs
        .mft_cluster
        .checked_mul(u64::from(cluster_size))
        .ok_or("NTFS MFT byte address overflow")?;
    let mirror_address = pbs
        .mft_mirror_cluster
        .checked_mul(u64::from(cluster_size))
        .ok_or("NTFS MFT mirror byte address overflow")?;
    if mft_address >= volume_size || mirror_address >= volume_size {
        return Err("NTFS MFT byte address lies outside the volume".into());
    }

    let encoded_size = |clusters: i8, label: &str| -> Result<u32, String> {
        let size = if clusters > 0 {
            u32::from(clusters as u8)
                .checked_mul(cluster_size)
                .ok_or_else(|| format!("NTFS {label} size overflow"))?
        } else if clusters < 0 {
            1u32.checked_shl(clusters.unsigned_abs() as u32)
                .ok_or_else(|| format!("invalid NTFS {label} size exponent"))?
        } else {
            return Err(format!("NTFS {label} size encoding is zero"));
        };
        if !(256..=64 * 1024).contains(&size) || !size.is_power_of_two() {
            return Err(format!("NTFS {label} size is outside supported bounds"));
        }
        Ok(size)
    };
    encoded_size(pbs.clusters_per_file_record, "FILE record")?;
    encoded_size(pbs.clusters_per_index_buffer, "INDX record")?;
    if pbs.end_of_sector_marker != 0xAA55 {
        return Err("invalid NTFS boot-sector marker".into());
    }
    Ok(())
}

fn try_zeroed_buffer(length: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    if length > isize::MAX as usize {
        return Err("requested buffer exceeds addressable Vec capacity".into());
    }
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(length)
        .map_err(|error| format!("unable to allocate {length} bytes: {error}"))?;
    buffer.resize(length, 0);
    Ok(buffer)
}

fn split_file_reference(reference: u64) -> (u64, u16) {
    (reference & 0x0000_FFFF_FFFF_FFFF, (reference >> 48) as u16)
}

fn attribute_matches_list_entry(attribute: &Attribute, entry: &AttributeListEntry) -> bool {
    let header = attribute.header();
    header.attr_type == entry.attr_type
        && header.id == entry.attribute_id
        && header.name == entry.name
        && attribute.lowest_vcn() == entry.lowest_vcn
}

fn canonicalize_directory_entries(entries: &mut Vec<DirectoryEntry>) {
    // A Win32 long name and its DOS 8.3 alias share the same complete file
    // reference. Different generations of a reused MFT slot must not affect
    // one another.
    let with_long_name = entries
        .iter()
        .filter(|entry| !entry.namespace.is_dos_only())
        .map(|entry| {
            (
                entry.file_id,
                entry.file_sequence,
                entry.parent_ref,
                entry.parent_seq,
            )
        })
        .collect::<HashSet<_>>();
    entries.retain(|entry| {
        !entry.namespace.is_dos_only()
            || !with_long_name.contains(&(
                entry.file_id,
                entry.file_sequence,
                entry.parent_ref,
                entry.parent_seq,
            ))
    });

    // Multiple non-DOS names for one FRN are valid hard links. Remove only an
    // identical directory key observed through more than one B-tree level.
    let mut seen = HashSet::<(u64, u16, u64, u16, String)>::new();
    entries.retain(|entry| {
        seen.insert((
            entry.file_id,
            entry.file_sequence,
            entry.parent_ref,
            entry.parent_seq,
            entry.name.clone(),
        ))
    });
}

type NonResidentExtent<'a> = (
    &'a mft::AttributeHeaderCommon,
    &'a mft::NonResidentHeader,
    &'a Vec<u8>,
);

fn nonresident_stream_size(
    attributes: &[Attribute],
    _cluster_size: u64,
) -> Result<u64, Box<dyn Error>> {
    let mut size = None;
    for attribute in attributes {
        match attribute {
            Attribute::NonResident { non_resident, .. } => {
                if non_resident.lowest_vcn == 0 && size.replace(non_resident.real_size).is_some() {
                    return Err("non-resident stream has multiple zero-VCN extents".into());
                }
            }
            Attribute::Resident { .. } => {
                return Err("resident attribute found in a non-resident stream".into());
            }
        }
    }
    size.ok_or_else(|| "non-resident stream has no zero-VCN extent".into())
}

fn validate_nonresident_extents(extents: &[NonResidentExtent<'_>]) -> Result<(), Box<dyn Error>> {
    let Some((first_header, _, _)) = extents.first() else {
        return Err("non-resident stream has no extents".into());
    };
    let mut previous_high = None;
    for (header, non_resident, run_list) in extents {
        if header.attr_type != first_header.attr_type || header.name != first_header.name {
            return Err("non-resident extent set mixes different streams".into());
        }
        if header.flags & 0x0001 != 0 || header.flags & 0x4000 != 0 {
            return Err("compressed or EFS-encrypted NTFS streams are not supported".into());
        }
        if previous_high.is_some_and(|high| non_resident.lowest_vcn <= high) {
            return Err("overlapping or duplicate non-resident extents".into());
        }

        let runs = decode_run_list(run_list)?;
        let decoded_clusters = runs.iter().try_fold(0u64, |total, (_, length)| {
            total
                .checked_add(*length)
                .ok_or("run-list cluster count overflow")
        })?;
        if decoded_clusters == 0 {
            if non_resident.allocated_size == 0
                && non_resident.real_size == 0
                && non_resident.initialized_size == 0
            {
                previous_high = Some(non_resident.lowest_vcn.saturating_sub(1));
                continue;
            }
            return Err("non-empty stream has an empty mapping-pairs list".into());
        }
        let expected_clusters = non_resident
            .highest_vcn
            .checked_sub(non_resident.lowest_vcn)
            .and_then(|difference| difference.checked_add(1))
            .ok_or("invalid non-resident VCN range")?;
        if decoded_clusters != expected_clusters {
            return Err(format!(
                "mapping pairs cover {decoded_clusters} clusters, expected {expected_clusters} for VCN {}..{}",
                non_resident.lowest_vcn, non_resident.highest_vcn
            )
            .into());
        }
        previous_high = Some(non_resident.highest_vcn);
    }
    Ok(())
}

fn ensure_nonresident_coverage(
    extents: &[NonResidentExtent<'_>],
    start: u64,
    end: u64,
    cluster_size: u64,
) -> Result<(), Box<dyn Error>> {
    if start >= end {
        return Ok(());
    }
    let first_vcn = start / cluster_size;
    let end_vcn = end.div_ceil(cluster_size);
    let mut covered_until = first_vcn;
    for (_, extent, _) in extents {
        let extent_end = extent
            .highest_vcn
            .checked_add(1)
            .ok_or("extent VCN end overflow")?;
        if extent_end <= covered_until {
            continue;
        }
        if extent.lowest_vcn > covered_until {
            return Err(format!(
                "non-resident stream is missing VCN {} before extent {}",
                covered_until, extent.lowest_vcn
            )
            .into());
        }
        covered_until = extent_end;
        if covered_until >= end_vcn {
            return Ok(());
        }
    }
    Err(
        format!("non-resident stream ends at VCN {covered_until}, before required VCN {end_vcn}")
            .into(),
    )
}

// Decode mapping pairs into (LCN, length_in_clusters). Sparse runs use -1.
fn decode_run_list(raw: &[u8]) -> Result<Vec<(i64, u64)>, String> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    let mut cur_lcn: i64 = 0;
    let mut terminated = false;
    while pos < raw.len() {
        let hdr = raw[pos];
        pos += 1;
        if hdr == 0 {
            terminated = true;
            break;
        }
        let len_sz = (hdr & 0x0F) as usize;
        let ofs_sz = (hdr >> 4) as usize;
        if len_sz == 0 || len_sz > 8 || ofs_sz > 8 {
            return Err("invalid mapping-pairs field width".into());
        }
        let fields_end = pos
            .checked_add(len_sz)
            .and_then(|end| end.checked_add(ofs_sz))
            .ok_or("mapping-pairs offset overflow")?;
        if fields_end > raw.len() {
            return Err("truncated mapping-pairs run".into());
        }

        let mut run_len = 0u64;
        for i in 0..len_sz {
            run_len |= (raw[pos + i] as u64) << (8 * i);
        }
        pos += len_sz;
        if run_len == 0 {
            return Err("zero-length mapping-pairs run".into());
        }

        if ofs_sz == 0 {
            out.push((-1, run_len));
        } else {
            let mut raw_offset = 0u64;
            for i in 0..ofs_sz {
                raw_offset |= (raw[pos + i] as u64) << (8 * i);
            }
            let shift = 64 - ofs_sz * 8;
            let relative = ((raw_offset << shift) as i64) >> shift;
            cur_lcn = cur_lcn
                .checked_add(relative)
                .ok_or("mapping-pairs LCN overflow")?;
            if cur_lcn < 0 {
                return Err("mapping-pairs LCN became negative".into());
            }
            out.push((cur_lcn, run_len));
        }
        pos += ofs_sz;
    }
    if !terminated {
        return Err("mapping-pairs list has no terminator".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mft::{AttributeHeaderCommon, FileNameNamespace, NonResidentHeader, ResidentHeader};
    use sha2::{Digest, Sha256};
    use std::fs::File;
    use std::io::Cursor;

    fn test_pbs() -> PartitionBootSector {
        PartitionBootSector {
            jump_instruction: vec![0; 3],
            oem_id: PartitionBootSector::NTFS_OEM_ID,
            bytes_per_sector: 512,
            sectors_per_cluster: 1,
            reserved_sectors: 0,
            unused1: [0; 3],
            unused2: 0,
            media_descriptor: 0xF8,
            unused3: 0,
            sectors_per_track: 0,
            number_of_heads: 0,
            hidden_sectors: 0,
            unused4: 0,
            unused5: 0,
            total_sectors: 64,
            mft_cluster: 0,
            mft_mirror_cluster: 0,
            clusters_per_file_record: -10,
            unused6: [0; 3],
            clusters_per_index_buffer: 1,
            unused7: [0; 3],
            volume_serial_number: 0,
            checksum: 0,
            bootstrap_code: vec![0; 426],
            end_of_sector_marker: 0xAA55,
        }
    }

    fn nonresident_data(
        id: u16,
        lowest_vcn: u64,
        highest_vcn: u64,
        run_list: Vec<u8>,
    ) -> Attribute {
        Attribute::NonResident {
            header: AttributeHeaderCommon {
                attr_type: AttributeType::Data,
                length: 0x40 + run_list.len() as u32,
                non_resident: true,
                name_length: 0,
                name_offset: 0,
                flags: 0,
                id,
                name: None,
            },
            non_resident: NonResidentHeader {
                lowest_vcn,
                highest_vcn,
                mapping_pairs_offset: 0x40,
                compression_unit: 0,
                allocated_size: 1024,
                real_size: 1024,
                initialized_size: 1024,
            },
            run_list,
        }
    }

    fn dir_entry(
        file_id: u64,
        file_sequence: u16,
        parent_ref: u64,
        parent_seq: u16,
        name: &str,
        namespace: FileNameNamespace,
    ) -> DirectoryEntry {
        DirectoryEntry {
            file_id,
            file_sequence,
            name: name.into(),
            flags: 0,
            parent_ref,
            parent_seq,
            namespace,
        }
    }

    #[test]
    fn run_list_rejects_truncation_and_preserves_sparse_runs() {
        assert_eq!(
            decode_run_list(&[0x11, 3, 5, 0x01, 2, 0]).expect("valid mapping pairs"),
            vec![(5, 3), (-1, 2)]
        );
        assert_eq!(
            decode_run_list(&[0x11, 1, 10, 0x11, 1, 0xFE, 0]).expect("signed relative LCN"),
            vec![(10, 1), (8, 1)]
        );
        assert!(decode_run_list(&[0x21, 1, 5]).is_err());
        assert!(decode_run_list(&[0x11, 1, 5]).is_err());
    }

    #[test]
    fn ntfs_geometry_rejects_unbounded_or_inconsistent_values() {
        let valid = test_pbs();
        validate_ntfs_geometry(&valid).expect("valid test geometry");

        let mut invalid = valid.clone();
        invalid.bytes_per_sector = 513;
        assert!(validate_ntfs_geometry(&invalid).is_err());
        invalid = valid.clone();
        invalid.sectors_per_cluster = 0;
        assert!(validate_ntfs_geometry(&invalid).is_err());
        invalid = valid;
        invalid.mft_cluster = 65;
        assert!(validate_ntfs_geometry(&invalid).is_err());

        let mut overflow = test_pbs();
        overflow.total_sectors = u64::MAX;
        assert!(validate_ntfs_geometry(&overflow).is_err());
        overflow.mft_cluster = u64::MAX;
        assert!(overflow.checked_mft_address().is_none());
    }

    #[test]
    fn eager_stream_read_rejects_evidence_controlled_oversized_allocation() {
        let declared_size = MAX_EAGER_STREAM_BYTES as u64 + 1;
        let mut attribute = nonresident_data(1, 0, 0, vec![0]);
        if let Attribute::NonResident { non_resident, .. } = &mut attribute {
            non_resident.allocated_size = declared_size;
            non_resident.real_size = declared_size;
            non_resident.initialized_size = declared_size;
        }
        let record = MFTRecord {
            id: 9,
            header: mft::FileRecordHeader {
                signature: *b"FILE",
                usa_offset: 0,
                usa_count: 0,
                lsn: 0,
                sequence_number: 1,
                hard_link_count: 1,
                attrs_offset: 0,
                flags: 1,
                bytes_in_use: 0,
                bytes_allocated: 0,
                base_file_record: 0,
                next_attr_id: 0,
            },
            attributes: vec![attribute],
            extension_record_ids: Vec::new(),
        };
        let mut pbs = test_pbs();
        pbs.total_sectors = declared_size.div_ceil(u64::from(pbs.bytes_per_sector));
        let mut ntfs = NTFS {
            pbs,
            body: Cursor::new(Vec::<u8>::new()),
            mft_runs: None,
        };

        let error = ntfs.read_file(&record).expect_err("oversized eager read");
        assert!(error.to_string().contains("size limit"));
        assert!(try_zeroed_buffer(usize::MAX).is_err());
    }

    #[test]
    fn nonempty_stream_cannot_claim_an_empty_mapping_list() {
        let mut attribute = nonresident_data(1, 0, 0, vec![0]);
        if let Attribute::NonResident { non_resident, .. } = &mut attribute {
            non_resident.allocated_size = 0;
            non_resident.real_size = 512;
            non_resident.initialized_size = 512;
        }
        let mut ntfs = NTFS {
            pbs: test_pbs(),
            body: Cursor::new(vec![0; 512]),
            mft_runs: None,
        };
        assert!(
            ntfs.read_nonresident_stream_slice(&[attribute], 0, 512)
                .is_err()
        );
    }

    #[test]
    fn multi_extent_reader_sorts_by_vcn_and_resets_relative_lcn() {
        let mut body = vec![0u8; 4 * 512];
        body[512..1024].fill(b'A');
        body[1536..2048].fill(b'B');
        let mut ntfs = NTFS {
            pbs: test_pbs(),
            body: Cursor::new(body),
            mft_runs: None,
        };
        // Deliberately reverse the logical extent order. The first LCN in each
        // mapping-pairs array is relative to zero, not to the prior extent.
        let attributes = vec![
            nonresident_data(2, 1, 1, vec![0x11, 1, 3, 0]),
            nonresident_data(1, 0, 0, vec![0x11, 1, 1, 0]),
        ];
        let bytes = ntfs
            .read_nonresident_stream_slice(&attributes, 0, 1024)
            .expect("split stream");
        assert_eq!(&bytes[..512], vec![b'A'; 512]);
        assert_eq!(&bytes[512..], vec![b'B'; 512]);
    }

    #[test]
    fn dos_alias_suppression_is_scoped_to_complete_file_and_parent_references() {
        let mut entries = vec![
            dir_entry(7, 2, 5, 1, "LONG NAME", FileNameNamespace::Win32),
            dir_entry(7, 2, 5, 1, "LONGNA~1", FileNameNamespace::Dos),
            // Same MFT slot, different generation: this alias must survive.
            dir_entry(7, 3, 5, 1, "OLDGEN~1", FileNameNamespace::Dos),
            // Same FRN generation, different hard-link parent: must survive.
            dir_entry(7, 2, 9, 4, "OTHER~1", FileNameNamespace::Dos),
            // Two non-DOS hard-link names are both legitimate.
            dir_entry(7, 2, 5, 1, "Second link", FileNameNamespace::Win32),
        ];
        canonicalize_directory_entries(&mut entries);
        let names = entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<HashSet<_>>();
        assert!(!names.contains("LONGNA~1"));
        assert!(names.contains("LONG NAME"));
        assert!(names.contains("OLDGEN~1"));
        assert!(names.contains("OTHER~1"));
        assert!(names.contains("Second link"));
    }

    #[test]
    fn attribute_list_tuple_matching_includes_name_vcn_and_instance() {
        let attribute = nonresident_data(4, 3, 3, vec![0x11, 1, 2, 0]);
        let exact = AttributeListEntry {
            attr_type: AttributeType::Data,
            name: None,
            lowest_vcn: 3,
            segment_reference: 20,
            segment_sequence: 2,
            attribute_id: 4,
        };
        assert!(attribute_matches_list_entry(&attribute, &exact));
        let mut wrong = exact.clone();
        wrong.lowest_vcn = 4;
        assert!(!attribute_matches_list_entry(&attribute, &wrong));
        wrong = exact.clone();
        wrong.attribute_id = 5;
        assert!(!attribute_matches_list_entry(&attribute, &wrong));
        wrong = exact;
        wrong.name = Some("stream".into());
        assert!(!attribute_matches_list_entry(&attribute, &wrong));
    }

    #[test]
    fn logical_unnamed_size_comes_from_zero_vcn_extent() {
        let mut first = nonresident_data(1, 0, 0, vec![0x11, 1, 1, 0]);
        let mut later = nonresident_data(2, 1, 1, vec![0x11, 1, 3, 0]);
        if let Attribute::NonResident { non_resident, .. } = &mut first {
            non_resident.real_size = 777;
        }
        if let Attribute::NonResident { non_resident, .. } = &mut later {
            non_resident.real_size = 0;
        }
        let record = MFTRecord {
            id: 1,
            header: mft::FileRecordHeader {
                signature: *b"FILE",
                usa_offset: 0,
                usa_count: 0,
                lsn: 0,
                sequence_number: 1,
                hard_link_count: 1,
                attrs_offset: 0,
                flags: 1,
                bytes_in_use: 0,
                bytes_allocated: 0,
                base_file_record: 0,
                next_attr_id: 0,
            },
            attributes: vec![first, later],
            extension_record_ids: vec![2],
        };
        assert_eq!(record.unnamed_data_size(), Some(777));
    }

    /// Opt-in regression against the decrypted image used during development:
    /// `EXHUME_NTFS_TEST_IMAGE=/path/to/Suspect.ntfs.img cargo test -p
    /// exhume_ntfs real_suspect_image_attribute_list_regressions -- --ignored`
    #[test]
    #[ignore = "requires EXHUME_NTFS_TEST_IMAGE pointing to the decrypted fixture"]
    fn real_suspect_image_attribute_list_regressions() {
        let path = std::env::var("EXHUME_NTFS_TEST_IMAGE")
            .expect("set EXHUME_NTFS_TEST_IMAGE to Suspect.ntfs.img");
        let file = File::open(path).expect("open real NTFS fixture");
        let mut ntfs = NTFS::new(file).expect("parse NTFS boot sector");

        let documents = ntfs.get_file_id(115_693).expect("hydrate Documents");
        assert_eq!(documents.primary_name().as_deref(), Some("Documents"));
        assert_eq!(documents.extension_record_ids, vec![320_246]);
        let children = ntfs.list_dir(115_693).expect("list Documents");
        assert_eq!(children.len(), 22);
        assert!(children.iter().any(|entry| {
            entry.file_id == 284_399
                && entry.name == "Database.kdbx"
                && !entry.namespace.is_dos_only()
        }));

        for (record_id, size, expected_hash, extension_id) in [
            (
                41_084,
                817_624,
                "50a5c14fd4da7116a2072d12cb94c258354d0237979d5d5afa979be740d118f5",
                42_214,
            ),
            (
                177_967,
                540_672,
                "9fb89989f1a7c4e52244d29ee82205cdcafbf9db96fbafa9ec55fd1f4ad74514",
                0,
            ),
            (
                284_399,
                2_126,
                "d7b049d92af82c6dcb96e725675118a23f9d682ec8f8c0ea62c672d464db06f3",
                0,
            ),
        ] {
            let record = ntfs.get_file_id(record_id).expect("hydrate file record");
            if extension_id != 0 {
                assert!(record.extension_record_ids.contains(&extension_id));
            }
            let bytes = ntfs.read_file(&record).expect("read logical DATA stream");
            assert_eq!(bytes.len(), size);
            assert_eq!(hex::encode(Sha256::digest(&bytes)), expected_hash);
        }
    }

    #[test]
    fn resident_stream_slice_stays_bounded() {
        let value = b"abcdef".to_vec();
        let attribute = Attribute::Resident {
            header: AttributeHeaderCommon {
                attr_type: AttributeType::Data,
                length: 30,
                non_resident: false,
                name_length: 0,
                name_offset: 0,
                flags: 0,
                id: 1,
                name: None,
            },
            resident: ResidentHeader {
                value_length: value.len() as u32,
                value_offset: 24,
                resident_flags: 0,
            },
            value,
        };
        let mut ntfs = NTFS {
            pbs: test_pbs(),
            body: Cursor::new(Vec::<u8>::new()),
            mft_runs: None,
        };
        assert_eq!(
            ntfs.read_attribute_stream_slice(&[attribute], 2, usize::MAX)
                .expect("resident slice"),
            b"cdef"
        );
    }
}
