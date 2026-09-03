// Sources:
// - https://dubeyko.com/development/FileSystems/NTFS/ntfsdoc.pdf
// - https://en.wikipedia.org/wiki/NTFS
// TODO: include finer‑grained logs and error handling.

use byteorder::{LittleEndian, ReadBytesExt};
use chrono::{TimeZone, Utc};
use core::convert::TryFrom;
use log::{debug, error, warn};
use prettytable::{Table, row};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::{Cursor, Read, Seek, SeekFrom};

/// Header found at the very beginning of every **FILE** record (offset 0).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FileRecordHeader {
    pub signature: [u8; 4],
    pub usa_offset: u16,
    pub usa_count: u16,
    pub lsn: u64,
    pub sequence_number: u16,
    pub hard_link_count: u16,
    pub attrs_offset: u16,
    pub flags: u16,
    pub bytes_in_use: u32,
    pub bytes_allocated: u32,
    pub base_file_record: u64,
    pub next_attr_id: u16,
}

/// Common header part for resident & non‑resident attributes.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AttributeHeaderCommon {
    pub attr_type: AttributeType,
    pub length: u32,
    pub non_resident: bool,
    pub name_length: u8,
    pub name_offset: u16,
    pub flags: u16,
    pub id: u16,
    pub name: Option<String>,
}

/// Additional 8‑byte header present only when the attribute is resident
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResidentHeader {
    pub value_length: u32,
    pub value_offset: u16,
    pub resident_flags: u8, // 0 = indexed ($I30), 1 = normal
}

/// Additional 40‑byte header present only when the attribute is non‑resident
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NonResidentHeader {
    pub lowest_vcn: u64,
    pub highest_vcn: u64,
    pub mapping_pairs_offset: u16,
    pub compression_unit: u16,
    pub allocated_size: u64,
    pub real_size: u64,
    pub initialized_size: u64,
}

/// High‑level representation of a single attribute (header + raw value bytes).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum Attribute {
    Resident {
        header: AttributeHeaderCommon,
        resident: ResidentHeader,
        value: Vec<u8>,
    },
    NonResident {
        header: AttributeHeaderCommon,
        non_resident: NonResidentHeader,
        run_list: Vec<u8>,
    },
}

/// Represents an Alternate Data Stream (named $DATA attribute).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DataStream {
    pub name: String,
    pub size: u64,
    pub resident: bool,
    pub attr_id: u16,
}

/// A fully parsed 1 KiB MFT record.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MFTRecord {
    pub id: u64,
    pub header: FileRecordHeader,
    pub attributes: Vec<Attribute>,
    /// Physical extension records merged into this logical record through
    /// `$ATTRIBUTE_LIST`. Empty for records parsed directly from disk.
    #[serde(default)]
    pub extension_record_ids: Vec<u64>,
}

/// Apply an NTFS update-sequence array using the supplied sector size.
///
/// Every protected sector must carry the update-sequence number before any
/// replacement word is applied. A mismatch invalidates the complete record;
/// callers must never continue parsing a partially fixed record.
pub(crate) fn apply_fixups_with_sector_size(
    buf: &mut [u8],
    usa_offset: usize,
    usa_count: usize,
    sector_size: usize,
) -> Result<(), String> {
    let usa_bytes = usa_count.checked_mul(2).ok_or("USA byte count overflow")?;
    let usa_end = usa_offset
        .checked_add(usa_bytes)
        .ok_or("USA offset overflow")?;
    if usa_count == 0 || usa_end > buf.len() {
        warn!("Incomplete multi‑sector transfer – corrupted MFT record.");
        return Err("USA table outside record".into());
    }
    if usa_count == 1 {
        return Err("USA does not protect any sector".into());
    }
    if !(256..=4096).contains(&sector_size) || !sector_size.is_power_of_two() {
        return Err("invalid USA sector size".into());
    }

    let protected_len = (usa_count - 1)
        .checked_mul(sector_size)
        .ok_or("USA protected length overflow")?;
    if protected_len != buf.len() {
        return Err("USA protected length does not match record length".into());
    }

    debug!("Detected a multi-sector record, patching.");

    // Take a copy of the Update‑Sequence Number, not a slice
    let usn = [buf[usa_offset], buf[usa_offset + 1]];

    for i in 1..usa_count {
        let sector_end = i
            .checked_mul(sector_size)
            .and_then(|end| end.checked_sub(2))
            .ok_or("USA sector offset overflow")?;
        if sector_end + 2 > buf.len() {
            return Err(format!("sector {} ends after record", i));
        }

        // Validate the two bytes at the end of the sector
        if buf[sector_end] != usn[0] || buf[sector_end + 1] != usn[1] {
            return Err(format!("bad USN at sector {}", i));
        }

        // Fetch the real words from the USA and patch them in
        let fix_pos = usa_offset + 2 * i;
        let fix0 = buf[fix_pos];
        let fix1 = buf[fix_pos + 1];

        buf[sector_end] = fix0;
        buf[sector_end + 1] = fix1;
    }
    Ok(())
}

// FILE records do not carry the sector size explicitly. The number of
// protected sectors is encoded by usa_count, so derive the only sector size
// consistent with the record length instead of assuming 512-byte sectors.
fn apply_file_record_fixups(
    buf: &mut [u8],
    usa_offset: usize,
    usa_count: usize,
) -> Result<(), String> {
    if usa_count <= 1 {
        return Err("FILE record has an invalid USA count".into());
    }
    let sectors = usa_count - 1;
    if !buf.len().is_multiple_of(sectors) {
        return Err("FILE record length is inconsistent with USA count".into());
    }
    let sector_size = buf.len() / sectors;
    apply_fixups_with_sector_size(buf, usa_offset, usa_count, sector_size)
}

impl MFTRecord {
    /// Parse a raw FILE record when the enclosing NTFS sector geometry is not
    /// available. The sector size is derived from the USA count.
    pub fn from_bytes(raw: &[u8], identifier: Option<u64>) -> Result<Self, String> {
        Self::from_bytes_inner(raw, identifier, None)
    }

    /// Parse a raw FILE record using the authoritative sector size from the
    /// partition boot sector.
    pub fn from_bytes_with_sector_size(
        raw: &[u8],
        identifier: Option<u64>,
        sector_size: usize,
    ) -> Result<Self, String> {
        Self::from_bytes_inner(raw, identifier, Some(sector_size))
    }

    fn from_bytes_inner(
        raw: &[u8],
        identifier: Option<u64>,
        sector_size: Option<usize>,
    ) -> Result<Self, String> {
        if raw.len() < 0x30 {
            return Err("MFT record is shorter than its fixed header".into());
        }
        // we need a mutable copy so we can patch the USNs in‑place
        let mut buf = raw.to_vec();

        let mut cursor = Cursor::new(&buf);
        let header = parse_header(&mut cursor)?;
        if header.usa_offset < 0x2A || header.usa_offset % 2 != 0 {
            return Err("invalid FILE record USA offset".into());
        }

        if let Some(sector_size) = sector_size {
            apply_fixups_with_sector_size(
                &mut buf,
                header.usa_offset as usize,
                header.usa_count as usize,
                sector_size,
            )?;
        } else {
            apply_file_record_fixups(
                &mut buf,
                header.usa_offset as usize,
                header.usa_count as usize,
            )?;
        }

        let bytes_in_use = usize::try_from(header.bytes_in_use)
            .map_err(|_| "MFT bytes_in_use does not fit in memory")?;
        let attrs_offset = usize::from(header.attrs_offset);
        if bytes_in_use > buf.len()
            || attrs_offset < 0x30
            || attrs_offset % 8 != 0
            || attrs_offset > bytes_in_use
        {
            return Err("MFT attribute bounds are outside the record".into());
        }
        if header.bytes_allocated < header.bytes_in_use
            || usize::try_from(header.bytes_allocated).unwrap_or(usize::MAX) > buf.len()
        {
            return Err("invalid MFT bytes_allocated/bytes_in_use values".into());
        }

        let mut attributes = Vec::new();
        let mut attr_offset = attrs_offset;
        loop {
            /* stop if fewer than 4 bytes remain */
            if attr_offset
                .checked_add(4)
                .is_none_or(|end| end > bytes_in_use)
            {
                break;
            }

            let attr_type_num = u32::from_le_bytes(
                buf[attr_offset..attr_offset + 4]
                    .try_into()
                    .map_err(|_| "truncated attribute type")?,
            );
            if attr_type_num == 0xFFFFFFFF {
                break;
            }

            let attr_type = AttributeType::try_from(attr_type_num)?;
            let (attr, next_offset) = parse_attribute(&buf, attr_offset, bytes_in_use, attr_type)?;
            attributes.push(attr);
            attr_offset = next_offset;
        }

        Ok(MFTRecord {
            id: identifier.unwrap_or(0),
            header,
            attributes,
            extension_record_ids: Vec::new(),
        })
    }

    /// List every $FILE_NAME attribute found (there may be 2 – long & DOS).
    pub fn file_names(&self) -> Vec<FileNameAttr> {
        self.attributes
            .iter()
            .filter_map(|a| {
                if let Attribute::Resident { value, header, .. } = a {
                    (header.attr_type == AttributeType::FileName)
                        .then(|| FileNameAttr::parse(value))
                } else {
                    None
                }
            })
            .flatten()
            .collect()
    }

    /// Return the preferred `$FILE_NAME`, independent of on-disk attribute
    /// ordering. Win32-capable names win over POSIX names, and DOS-only aliases
    /// are used only as a last resort.
    pub fn preferred_file_name(&self) -> Option<FileNameAttr> {
        let mut best = None::<FileNameAttr>;
        for candidate in self.file_names() {
            let replace = best.as_ref().is_none_or(|current| {
                candidate.namespace.preference() > current.namespace.preference()
            });
            if replace {
                best = Some(candidate);
            }
        }
        best
    }

    /// Return the preferred human-readable name, if present.
    pub fn primary_name(&self) -> Option<String> {
        self.preferred_file_name().map(|f| f.name)
    }

    /// Parent directory MFT reference from the preferred `$FILE_NAME`.
    pub fn parent_file_id(&self) -> Option<u64> {
        self.preferred_file_name().map(|f| f.parent_ref)
    }

    /// Logical size of the unnamed `$DATA` stream. For a split non-resident
    /// stream, size metadata belongs to the extent whose lowest VCN is zero.
    pub fn unnamed_data_size(&self) -> Option<u64> {
        let mut resident_size = None;
        let mut first_extent_size = None;
        let mut fallback_size = None;
        for attribute in &self.attributes {
            match attribute {
                Attribute::Resident {
                    header, resident, ..
                } if header.attr_type == AttributeType::Data && header.name_length == 0 => {
                    resident_size.get_or_insert(u64::from(resident.value_length));
                }
                Attribute::NonResident {
                    header,
                    non_resident,
                    ..
                } if header.attr_type == AttributeType::Data && header.name_length == 0 => {
                    if non_resident.lowest_vcn == 0 {
                        first_extent_size.get_or_insert(non_resident.real_size);
                    }
                    fallback_size = Some(fallback_size.unwrap_or(0).max(non_resident.real_size));
                }
                _ => {}
            }
        }
        resident_size.or(first_extent_size).or(fallback_size)
    }

    /// Extract Alternate Data Streams (named $DATA attributes).
    pub fn alternate_data_streams(&self) -> Vec<DataStream> {
        let mut streams = Vec::<DataStream>::new();
        for attribute in &self.attributes {
            let (header, size, resident, lowest_vcn) = match attribute {
                Attribute::Resident {
                    header, resident, ..
                } if header.attr_type == AttributeType::Data && header.name_length > 0 => {
                    (header, u64::from(resident.value_length), true, 0)
                }
                Attribute::NonResident {
                    header,
                    non_resident,
                    ..
                } if header.attr_type == AttributeType::Data && header.name_length > 0 => (
                    header,
                    non_resident.real_size,
                    false,
                    non_resident.lowest_vcn,
                ),
                _ => continue,
            };
            let name = header.name.clone().unwrap_or_default();
            if let Some(existing) = streams.iter_mut().find(|stream| stream.name == name) {
                // The zero-VCN extent owns logical size. Later extents often
                // carry zero in this field, so never overwrite it blindly.
                if lowest_vcn == 0 || existing.size == 0 {
                    existing.size = size;
                    existing.attr_id = header.id;
                }
                existing.resident &= resident;
            } else {
                streams.push(DataStream {
                    name,
                    size,
                    resident,
                    attr_id: header.id,
                });
            }
        }
        streams
    }

    pub fn is_dir(&self) -> bool {
        self.header.flags & 0x0002 != 0
    }

    /// Fetch directory entries (works for resident & non‑resident index)
    pub fn directory_entries(&self) -> Option<Vec<DirectoryEntry>> {
        if !self.is_dir() {
            return None;
        }
        let root_attr = self.attributes.iter().find_map(|a| {
            if let Attribute::Resident { value, header, .. } = a {
                (header.attr_type == AttributeType::IndexRoot
                    && header.name.as_deref() == Some("$I30"))
                .then_some(value)
            } else {
                None
            }
        })?;
        parse_index_root(root_attr)
    }

    /// Size of an index‑record for large directories.
    pub fn index_record_size(&self, default: u32) -> u32 {
        if let Some(root) = self.attributes.iter().find_map(|a| {
            if let Attribute::Resident { value, header, .. } = a {
                (header.attr_type == AttributeType::IndexRoot
                    && header.name.as_deref() == Some("$I30"))
                .then_some(value)
            } else {
                None
            }
        }) && root.len() >= 0x0C
        {
            let mut c = Cursor::new(root);
            c.set_position(8);
            if let Ok(sz) = c.read_u32::<LittleEndian>()
                && sz.is_power_of_two()
                && (512..=65_536).contains(&sz)
            {
                return sz;
            }
        }
        default
    }
}

/// Convert record to a human‑readable table string.
impl std::fmt::Display for MFTRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut out = String::new();

        //  Header
        let mut hdr = Table::new();
        hdr.add_row(row!["MFT Entry Header Values"]);
        hdr.add_row(row![b -> "Sequence", self.header.sequence_number]);
        hdr.add_row(row![b -> "$LogFile Sequence Number", self.header.lsn]);
        hdr.add_row(row![b -> "Flags", record_flags_to_string(self.header.flags)]);
        hdr.add_row(row![b -> "Links", self.header.hard_link_count]);
        out.push_str(&hdr.to_string());
        out.push('\n');

        //  Attributes overview
        let mut attrs = Table::new();
        attrs.add_row(row!["Attributes", "Name", "Status", "Size"]);
        for a in &self.attributes {
            let (header, resident, size, name) = match a {
                Attribute::Resident {
                    header, resident, ..
                } => (
                    header,
                    "Resident",
                    resident.value_length as u64,
                    header.name.clone().unwrap_or_else(|| "N/A".to_string()),
                ),
                Attribute::NonResident {
                    header,
                    non_resident,
                    ..
                } => (
                    header,
                    "Non‑resident",
                    non_resident.real_size,
                    header.name.clone().unwrap_or_else(|| "N/A".to_string()),
                ),
            };
            attrs.add_row(row![
                format!(
                    "{:?} (0x{:X}‑#{})",
                    header.attr_type, header.attr_type as u32, header.id
                ),
                name,
                resident,
                format!("{}", size)
            ]);
        }
        out.push('\n');
        out.push_str(&attrs.to_string());

        //  $STANDARD_INFORMATION
        if let Some(std) = self.attributes.iter().find_map(|a| {
            if let Attribute::Resident { value, header, .. } = a {
                (header.attr_type == AttributeType::StandardInformation)
                    .then(|| StandardInformation::from_bytes(value))
                    .flatten()
            } else {
                None
            }
        }) {
            let mut t = Table::new();
            t.add_row(row!["$STANDARD_INFORMATION"]);
            t.add_row(row![b -> "Created", filetime_to_local_datetime(std.created)]);
            t.add_row(row![b -> "File Modified", filetime_to_local_datetime(std.modified)]);
            t.add_row(row![b -> "MFT Modified", filetime_to_local_datetime(std.mft_modified)]);
            t.add_row(row![b -> "Accessed", filetime_to_local_datetime(std.accessed)]);
            t.add_row(row![b -> "Flags", si_flags_to_string(std.file_attrs)]);
            t.add_row(row![b -> "Owner ID", std.owner_id.map_or("‑".into(), |v| v.to_string())]);
            t.add_row(
                row![b -> "Security ID", std.security_id.map_or("‑".into(), |v| v.to_string())],
            );
            if let Some(q) = std.quota_charged {
                t.add_row(row![b -> "Quota Charged", q]);
            }
            if let Some(u) = std.usn {
                t.add_row(row![b -> "Last USN", u]);
            }
            out.push('\n');
            out.push_str(&t.to_string());
        }

        //  All FILE_NAME attributes
        let names = self.file_names();
        if !names.is_empty() {
            let mut t = Table::new();
            t.add_row(row!["$FILE_NAME Attributes"]);
            for fname in names {
                t.add_row(row![b -> "Name", fname.name.clone()]);
                t.add_row(row![b -> "Namespace", format!("{:?}", fname.namespace)]);
                t.add_row(row![b -> "Parent MFT", format!("{} (seq {})", fname.parent_ref, fname.parent_seq)]);
                t.add_row(row![b -> "Allocated", fname.allocated_size]);
                t.add_row(row![b -> "Actual", fname.real_size]);
                t.add_row(row!["Flags", record_flags_to_string(fname.flags as u16)]);
                t.add_row(row![b -> "Timestamps", ""]);
                t.add_row(row!["‑ Created", filetime_to_local_datetime(fname.created)]);
                t.add_row(row![
                    "‑ Modified",
                    filetime_to_local_datetime(fname.modified)
                ]);
                t.add_row(row![
                    "‑ MFT Mod",
                    filetime_to_local_datetime(fname.mft_modified)
                ]);
                t.add_row(row![
                    "‑ Accessed",
                    filetime_to_local_datetime(fname.accessed)
                ]);
                t.add_row(row!["", ""]); // blank separator
            }
            out.push('\n');
            out.push_str(&t.to_string());
        }

        //  Alternate Data Streams
        let ads = self.alternate_data_streams();
        if !ads.is_empty() {
            let mut t = Table::new();
            t.add_row(row!["Alternate Data Streams"]);
            t.add_row(row![b -> "Name", "Size", "Resident"]);
            for s in ads {
                t.add_row(row![s.name, s.size, if s.resident { "Yes" } else { "No" }]);
            }
            out.push('\n');
            out.push_str(&t.to_string());
        }

        write!(f, "{}", out)
    }
}

/// Serialize to JSON (uses `serde`).
impl MFTRecord {
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "header": &self.header,
            "attributes": &self.attributes,
            "extension_record_ids": &self.extension_record_ids,
            "file_names": self.file_names().into_iter().map(|f| f.to_json()).collect::<Vec<_>>(),
            "ads": self.alternate_data_streams(),
        })
    }
}

/*  Private helpers  */

fn parse_header<R: Read + Seek>(cursor: &mut R) -> Result<FileRecordHeader, String> {
    let mut signature = [0u8; 4];
    cursor
        .read_exact(&mut signature)
        .map_err(|e| e.to_string())?;
    if &signature != b"FILE" {
        error!(
            "Record signature is not 'FILE', found: {}",
            String::from_utf8_lossy(&signature)
        );
        return Err("record signature is not 'FILE'".to_string());
    }
    let usa_offset = cursor
        .read_u16::<LittleEndian>()
        .map_err(|e| e.to_string())?;
    let usa_count = cursor
        .read_u16::<LittleEndian>()
        .map_err(|e| e.to_string())?;
    let lsn = cursor
        .read_u64::<LittleEndian>()
        .map_err(|e| e.to_string())?;
    let sequence_number = cursor
        .read_u16::<LittleEndian>()
        .map_err(|e| e.to_string())?;
    let hard_link_count = cursor
        .read_u16::<LittleEndian>()
        .map_err(|e| e.to_string())?;
    let attrs_offset = cursor
        .read_u16::<LittleEndian>()
        .map_err(|e| e.to_string())?;
    let flags = cursor
        .read_u16::<LittleEndian>()
        .map_err(|e| e.to_string())?;
    let bytes_in_use = cursor
        .read_u32::<LittleEndian>()
        .map_err(|e| e.to_string())?;
    let bytes_allocated = cursor
        .read_u32::<LittleEndian>()
        .map_err(|e| e.to_string())?;
    let base_file_record = cursor
        .read_u64::<LittleEndian>()
        .map_err(|e| e.to_string())?;
    let next_attr_id = cursor
        .read_u16::<LittleEndian>()
        .map_err(|e| e.to_string())?;
    cursor
        .seek(SeekFrom::Current(6))
        .map_err(|e| e.to_string())?;
    Ok(FileRecordHeader {
        signature,
        usa_offset,
        usa_count,
        lsn,
        sequence_number,
        hard_link_count,
        attrs_offset,
        flags,
        bytes_in_use,
        bytes_allocated,
        base_file_record,
        next_attr_id,
    })
}

fn parse_attribute(
    raw: &[u8],
    start_pos: usize,
    record_limit: usize,
    attr_type: AttributeType,
) -> Result<(Attribute, usize), String> {
    let common_end = start_pos
        .checked_add(0x10)
        .ok_or("attribute header offset overflow")?;
    if common_end > record_limit || common_end > raw.len() {
        return Err("truncated attribute common header".into());
    }

    let u16_at = |off: usize| -> Result<u16, String> {
        let end = off.checked_add(2).ok_or("attribute offset overflow")?;
        let bytes = raw.get(off..end).ok_or("truncated attribute u16")?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    };
    let u32_at = |off: usize| -> Result<u32, String> {
        let end = off.checked_add(4).ok_or("attribute offset overflow")?;
        let bytes = raw.get(off..end).ok_or("truncated attribute u32")?;
        Ok(u32::from_le_bytes(
            bytes.try_into().map_err(|_| "truncated attribute u32")?,
        ))
    };
    let u64_at = |off: usize| -> Result<u64, String> {
        let end = off.checked_add(8).ok_or("attribute offset overflow")?;
        let bytes = raw.get(off..end).ok_or("truncated attribute u64")?;
        Ok(u64::from_le_bytes(
            bytes.try_into().map_err(|_| "truncated attribute u64")?,
        ))
    };

    let length = u32_at(start_pos + 4)?;
    let length_usize = usize::try_from(length).map_err(|_| "attribute length overflow")?;
    if length_usize < 0x10 || length_usize % 8 != 0 {
        return Err("attribute length is smaller than its common header".into());
    }
    let attr_end = start_pos
        .checked_add(length_usize)
        .ok_or("attribute end offset overflow")?;
    if attr_end > record_limit || attr_end > raw.len() {
        return Err("attribute extends beyond bytes_in_use".into());
    }

    let non_resident = raw[start_pos + 8] != 0;
    if raw[start_pos + 8] > 1 {
        return Err("invalid resident flag in attribute header".into());
    }
    let name_length = raw[start_pos + 9];
    let name_offset = u16_at(start_pos + 0x0A)?;
    let flags = u16_at(start_pos + 0x0C)?;
    let id = u16_at(start_pos + 0x0E)?;
    let minimum_header_end = start_pos
        .checked_add(if non_resident { 0x40 } else { 0x18 })
        .ok_or("attribute header end overflow")?;
    if attr_end < minimum_header_end {
        return Err("attribute is shorter than its resident header".into());
    }

    let name = if name_length > 0 {
        let name_bytes = usize::from(name_length)
            .checked_mul(2)
            .ok_or("attribute name length overflow")?;
        let name_pos = start_pos
            .checked_add(usize::from(name_offset))
            .ok_or("attribute name offset overflow")?;
        let name_end = name_pos
            .checked_add(name_bytes)
            .ok_or("attribute name end overflow")?;
        if name_pos < minimum_header_end || name_end > attr_end {
            return Err("attribute name extends beyond attribute".into());
        }
        let encoded = &raw[name_pos..name_end];
        Some(
            String::from_utf16(
                &encoded
                    .chunks_exact(2)
                    .map(|b| u16::from_le_bytes([b[0], b[1]]))
                    .collect::<Vec<_>>(),
            )
            .map_err(|_| "attribute name is not valid UTF-16")?,
        )
    } else {
        None
    };

    let common = AttributeHeaderCommon {
        attr_type,
        length,
        non_resident,
        name_length,
        name_offset,
        flags,
        id,
        name,
    };

    let attr = if !non_resident {
        let value_length = u32_at(start_pos + 0x10)?;
        let value_offset = u16_at(start_pos + 0x14)?;
        let resident_flags = raw[start_pos + 0x16];
        let value_pos = start_pos
            .checked_add(usize::from(value_offset))
            .ok_or("resident value offset overflow")?;
        let value_end = value_pos
            .checked_add(
                usize::try_from(value_length).map_err(|_| "resident value length overflow")?,
            )
            .ok_or("resident value end overflow")?;
        if value_pos < start_pos + 0x18 || value_end > attr_end {
            return Err("resident value extends beyond attribute".into());
        }
        let value = raw[value_pos..value_end].to_vec();
        Attribute::Resident {
            header: common,
            resident: ResidentHeader {
                value_length,
                value_offset,
                resident_flags,
            },
            value,
        }
    } else {
        let lowest_vcn = u64_at(start_pos + 0x10)?;
        let highest_vcn = u64_at(start_pos + 0x18)?;
        let mapping_pairs_offset = u16_at(start_pos + 0x20)?;
        let compression_unit = u16_at(start_pos + 0x22)?;
        let allocated_size = u64_at(start_pos + 0x28)?;
        let real_size = u64_at(start_pos + 0x30)?;
        let initialized_size = u64_at(start_pos + 0x38)?;
        let run_list_pos = start_pos
            .checked_add(usize::from(mapping_pairs_offset))
            .ok_or("mapping-pairs offset overflow")?;
        if run_list_pos < start_pos + 0x40 || run_list_pos > attr_end {
            return Err("mapping pairs extend beyond attribute".into());
        }
        if highest_vcn < lowest_vcn && run_list_pos != attr_end {
            return Err("non-resident attribute has an inverted VCN range".into());
        }
        let run_list = raw[run_list_pos..attr_end].to_vec();
        Attribute::NonResident {
            header: common,
            non_resident: NonResidentHeader {
                lowest_vcn,
                highest_vcn,
                mapping_pairs_offset,
                compression_unit,
                allocated_size,
                real_size,
                initialized_size,
            },
            run_list,
        }
    };

    Ok((attr, attr_end))
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub enum AttributeType {
    StandardInformation = 0x10,
    AttributeList = 0x20,
    FileName = 0x30,
    ObjectId = 0x40,
    SecurityDescriptor = 0x50,
    VolumeName = 0x60,
    VolumeInformation = 0x70,
    Data = 0x80,
    IndexRoot = 0x90,
    IndexAllocation = 0xA0,
    Bitmap = 0xB0,
    ReparsePoint = 0xC0,
    EaInformation = 0xD0,
    Ea = 0xE0,
    PropertySet = 0xF0,
    LoggedUtilityStream = 0x100,
}

impl Attribute {
    pub fn header(&self) -> &AttributeHeaderCommon {
        match self {
            Self::Resident { header, .. } | Self::NonResident { header, .. } => header,
        }
    }

    pub fn lowest_vcn(&self) -> u64 {
        match self {
            Self::Resident { .. } => 0,
            Self::NonResident { non_resident, .. } => non_resident.lowest_vcn,
        }
    }
}

/// One validated entry in an NTFS `$ATTRIBUTE_LIST` value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttributeListEntry {
    pub attr_type: AttributeType,
    pub name: Option<String>,
    pub lowest_vcn: u64,
    pub segment_reference: u64,
    pub segment_sequence: u16,
    pub attribute_id: u16,
}

const ATTRIBUTE_LIST_ENTRY_HEADER_SIZE: usize = 0x1A;

/// Parse the value of `$ATTRIBUTE_LIST` with strict entry and allocation
/// bounds. Padding bytes after the final entry are accepted only when zero.
pub fn parse_attribute_list(
    raw: &[u8],
    max_entries: usize,
) -> Result<Vec<AttributeListEntry>, String> {
    let mut entries = Vec::new();
    let mut offset = 0usize;

    while offset < raw.len() {
        let remaining = &raw[offset..];
        if remaining.iter().all(|byte| *byte == 0) {
            break;
        }
        if remaining.len() < ATTRIBUTE_LIST_ENTRY_HEADER_SIZE {
            return Err("truncated ATTRIBUTE_LIST entry header".into());
        }
        if entries.len() >= max_entries {
            return Err("ATTRIBUTE_LIST entry limit exceeded".into());
        }

        let attr_type_raw = u32::from_le_bytes(
            remaining[0..4]
                .try_into()
                .map_err(|_| "truncated ATTRIBUTE_LIST type")?,
        );
        if attr_type_raw == u32::MAX {
            break;
        }
        let attr_type = AttributeType::try_from(attr_type_raw)
            .map_err(|_| format!("unknown ATTRIBUTE_LIST type 0x{attr_type_raw:X}"))?;
        let record_length = usize::from(u16::from_le_bytes([remaining[4], remaining[5]]));
        let name_length = usize::from(remaining[6]);
        let name_offset = usize::from(remaining[7]);
        if record_length < ATTRIBUTE_LIST_ENTRY_HEADER_SIZE || record_length > remaining.len() {
            return Err("invalid ATTRIBUTE_LIST record length".into());
        }

        let lowest_vcn = u64::from_le_bytes(
            remaining[8..16]
                .try_into()
                .map_err(|_| "truncated ATTRIBUTE_LIST lowest VCN")?,
        );
        let segment_raw = u64::from_le_bytes(
            remaining[16..24]
                .try_into()
                .map_err(|_| "truncated ATTRIBUTE_LIST segment reference")?,
        );
        let segment_reference = segment_raw & 0x0000_FFFF_FFFF_FFFF;
        let segment_sequence = (segment_raw >> 48) as u16;
        let attribute_id = u16::from_le_bytes([remaining[24], remaining[25]]);

        let name = if name_length == 0 {
            None
        } else {
            let name_bytes = name_length
                .checked_mul(2)
                .ok_or("ATTRIBUTE_LIST name length overflow")?;
            let name_end = name_offset
                .checked_add(name_bytes)
                .ok_or("ATTRIBUTE_LIST name offset overflow")?;
            if name_offset < ATTRIBUTE_LIST_ENTRY_HEADER_SIZE || name_end > record_length {
                return Err("ATTRIBUTE_LIST name extends beyond entry".into());
            }
            let utf16 = remaining[name_offset..name_end]
                .chunks_exact(2)
                .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
                .collect::<Vec<_>>();
            Some(
                String::from_utf16(&utf16)
                    .map_err(|_| "ATTRIBUTE_LIST name is not valid UTF-16")?,
            )
        };

        entries.push(AttributeListEntry {
            attr_type,
            name,
            lowest_vcn,
            segment_reference,
            segment_sequence,
            attribute_id,
        });
        offset = offset
            .checked_add(record_length)
            .ok_or("ATTRIBUTE_LIST offset overflow")?;
    }

    Ok(entries)
}

impl TryFrom<u32> for AttributeType {
    type Error = String;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        use AttributeType::*;
        Ok(match value {
            0x10 => StandardInformation,
            0x20 => AttributeList,
            0x30 => FileName,
            0x40 => ObjectId,
            0x50 => SecurityDescriptor,
            0x60 => VolumeName,
            0x70 => VolumeInformation,
            0x80 => Data,
            0x90 => IndexRoot,
            0xA0 => IndexAllocation,
            0xB0 => Bitmap,
            0xC0 => ReparsePoint,
            0xD0 => EaInformation,
            0xE0 => Ea,
            0xF0 => PropertySet,
            0x100 => LoggedUtilityStream,
            _ => return Err("unknown attribute type".to_string()),
        })
    }
}

pub fn filetime_to_local_datetime(ft: u64) -> String {
    let micros_since_1601 = ft / 10;
    const DELTA_MICROS: i64 = 11_644_473_600_000_000;
    let unix_micros = micros_since_1601 as i64 - DELTA_MICROS;
    let secs = unix_micros / 1_000_000;
    let nanos = (unix_micros % 1_000_000) * 1_000;
    Utc.timestamp_opt(secs, nanos as u32)
        .single()
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_default()
}

/// Parsed $STANDARD_INFORMATION (covers v0 & v1, optionally v2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StandardInformation {
    pub created: u64,
    pub modified: u64,
    pub mft_modified: u64,
    pub accessed: u64,
    pub file_attrs: u32,
    pub max_versions: u32,
    pub version_number: u32,
    pub class_id: u32,
    pub owner_id: Option<u32>,
    pub security_id: Option<u32>,
    pub quota_charged: Option<u64>,
    pub usn: Option<u64>,
}

impl StandardInformation {
    pub fn from_bytes(raw: &[u8]) -> Option<Self> {
        if raw.len() < 0x30 {
            return None;
        }
        let mut cur = Cursor::new(raw);
        let created = cur.read_u64::<LittleEndian>().ok()?;
        let modified = cur.read_u64::<LittleEndian>().ok()?;
        let mft_modified = cur.read_u64::<LittleEndian>().ok()?;
        let accessed = cur.read_u64::<LittleEndian>().ok()?;
        let file_attrs = cur.read_u32::<LittleEndian>().ok()?;
        let max_versions = cur.read_u32::<LittleEndian>().ok()?;
        let version_number = cur.read_u32::<LittleEndian>().ok()?;
        let class_id = cur.read_u32::<LittleEndian>().ok()?;
        let owner_id = if raw.len() >= 0x34 {
            Some(cur.read_u32::<LittleEndian>().ok()?)
        } else {
            None
        };
        let security_id = if raw.len() >= 0x38 {
            Some(cur.read_u32::<LittleEndian>().ok()?)
        } else {
            None
        };
        let quota_charged = if raw.len() >= 0x40 {
            Some(cur.read_u64::<LittleEndian>().ok()?)
        } else {
            None
        };
        let usn = if raw.len() >= 0x48 {
            Some(cur.read_u64::<LittleEndian>().ok()?)
        } else {
            None
        };

        Some(Self {
            created,
            modified,
            mft_modified,
            accessed,
            file_attrs,
            max_versions,
            version_number,
            class_id,
            owner_id,
            security_id,
            quota_charged,
            usn,
        })
    }
}

// ----- FileNameAttr -----
/// Namespace byte stored in `$FILE_NAME` and directory index keys.
///
/// NTFS may store both a Win32 long name and a DOS 8.3 alias for the same
/// parent link. Keeping this value is essential: attribute order is not a
/// reliable indication of which name should be presented to investigators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileNameNamespace {
    Posix,
    Win32,
    Dos,
    Win32AndDos,
    Unknown(u8),
}

impl FileNameNamespace {
    pub fn from_raw(value: u8) -> Self {
        match value {
            0 => Self::Posix,
            1 => Self::Win32,
            2 => Self::Dos,
            3 => Self::Win32AndDos,
            other => Self::Unknown(other),
        }
    }

    pub fn as_raw(self) -> u8 {
        match self {
            Self::Posix => 0,
            Self::Win32 => 1,
            Self::Dos => 2,
            Self::Win32AndDos => 3,
            Self::Unknown(value) => value,
        }
    }

    pub fn is_dos_only(self) -> bool {
        self == Self::Dos
    }

    fn preference(self) -> u8 {
        match self {
            Self::Win32 | Self::Win32AndDos => 3,
            Self::Posix => 2,
            Self::Dos => 1,
            Self::Unknown(_) => 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileNameAttr {
    pub parent_ref: u64,
    pub parent_seq: u16,
    pub allocated_size: u64,
    pub real_size: u64,
    pub name: String,
    pub namespace: FileNameNamespace,
    pub flags: u32,
    pub created: u64,      // FILETIME
    pub modified: u64,     // FILETIME
    pub mft_modified: u64, // FILETIME
    pub accessed: u64,     // FILETIME
}

impl FileNameAttr {
    fn parse(raw: &[u8]) -> Option<Self> {
        if raw.len() < 66 {
            return None;
        }
        let mut cur = Cursor::new(raw);
        let parent_raw = cur.read_u64::<LittleEndian>().ok()?;
        let parent_ref = parent_raw & 0x0000_FFFF_FFFF_FFFF;
        let parent_seq = (parent_raw >> 48) as u16;

        let created = cur.read_u64::<LittleEndian>().ok()?; // FILETIME
        let modified = cur.read_u64::<LittleEndian>().ok()?; // FILETIME
        let mft_modified = cur.read_u64::<LittleEndian>().ok()?; // FILETIME
        let accessed = cur.read_u64::<LittleEndian>().ok()?; // FILETIME

        let allocated_size = cur.read_u64::<LittleEndian>().ok()?;
        let real_size = cur.read_u64::<LittleEndian>().ok()?;
        let flags = cur.read_u32::<LittleEndian>().ok()?;
        cur.read_u32::<LittleEndian>().ok()?; // reparse value
        let name_len = cur.read_u8().ok()? as usize;
        let namespace = FileNameNamespace::from_raw(cur.read_u8().ok()?);

        let name_off = 66;
        if raw.len() < name_off + name_len * 2 {
            return None;
        }
        let name_raw = &raw[name_off..name_off + name_len * 2];
        let name = String::from_utf16(
            &name_raw
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect::<Vec<_>>(),
        )
        .ok()?;

        Some(Self {
            parent_ref,
            parent_seq,
            allocated_size,
            real_size,
            name,
            namespace,
            flags,
            created,
            modified,
            mft_modified,
            accessed,
        })
    }

    fn to_json(&self) -> Value {
        json!({
            "name": self.name,
            "namespace": self.namespace,
            "parent": self.parent_ref,
            "allocated": self.allocated_size,
            "size": self.real_size,
            // keep JSON human-friendly by rendering as ISO strings
            "created_raw":       self.created,
            "modified_raw":      self.modified,
            "mft_modified_raw":  self.mft_modified,
            "accessed_raw":      self.accessed,
            "created":       filetime_to_local_datetime(self.created),
            "modified":      filetime_to_local_datetime(self.modified),
            "mft_modified":  filetime_to_local_datetime(self.mft_modified),
            "accessed":      filetime_to_local_datetime(self.accessed),
            "flags": self.flags,
        })
    }
}

/// Decode MFT record flags.
fn record_flags_to_string(flags: u16) -> String {
    let mut v = Vec::new();
    if flags & 0x0001 != 0 {
        v.push("Allocated")
    }
    if flags & 0x0002 != 0 {
        v.push("Directory")
    }
    if flags & 0x0004 != 0 {
        v.push("System")
    }
    if flags & 0x0008 != 0 {
        v.push("Bad")
    }
    if v.is_empty() {
        "None".into()
    } else {
        v.join(" | ")
    }
}

/// Decode FILE attribute flags inside $STANDARD_INFORMATION.
fn si_flags_to_string(flags: u32) -> String {
    let mut v = Vec::new();
    if flags & 0x0001 != 0 {
        v.push("READONLY");
    }
    if flags & 0x0002 != 0 {
        v.push("HIDDEN");
    }
    if flags & 0x0004 != 0 {
        v.push("SYSTEM");
    }
    if flags & 0x0020 != 0 {
        v.push("ARCHIVE");
    }
    if flags & 0x0100 != 0 {
        v.push("TEMPORARY");
    }
    if flags & 0x0200 != 0 {
        v.push("SPARSE_FILE");
    }
    if flags & 0x0400 != 0 {
        v.push("REPARSE_POINT");
    }
    if flags & 0x0800 != 0 {
        v.push("COMPRESSED");
    }
    if flags & 0x1000 != 0 {
        v.push("OFFLINE");
    }
    if flags & 0x2000 != 0 {
        v.push("NOT_CONTENT_INDEXED");
    }
    if flags & 0x4000 != 0 {
        v.push("ENCRYPTED");
    }
    if flags & 0x10000000 != 0 {
        v.push("DIRECTORY");
    }
    if flags & 0x20000000 != 0 {
        v.push("INDEX_VIEW");
    }
    if v.is_empty() {
        "None".to_string()
    } else {
        v.join(" | ")
    }
}

/* Directory parsing helpers (unchanged) */

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryEntry {
    pub file_id: u64,
    pub file_sequence: u16,
    pub name: String,
    pub flags: u8,
    pub parent_ref: u64,
    pub parent_seq: u16,
    pub namespace: FileNameNamespace,
}

impl DirectoryEntry {
    pub fn from_slice(slice: &[u8]) -> Option<(Self, usize)> {
        if slice.len() < 0x10 {
            return None;
        }
        let mut cur = Cursor::new(slice);
        let file_ref = cur.read_u64::<LittleEndian>().ok()?;
        let entry_len = cur.read_u16::<LittleEndian>().ok()? as usize;
        let key_len = cur.read_u16::<LittleEndian>().ok()? as usize;
        let flags = cur.read_u8().ok()?;
        cur.read_u8().ok()?;
        cur.read_u16::<LittleEndian>().ok()?;
        let key_start = 0x10;
        if entry_len < key_start
            || entry_len > slice.len()
            || key_len == 0
            || key_len > entry_len - key_start
        {
            return None;
        }
        let key_slice = &slice[key_start..key_start + key_len];
        let fname = FileNameAttr::parse(key_slice)?;
        Some((
            DirectoryEntry {
                file_id: file_ref & 0x0000_FFFF_FFFF_FFFF,
                file_sequence: (file_ref >> 48) as u16,
                name: fname.name,
                flags,
                parent_ref: fname.parent_ref,
                parent_seq: fname.parent_seq,
                namespace: fname.namespace,
            },
            entry_len,
        ))
    }
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({}))
    }
}

pub fn parse_index_root(raw: &[u8]) -> Option<Vec<DirectoryEntry>> {
    if raw.len() < 0x20 {
        // need at least ROOT(0x10) + HEADER(0x10)
        return None;
    }
    let mut cur = Cursor::new(raw);

    // INDEX_ROOT (0x10)
    cur.read_u32::<LittleEndian>().ok()?; // attr-type
    cur.read_u32::<LittleEndian>().ok()?; // collation
    cur.read_u32::<LittleEndian>().ok()?; // index block size
    cur.read_u8().ok()?; // clusters per index block
    cur.seek(SeekFrom::Current(3)).ok()?; // padding

    // INDEX_HEADER begins at offset 0x10 within raw
    let index_header_base = 0x10usize;

    // INDEX_HEADER (0x10)
    let entries_offset = cur.read_u32::<LittleEndian>().ok()? as usize;
    let total_size = cur.read_u32::<LittleEndian>().ok()? as usize;
    let allocated_size = cur.read_u32::<LittleEndian>().ok()? as usize;
    let _flags = cur.read_u8().ok()?;
    cur.seek(SeekFrom::Current(3)).ok()?;

    parse_index_entries(
        raw,
        index_header_base,
        entries_offset,
        total_size,
        allocated_size,
    )
    .ok()
}

/// Apply INDX fixups and parse the entries of one index-allocation block.
/// Any USA mismatch rejects the entire block.
pub(crate) fn parse_index_record(
    raw: &[u8],
    sector_size: usize,
) -> Result<Vec<DirectoryEntry>, String> {
    if raw.len() < 0x28 || &raw[..4] != b"INDX" {
        return Err("invalid INDX record signature or length".into());
    }
    let mut fixed = raw.to_vec();
    let usa_offset = usize::from(u16::from_le_bytes([fixed[4], fixed[5]]));
    let usa_count = usize::from(u16::from_le_bytes([fixed[6], fixed[7]]));
    apply_fixups_with_sector_size(&mut fixed, usa_offset, usa_count, sector_size)?;

    let index_header_base = 0x18usize;
    let entries_offset = u32::from_le_bytes(
        fixed[0x18..0x1C]
            .try_into()
            .map_err(|_| "truncated INDX entries offset")?,
    ) as usize;
    let total_size = u32::from_le_bytes(
        fixed[0x1C..0x20]
            .try_into()
            .map_err(|_| "truncated INDX total size")?,
    ) as usize;
    let allocated_size = u32::from_le_bytes(
        fixed[0x20..0x24]
            .try_into()
            .map_err(|_| "truncated INDX allocated size")?,
    ) as usize;
    parse_index_entries(
        &fixed,
        index_header_base,
        entries_offset,
        total_size,
        allocated_size,
    )
}

fn parse_index_entries(
    raw: &[u8],
    index_header_base: usize,
    entries_offset: usize,
    total_size: usize,
    allocated_size: usize,
) -> Result<Vec<DirectoryEntry>, String> {
    if entries_offset < 0x10 || total_size < entries_offset || allocated_size < total_size {
        return Err("invalid INDEX_HEADER sizes".into());
    }
    let start = index_header_base
        .checked_add(entries_offset)
        .ok_or("index entries offset overflow")?;
    let end = index_header_base
        .checked_add(total_size)
        .ok_or("index entries end overflow")?;
    let allocation_end = index_header_base
        .checked_add(allocated_size)
        .ok_or("index allocation end overflow")?;
    if start > end || end > allocation_end || allocation_end > raw.len() {
        return Err("INDEX_HEADER extends outside index allocation".into());
    }

    let mut off = start;
    let mut out = Vec::new();
    let mut terminal_seen = false;

    while off.checked_add(0x10).is_some_and(|minimum| minimum <= end) {
        let slice = &raw[off..end];
        let entry_len = usize::from(u16::from_le_bytes([slice[8], slice[9]]));
        let key_len = usize::from(u16::from_le_bytes([slice[10], slice[11]]));
        let entry_flags = u16::from_le_bytes([slice[12], slice[13]]);
        if entry_len < 0x10 || entry_len > slice.len() {
            return Err("invalid index-entry length".into());
        }
        if key_len == 0 {
            if entry_flags & 0x02 != 0 {
                terminal_seen = true;
                break;
            }
            return Err("non-terminal index entry has an empty key".into());
        }
        if let Some((entry, consumed)) = DirectoryEntry::from_slice(slice) {
            if entry.name != "." && entry.name != ".." {
                out.push(entry);
            }
            if entry_flags & 0x02 != 0 {
                terminal_seen = true;
                break;
            } // last entry
            off = off
                .checked_add(consumed)
                .ok_or("index-entry offset overflow")?;
        } else {
            return Err("malformed index-entry key".into());
        }
    }
    if !terminal_seen {
        return Err("index allocation has no terminal entry".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> FileRecordHeader {
        FileRecordHeader {
            signature: *b"FILE",
            usa_offset: 0x30,
            usa_count: 3,
            lsn: 0,
            sequence_number: 7,
            hard_link_count: 1,
            attrs_offset: 0x38,
            flags: 1,
            bytes_in_use: 1024,
            bytes_allocated: 1024,
            base_file_record: 0,
            next_attr_id: 3,
        }
    }

    fn file_name_value(name: &str, namespace: u8, parent: u64, parent_seq: u16) -> Vec<u8> {
        let encoded = name.encode_utf16().collect::<Vec<_>>();
        let mut value = vec![0u8; 66 + encoded.len() * 2];
        let parent_ref = parent | (u64::from(parent_seq) << 48);
        value[0..8].copy_from_slice(&parent_ref.to_le_bytes());
        value[64] = encoded.len() as u8;
        value[65] = namespace;
        for (index, unit) in encoded.into_iter().enumerate() {
            value[66 + index * 2..68 + index * 2].copy_from_slice(&unit.to_le_bytes());
        }
        value
    }

    fn file_name_attribute(id: u16, name: &str, namespace: u8) -> Attribute {
        let value = file_name_value(name, namespace, 42, 9);
        Attribute::Resident {
            header: AttributeHeaderCommon {
                attr_type: AttributeType::FileName,
                length: (24 + value.len()) as u32,
                non_resident: false,
                name_length: 0,
                name_offset: 0,
                flags: 0,
                id,
                name: None,
            },
            resident: ResidentHeader {
                value_length: value.len() as u32,
                value_offset: 24,
                resident_flags: 1,
            },
            value,
        }
    }

    #[test]
    fn preferred_name_uses_namespace_not_attribute_order() {
        let record = MFTRecord {
            id: 100,
            header: header(),
            attributes: vec![
                file_name_attribute(1, "DOCUME~1", 2),
                file_name_attribute(2, "Documents", 1),
            ],
            extension_record_ids: Vec::new(),
        };

        let names = record.file_names();
        assert_eq!(names[0].namespace, FileNameNamespace::Dos);
        assert_eq!(names[1].namespace, FileNameNamespace::Win32);
        assert_eq!(record.primary_name().as_deref(), Some("Documents"));
        assert_eq!(record.parent_file_id(), Some(42));
    }

    #[test]
    fn directory_entry_retains_both_file_references_and_namespace() {
        let key = file_name_value("Documents", 3, 115_693, 2);
        let entry_len = 0x10 + key.len();
        let mut raw = vec![0u8; entry_len];
        let file_ref = 284_399u64 | (11u64 << 48);
        raw[0..8].copy_from_slice(&file_ref.to_le_bytes());
        raw[8..10].copy_from_slice(&(entry_len as u16).to_le_bytes());
        raw[10..12].copy_from_slice(&(key.len() as u16).to_le_bytes());
        raw[0x10..].copy_from_slice(&key);

        let (entry, consumed) = DirectoryEntry::from_slice(&raw).expect("valid entry");
        assert_eq!(consumed, entry_len);
        assert_eq!(entry.file_id, 284_399);
        assert_eq!(entry.file_sequence, 11);
        assert_eq!(entry.parent_ref, 115_693);
        assert_eq!(entry.parent_seq, 2);
        assert_eq!(entry.namespace, FileNameNamespace::Win32AndDos);
    }

    #[test]
    fn attribute_list_parser_validates_fixed_tuple_and_bounds() {
        let mut raw = vec![0u8; 40];
        raw[0..4].copy_from_slice(&(AttributeType::IndexRoot as u32).to_le_bytes());
        raw[4..6].copy_from_slice(&40u16.to_le_bytes());
        raw[6] = 4;
        raw[7] = 0x1A;
        raw[8..16].copy_from_slice(&3u64.to_le_bytes());
        let segment = 320_246u64 | (3u64 << 48);
        raw[16..24].copy_from_slice(&segment.to_le_bytes());
        raw[24..26].copy_from_slice(&7u16.to_le_bytes());
        for (offset, unit) in "$I30".encode_utf16().enumerate() {
            raw[0x1A + offset * 2..0x1C + offset * 2].copy_from_slice(&unit.to_le_bytes());
        }

        let entries = parse_attribute_list(&raw, 1).expect("valid ATTRIBUTE_LIST");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].segment_reference, 320_246);
        assert_eq!(entries[0].segment_sequence, 3);
        assert_eq!(entries[0].lowest_vcn, 3);
        assert_eq!(entries[0].attribute_id, 7);
        assert_eq!(entries[0].name.as_deref(), Some("$I30"));

        raw[4..6].copy_from_slice(&0u16.to_le_bytes());
        assert!(parse_attribute_list(&raw, 1).is_err());
    }

    #[test]
    fn usa_must_protect_the_whole_record_and_match_every_sector() {
        let mut record = vec![0u8; 1024];
        record[48..50].copy_from_slice(&[0xAA, 0x55]);
        record[50..52].copy_from_slice(&[1, 2]);
        record[52..54].copy_from_slice(&[3, 4]);
        record[510..512].copy_from_slice(&[0xAA, 0x55]);
        record[1022..1024].copy_from_slice(&[0xAA, 0x55]);
        apply_fixups_with_sector_size(&mut record, 48, 3, 512).expect("valid USA");
        assert_eq!(&record[510..512], &[1, 2]);
        assert_eq!(&record[1022..1024], &[3, 4]);

        assert!(apply_fixups_with_sector_size(&mut record, 48, 2, 512).is_err());
        record[1022..1024].copy_from_slice(&[0, 0]);
        assert!(apply_fixups_with_sector_size(&mut record, 48, 3, 512).is_err());
    }

    #[test]
    fn zero_length_attribute_is_rejected_instead_of_looping() {
        let mut raw = vec![0u8; 0x40];
        raw[0..4].copy_from_slice(&(AttributeType::Data as u32).to_le_bytes());
        assert!(parse_attribute(&raw, 0, raw.len(), AttributeType::Data).is_err());
    }

    #[test]
    fn index_header_requires_a_bounded_terminal_entry() {
        let mut raw = vec![0u8; 0x20];
        raw[0x10 + 8..0x10 + 10].copy_from_slice(&0x10u16.to_le_bytes());
        raw[0x10 + 12..0x10 + 14].copy_from_slice(&0x02u16.to_le_bytes());
        assert!(parse_index_entries(&raw, 0, 0x10, 0x20, 0x20).is_ok());

        raw[0x10 + 12..0x10 + 14].fill(0);
        assert!(parse_index_entries(&raw, 0, 0x10, 0x20, 0x20).is_err());
        assert!(parse_index_entries(&raw, 0, 0x18, 0x20, 0x18).is_err());
    }

    #[test]
    fn display_skips_truncated_standard_information_without_panicking() {
        let record = MFTRecord {
            id: 10,
            header: header(),
            attributes: vec![Attribute::Resident {
                header: AttributeHeaderCommon {
                    attr_type: AttributeType::StandardInformation,
                    length: 32,
                    non_resident: false,
                    name_length: 0,
                    name_offset: 0,
                    flags: 0,
                    id: 1,
                    name: None,
                },
                resident: ResidentHeader {
                    value_length: 4,
                    value_offset: 24,
                    resident_flags: 0,
                },
                value: vec![0; 4],
            }],
            extension_record_ids: Vec::new(),
        };

        let rendered = record.to_string();
        assert!(rendered.contains("StandardInformation"));
        assert!(!rendered.contains("$STANDARD_INFORMATION"));
    }
}
