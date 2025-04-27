// Sources:
// - https://dubeyko.com/development/FileSystems/NTFS/ntfsdoc.pdf
// - https://en.wikipedia.org/wiki/NTFS
// TODO: include more logs and error handling.
// TODO: Some attributes are missing parsing:
//  - Multiple FILE_NAME Attributes.
//  - ALTERNATE DATA STREAMS.
//  - Parent file id ?
//  - Last User Journal Update Sequence Number ?
//  - SID parsing.
//  - StandardInformation file flags.
use byteorder::{LittleEndian, ReadBytesExt};
use chrono::{TimeZone, Utc};
use core::convert::TryFrom;
use log::error;
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

/// AttributeHeader for resident and non‑resident.
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
    pub resident_flags: u8, // 0 = indexed (for $I30), 1 = normal
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

/// A fully parsed 1 KiB MFT record.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MftRecord {
    pub header: FileRecordHeader,
    pub attributes: Vec<Attribute>,
}

impl MftRecord {
    /// Create a new MFT record object from a buffer of data
    pub fn from_bytes(mut buf: &[u8]) -> Result<Self, String> {
        let mut cursor = Cursor::new(&mut buf);
        let header = match parse_header(&mut cursor) {
            Ok(header) => header,
            Err(err) => {
                error!("Could not parse the FILE Hearder: {:?}", err);
                return Err(err);
            }
        };

        // Position cursor at the first attribute.
        cursor
            .seek(SeekFrom::Start(u64::from(header.attrs_offset)))
            .unwrap();

        let mut attributes = Vec::new();
        loop {
            // Read the attribute type to check for the end marker first.
            let attr_type_num = cursor.read_u32::<LittleEndian>().unwrap();
            if attr_type_num == 0xFFFFFFFF {
                break; // End of attribute list
            }
            let attr_type = AttributeType::try_from(attr_type_num).unwrap();

            // Rewind 4 bytes because `parse_attribute` expects to read from the
            // beginning of the header again.
            cursor.seek(SeekFrom::Current(-4)).unwrap();
            let attr = parse_attribute(&mut cursor, attr_type).unwrap();
            attributes.push(attr);
        }

        Ok(MftRecord { header, attributes })
    }

    /// Fetch the Directory Entries of and MFT Record
    pub fn directory_entries(&self) -> Option<Vec<DirectoryEntry>> {
        // Flag 0x0002 = “this record describes a directory”
        if self.header.flags & 0x0002 == 0 {
            return None;
        }

        // Grab the first resident $INDEX_ROOT we can find.
        let root_attr = self.attributes.iter().find_map(|a| {
            if let Attribute::Resident { value, header, .. } = a {
                if header.attr_type == AttributeType::IndexRoot {
                    return Some(value);
                }
            }
            None
        })?;

        parse_index_root(root_attr)
    }

    /// Fetch the size of an index record
    pub fn index_record_size(&self, default: u32) -> u32 {
        if let Some(root) = self.attributes.iter().find_map(|a| {
            if let Attribute::Resident { value, header, .. } = a {
                (header.attr_type == AttributeType::IndexRoot).then_some(value)
            } else {
                None
            }
        }) {
            if root.len() >= 0x0C {
                use byteorder::{LittleEndian, ReadBytesExt};
                let mut c = std::io::Cursor::new(root);
                c.set_position(8); // skip attr-type & collation
                if let Ok(sz) = c.read_u32::<LittleEndian>() {
                    if sz.is_power_of_two() && sz >= 512 && sz <= 65_536 {
                        return sz;
                    }
                }
            }
        }
        default
    }

    pub fn to_string(&self) -> String {
        let mut out = String::new();
        let mut hdr = Table::new();
        hdr.add_row(row!["MFT Entry Header Values"]);
        hdr.add_row(row![b -> "Sequence",  self.header.sequence_number]);
        hdr.add_row(row![b -> "$LogFile Sequence Number", self.header.lsn]);
        hdr.add_row(row![b -> "Flags",     record_flags_to_string(self.header.flags)]);
        hdr.add_row(row![b -> "Links",     self.header.hard_link_count]);
        out.push_str(&hdr.to_string());
        out.push('\n');

        let mut attrs = Table::new();
        attrs.add_row(row!["Attributes", "Name", "Status", "Size"]);
        for a in &self.attributes {
            let (header, resident, size, name) = match a {
                Attribute::Resident {
                    header, resident, ..
                } => (
                    header,
                    "Resident",
                    resident.value_length,
                    header.name.clone().unwrap_or_else(|| "N/A".to_string()),
                ),
                Attribute::NonResident {
                    header,
                    non_resident,
                    ..
                } => (
                    header,
                    "Non-resident",
                    non_resident.real_size as u32,
                    if header.name_length == 0 {
                        "N/A".into()
                    } else {
                        header.name.clone().unwrap_or_else(|| "N/A".to_string())
                    },
                ),
            };
            attrs.add_row(row![
                format!(
                    "{:?} ({:X}-{:#})",
                    header.attr_type, header.attr_type as u32, header.id
                ),
                format!("{}", name),
                resident,
                format!("{}", size)
            ]);
        }
        out.push('\n');
        out.push_str(&attrs.to_string());

        if let Some(std) = self.attributes.iter().find_map(|a| {
            if let Attribute::Resident { value, header, .. } = a {
                if header.attr_type == AttributeType::StandardInformation {
                    return StandardInformation::from_bytes(value);
                }
            }
            None
        }) {
            let mut t = Table::new();
            t.add_row(row!["$STANDARD_INFORMATION Attribute Values"]);
            t.add_row(row![b -> "Owner ID",     std.owner_id]);
            t.add_row(row![b -> "Security ID",  std.security_id]);
            t.add_row(row![b -> "Created",      std.created]);
            t.add_row(row![b -> "File Modified",std.modified]);
            t.add_row(row![b -> "MFT Modified", std.mft_modified]);
            t.add_row(row![b -> "Accessed",     std.accessed]);
            out.push('\n');
            out.push_str(&t.to_string());
            out.push('\n');
        }

        if let Some(fname) = self.attributes.iter().find_map(|a| {
            if let Attribute::Resident { value, header, .. } = a {
                if header.attr_type == AttributeType::FileName {
                    return FileNameAttr::parse(value);
                }
            }
            None
        }) {
            let mut t = Table::new();
            t.add_row(row!["$FILE_NAME Attribute Values"]);
            if fname.flags & 0x0002 != 0 {
                t.add_row(row![b -> "Flags",    "Directory"]);
            } else {
                t.add_row(row![b -> "Flags",    "File"]);
            }
            t.add_row(row![b -> "Name",            fname.name]);
            t.add_row(row![b -> "Parent MFT Entry", format!("{} (seq {})", fname.parent_ref, fname.parent_seq)]);
            t.add_row(row![b -> "Allocated Size",   fname.allocated_size]);
            t.add_row(row![b -> "Actual Size",      fname.real_size]);
            t.add_row(row![b -> "Created",          fname.created]);
            t.add_row(row![b -> "File Modified",    fname.modified]);
            t.add_row(row![b -> "MFT Modified",     fname.mft_modified]);
            t.add_row(row![b -> "Accessed",         fname.accessed]);
            out.push('\n');
            out.push_str(&t.to_string());
            out.push('\n');
        }

        out
    }

    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({}))
    }
}

/// Parse a FILE record header
fn parse_header<R: Read + Seek>(cursor: &mut R) -> Result<FileRecordHeader, String> {
    let mut signature = [0u8; 4];
    cursor.read_exact(&mut signature).unwrap();
    if &signature != b"FILE" {
        error!(
            "Record signature is not 'FILE', found: {}",
            String::from_utf8_lossy(&signature)
        );
        return Err("record signature is not 'FILE'".to_string());
    }
    let usa_offset = cursor.read_u16::<LittleEndian>().unwrap();
    let usa_count = cursor.read_u16::<LittleEndian>().unwrap();
    let lsn = cursor.read_u64::<LittleEndian>().unwrap();
    let sequence_number = cursor.read_u16::<LittleEndian>().unwrap();
    let hard_link_count = cursor.read_u16::<LittleEndian>().unwrap();
    let attrs_offset = cursor.read_u16::<LittleEndian>().unwrap();
    let flags_bits = cursor.read_u16::<LittleEndian>().unwrap();
    let bytes_in_use = cursor.read_u32::<LittleEndian>().unwrap();
    let bytes_allocated = cursor.read_u32::<LittleEndian>().unwrap();
    let base_file_record = cursor.read_u64::<LittleEndian>().unwrap();
    let next_attr_id = cursor.read_u16::<LittleEndian>().unwrap();

    // Skip 2 bytes of `align_to_4_bytes` and 4 bytes of `mft_record_number`
    cursor.seek(SeekFrom::Current(6)).unwrap();

    Ok(FileRecordHeader {
        signature,
        usa_offset,
        usa_count,
        lsn,
        sequence_number,
        hard_link_count,
        attrs_offset,
        flags: flags_bits,
        bytes_in_use,
        bytes_allocated,
        base_file_record,
        next_attr_id,
    })
}

/// Parse any MFT Attribute
fn parse_attribute<R: Read + Seek>(
    cursor: &mut R,
    attr_type: AttributeType,
) -> Result<Attribute, String> {
    let start_pos = cursor.stream_position().unwrap();

    cursor.seek(SeekFrom::Current(4)).unwrap();
    let length = cursor.read_u32::<LittleEndian>().unwrap();
    let non_resident = cursor.read_u8().unwrap() != 0;
    let name_length = cursor.read_u8().unwrap();
    let name_offset = cursor.read_u16::<LittleEndian>().unwrap();
    let flags_bits = cursor.read_u16::<LittleEndian>().unwrap();
    let id = cursor.read_u16::<LittleEndian>().unwrap();

    let name = if name_length > 0 {
        // Save where we are, jump to the name, read it, jump back
        let after_common = cursor.stream_position().unwrap();
        let name_pos = start_pos + u64::from(name_offset);
        cursor.seek(SeekFrom::Start(name_pos)).unwrap();

        let mut raw = vec![0u8; name_length as usize * 2]; // UTF-16 → 2 bytes/char
        cursor.read_exact(&mut raw).unwrap();
        cursor.seek(SeekFrom::Start(after_common)).unwrap();

        String::from_utf16(
            &raw.chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect::<Vec<_>>(),
        )
        .ok()
    } else {
        None
    };

    let common = AttributeHeaderCommon {
        attr_type,
        length,
        non_resident,
        name_length,
        name_offset,
        flags: flags_bits,
        id,
        name,
    };

    let attr = if !non_resident {
        // Resident attribute − 8 byte resident header
        let value_length = cursor.read_u32::<LittleEndian>().unwrap();
        let value_offset = cursor.read_u16::<LittleEndian>().unwrap();
        let resident_flags = cursor.read_u8().unwrap();
        cursor.read_u8().unwrap(); // padding

        // Save current pos; jump to the value, read it, come back.
        let after_resident_pos = cursor.stream_position().unwrap();
        let value_pos = start_pos + u64::from(value_offset);
        cursor.seek(SeekFrom::Start(value_pos)).unwrap();
        let mut value = vec![0u8; value_length as usize];
        cursor.read_exact(&mut value).unwrap();
        cursor.seek(SeekFrom::Start(after_resident_pos)).unwrap();

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
        // Non‑resident attribute − 40 byte header (we parse a subset)
        let lowest_vcn = cursor.read_u64::<LittleEndian>().unwrap();
        let highest_vcn = cursor.read_u64::<LittleEndian>().unwrap();
        let mapping_pairs_offset = cursor.read_u16::<LittleEndian>().unwrap();
        let compression_unit = cursor.read_u16::<LittleEndian>().unwrap();
        cursor.seek(SeekFrom::Current(5)).unwrap(); // skip reserved
        let allocated_size = cursor.read_u64::<LittleEndian>().unwrap();
        let real_size = cursor.read_u64::<LittleEndian>().unwrap();
        let initialized_size = cursor.read_u64::<LittleEndian>().unwrap();

        // Save position, read run list, restore.
        let after_nr_header = cursor.stream_position().unwrap();
        let run_list_pos = start_pos + u64::from(mapping_pairs_offset);
        cursor.seek(SeekFrom::Start(run_list_pos)).unwrap();
        let run_list_len = (length as u64 + start_pos) - run_list_pos;
        let mut run_list = vec![0u8; run_list_len as usize];
        cursor.read_exact(&mut run_list).unwrap();
        cursor.seek(SeekFrom::Start(after_nr_header)).unwrap();

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

    // Proceed to the next
    cursor
        .seek(SeekFrom::Start(start_pos + u64::from(length)))
        .unwrap();
    Ok(attr)
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
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

/// Windows FILETIME → RFC3339
fn filetime_to_local_datetime(ft: u64) -> String {
    let micros_since_1601 = ft / 10;
    const DELTA_MICROS: i64 = 116_444_736_000_000_00;
    let unix_micros = micros_since_1601 as i64 - DELTA_MICROS;
    let secs = unix_micros / 1_000_000;
    let nanos = (unix_micros % 1_000_000) * 1_000;
    Utc.timestamp_opt(secs, nanos as u32)
        .single()
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_default()
}

/// Parsed $STANDARD_INFORMATION (first 72 bytes are identical on every NTFS version)
#[derive(Debug)]
struct StandardInformation {
    created: String,
    modified: String,
    mft_modified: String,
    accessed: String,
    owner_id: u32,
    security_id: u32,
    file_flags: u32,
}

impl StandardInformation {
    fn from_bytes(raw: &[u8]) -> Option<Self> {
        if raw.len() < 72 {
            return None;
        }
        let mut cur = Cursor::new(raw);
        use byteorder::{LittleEndian, ReadBytesExt};
        let created = filetime_to_local_datetime(cur.read_u64::<LittleEndian>().ok()?);
        let modified = filetime_to_local_datetime(cur.read_u64::<LittleEndian>().ok()?);
        let mft_modified = filetime_to_local_datetime(cur.read_u64::<LittleEndian>().ok()?);
        let accessed = filetime_to_local_datetime(cur.read_u64::<LittleEndian>().ok()?);
        let owner_id = cur.read_u32::<LittleEndian>().ok()?;
        let security_id = cur.read_u32::<LittleEndian>().ok()?;
        let file_flags = cur.read_u32::<LittleEndian>().ok()?;
        Some(Self {
            created,
            modified,
            mft_modified,
            accessed,
            owner_id,
            security_id,
            file_flags,
        })
    }
}

/// Parsed $FILE_NAME (first 66 bytes of the attribute, *before* the UTF-16LE name)
#[derive(Debug)]
struct FileNameAttr {
    parent_ref: u64,
    parent_seq: u16,
    allocated_size: u64,
    real_size: u64,
    name: String,
    flags: u32,
    created: String,
    modified: String,
    mft_modified: String,
    accessed: String,
}

impl FileNameAttr {
    fn parse(raw: &[u8]) -> Option<Self> {
        if raw.len() < 66 {
            return None;
        }
        use byteorder::{LittleEndian, ReadBytesExt};
        let mut cur = Cursor::new(raw);

        let parent_raw = cur.read_u64::<LittleEndian>().ok()?;
        let parent_ref = parent_raw & 0x0000_FFFF_FFFF_FFFF;
        let parent_seq = (parent_raw >> 48) as u16;

        let created = filetime_to_local_datetime(cur.read_u64::<LittleEndian>().ok()?);
        let modified = filetime_to_local_datetime(cur.read_u64::<LittleEndian>().ok()?);
        let mft_modified = filetime_to_local_datetime(cur.read_u64::<LittleEndian>().ok()?);
        let accessed = filetime_to_local_datetime(cur.read_u64::<LittleEndian>().ok()?);

        let allocated_size = cur.read_u64::<LittleEndian>().ok()?;
        let real_size = cur.read_u64::<LittleEndian>().ok()?;
        let flags = cur.read_u32::<LittleEndian>().ok()?;
        let _reparse = cur.read_u32::<LittleEndian>().ok()?; // Reparse value
        let name_len = cur.read_u8().ok()? as usize; // characters
        let _name_ns = cur.read_u8().ok()?; // name space

        // UTF-16LE file name follows immediately
        let name_off = 66; // bytes
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
            flags,
            created,
            modified,
            mft_modified,
            accessed,
        })
    }
}

/// Helpers to decode bit-flags
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

/// One entry (child) found in the directory’s $INDEX_ROOT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryEntry {
    pub file_id: u64,
    pub name: String,
    pub flags: u8,
}

impl DirectoryEntry {
    pub fn from_slice(slice: &[u8]) -> Option<(Self, usize)> {
        // Minimum INDEX_ENTRY header is 16 bytes
        if slice.len() < 0x10 {
            return None;
        }
        let mut cur = Cursor::new(slice);
        use byteorder::{LittleEndian, ReadBytesExt};

        let file_ref = cur.read_u64::<LittleEndian>().ok()?;
        let entry_len = cur.read_u16::<LittleEndian>().ok()? as usize;
        let key_len = cur.read_u16::<LittleEndian>().ok()? as usize;
        let flags = cur.read_u8().ok()?;
        cur.read_u8().ok()?; // padding
        cur.read_u16::<LittleEndian>().ok()?; // padding / VCN for sub-node

        // Key = full $FILE_NAME attribute value
        // The header we just consumed is always 0x10 bytes, the key begins
        // immediately afterwards and runs for `key_len` bytes.
        let key_start = 0x10;
        if slice.len() < key_start + key_len {
            return None;
        }
        let key_slice = &slice[key_start..key_start + key_len];
        let fname = FileNameAttr::parse(key_slice)?;

        Some((
            DirectoryEntry {
                file_id: file_ref & 0x0000_FFFF_FFFF_FFFF,
                name: fname.name,
                flags,
            },
            entry_len,
        ))
    }
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({}))
    }
}

fn parse_index_root(raw: &[u8]) -> Option<Vec<DirectoryEntry>> {
    // INDEX_ROOT header is 0x10 bytes, immediately followed by INDEX_HEADER.
    if raw.len() < 0x18 {
        return None;
    }
    use byteorder::{LittleEndian, ReadBytesExt};
    let mut cur = Cursor::new(raw);

    let _attr_type = cur.read_u32::<LittleEndian>().ok()?;
    let _collation_rule = cur.read_u32::<LittleEndian>().ok()?;
    let _index_block_size = cur.read_u32::<LittleEndian>().ok()?;
    let _clusters_per_rec = cur.read_u8().ok()?;
    cur.seek(SeekFrom::Current(3)).ok()?; // padding

    // INDEX_HEADER (inside INDEX_ROOT) – 16 bytes
    let entries_offset = cur.read_u32::<LittleEndian>().ok()? as usize;
    let total_size = cur.read_u32::<LittleEndian>().ok()? as usize;
    let _alloc_size = cur.read_u32::<LittleEndian>().ok()?;
    let _flags = cur.read_u8().ok()?;
    cur.seek(SeekFrom::Current(3)).ok()?; // padding

    // Begin processing all INDEX_ENTRY structures
    let start = entries_offset;
    let end = entries_offset + total_size;
    let mut off = start;
    let mut out = Vec::new();
    while off + 0x10 <= end && off + 0x10 <= raw.len() {
        let slice = &raw[off..];
        let (entry, consumed) = match DirectoryEntry::from_slice(slice) {
            Some(v) => v,
            None => break,
        };

        let flags = entry.flags;
        if entry.name != "." && entry.name != ".." {
            out.push(entry);
        }
        // Bit 0x02 = last entry – stop when we see it.
        if flags & 0x02 != 0 {
            break;
        }
        off += consumed;
    }
    Some(out)
}
