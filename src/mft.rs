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
}

/// A fully parsed 1 KiB MFT record.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MFTRecord {
    pub id: u64,
    pub header: FileRecordHeader,
    pub attributes: Vec<Attribute>,
}

// At the end of every 512‑byte sector NTFS overwrites the last two bytes with the Update‑Sequence Number (USN).
fn apply_fixups(buf: &mut [u8], usa_offset: usize, usa_count: usize) -> Result<(), String> {
    if usa_offset + 2 * usa_count > buf.len() {
        warn!("Incomplete multi‑sector transfer – corrupted MFT record.");
        return Err("USA table outside record".into());
    }
    if usa_count < 1 {
        debug!("MFT record verified (USA check OK).");
        return Ok(());
    }

    debug!("Detected a multi-sector record, patching.");

    // Take a copy of the Update‑Sequence Number, not a slice
    let usn = [buf[usa_offset], buf[usa_offset + 1]];

    for i in 1..usa_count {
        let sector_end = i * 512 - 2;
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

impl MFTRecord {
    /// Parse a raw 1 KiB record into a `MFTRecord`.
    pub fn from_bytes(raw: &[u8], identifier: Option<u64>) -> Result<Self, String> {
        // we need a mutable copy so we can patch the USNs in‑place
        let mut buf = raw.to_vec();

        let mut cursor = Cursor::new(&buf);
        let header = parse_header(&mut cursor)?;

        apply_fixups(
            &mut buf,
            header.usa_offset as usize,
            header.usa_count as usize,
        )?;

        cursor = Cursor::new(&buf);
        cursor
            .seek(SeekFrom::Start(header.attrs_offset.into()))
            .unwrap();

        let mut attributes = Vec::new();
        loop {
            /* stop if fewer than 4 bytes remain */
            if cursor.position() + 4 > header.bytes_in_use as u64 {
                break;
            }

            let attr_type_num = match cursor.read_u32::<LittleEndian>() {
                Ok(v) => v,
                Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break, // graceful
                Err(e) => return Err(e.to_string()),
            };
            if attr_type_num == 0xFFFFFFFF {
                break;
            }

            let attr_type = AttributeType::try_from(attr_type_num)?;
            cursor.seek(SeekFrom::Current(-4)).unwrap();
            let attr = parse_attribute(&mut cursor, attr_type)?; // propagate errors
            attributes.push(attr);
        }

        Ok(MFTRecord {
            id: identifier.unwrap_or(0),
            header,
            attributes,
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

    /// Return the first (usually long) name, if present.
    pub fn primary_name(&self) -> Option<String> {
        self.file_names().into_iter().next().map(|f| f.name)
    }

    /// Parent directory MFT reference (from the first $FILE_NAME attribute).
    pub fn parent_file_id(&self) -> Option<u64> {
        self.file_names().first().map(|f| f.parent_ref)
    }

    /// Extract Alternate Data Streams (named $DATA attributes).
    pub fn alternate_data_streams(&self) -> Vec<DataStream> {
        self.attributes
            .iter()
            .filter_map(|a| match a {
                Attribute::Resident {
                    header, resident, ..
                } if header.attr_type == AttributeType::Data && header.name_length > 0 => {
                    Some(DataStream {
                        name: header.name.clone().unwrap_or_default(),
                        size: resident.value_length as u64,
                        resident: true,
                    })
                }
                Attribute::NonResident {
                    header,
                    non_resident,
                    ..
                } if header.attr_type == AttributeType::Data && header.name_length > 0 => {
                    Some(DataStream {
                        name: header.name.clone().unwrap_or_default(),
                        size: non_resident.real_size,
                        resident: false,
                    })
                }
                _ => None,
            })
            .collect()
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
                (header.attr_type == AttributeType::IndexRoot).then_some(value)
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
                (header.attr_type == AttributeType::IndexRoot).then_some(value)
            } else {
                None
            }
        }) {
            if root.len() >= 0x0C {
                let mut c = Cursor::new(root);
                c.set_position(8);
                if let Ok(sz) = c.read_u32::<LittleEndian>() {
                    if sz.is_power_of_two() && sz >= 512 && sz <= 65_536 {
                        return sz;
                    }
                }
            }
        }
        default
    }

    /// Convert record to a human‑readable table string.
    pub fn to_string(&self) -> String {
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
            } else {
                None
            }
        }) {
            let std = std.unwrap();
            let mut t = Table::new();
            t.add_row(row!["$STANDARD_INFORMATION"]);
            t.add_row(row![b -> "Created", std.created]);
            t.add_row(row![b -> "File Modified", std.modified]);
            t.add_row(row![b -> "MFT Modified", std.mft_modified]);
            t.add_row(row![b -> "Accessed", std.accessed]);
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
                t.add_row(row![b -> "Parent MFT", format!("{} (seq {})", fname.parent_ref, fname.parent_seq)]);
                t.add_row(row![b -> "Allocated", fname.allocated_size]);
                t.add_row(row![b -> "Actual", fname.real_size]);
                t.add_row(row!["Flags", record_flags_to_string(fname.flags as u16)]);
                t.add_row(row![b -> "Timestamps", ""]);
                t.add_row(row!["‑ Created", fname.created]);
                t.add_row(row!["‑ Modified", fname.modified]);
                t.add_row(row!["‑ MFT Mod", fname.mft_modified]);
                t.add_row(row!["‑ Accessed", fname.accessed]);
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

        out
    }

    /// Serialize to JSON (uses `serde`).
    pub fn to_json(&self) -> Value {
        json!({
            "header": &self.header,
            "attributes": &self.attributes,
            "file_names": self.file_names().into_iter().map(|f| f.to_json()).collect::<Vec<_>>(),
            "ads": self.alternate_data_streams(),
        })
    }
}

/*  Private helpers  */

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
    let flags = cursor.read_u16::<LittleEndian>().unwrap();
    let bytes_in_use = cursor.read_u32::<LittleEndian>().unwrap();
    let bytes_allocated = cursor.read_u32::<LittleEndian>().unwrap();
    let base_file_record = cursor.read_u64::<LittleEndian>().unwrap();
    let next_attr_id = cursor.read_u16::<LittleEndian>().unwrap();
    cursor.seek(SeekFrom::Current(6)).unwrap();
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
    let flags = cursor.read_u16::<LittleEndian>().unwrap();
    let id = cursor.read_u16::<LittleEndian>().unwrap();

    let name = if name_length > 0 {
        let after_common = cursor.stream_position().unwrap();
        let name_pos = start_pos + u64::from(name_offset);
        cursor.seek(SeekFrom::Start(name_pos)).unwrap();
        let mut raw = vec![0u8; name_length as usize * 2];
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
        flags,
        id,
        name,
    };

    let attr = if !non_resident {
        let value_length = cursor.read_u32::<LittleEndian>().unwrap();
        let value_offset = cursor.read_u16::<LittleEndian>().unwrap();
        let resident_flags = cursor.read_u8().unwrap();
        cursor.read_u8().unwrap();
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
        let lowest_vcn = cursor.read_u64::<LittleEndian>().unwrap();
        let highest_vcn = cursor.read_u64::<LittleEndian>().unwrap();
        let mapping_pairs_offset = cursor.read_u16::<LittleEndian>().unwrap();
        let compression_unit = cursor.read_u16::<LittleEndian>().unwrap();
        cursor.seek(SeekFrom::Current(4)).unwrap();
        let allocated_size = cursor.read_u64::<LittleEndian>().unwrap();
        let real_size = cursor.read_u64::<LittleEndian>().unwrap();
        let initialized_size = cursor.read_u64::<LittleEndian>().unwrap();
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

/// Parsed $STANDARD_INFORMATION (covers v0 & v1, optionally v2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StandardInformation {
    pub created: String,
    pub modified: String,
    pub mft_modified: String,
    pub accessed: String,
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
        let created = filetime_to_local_datetime(cur.read_u64::<LittleEndian>().ok()?);
        let modified = filetime_to_local_datetime(cur.read_u64::<LittleEndian>().ok()?);
        let mft_modified = filetime_to_local_datetime(cur.read_u64::<LittleEndian>().ok()?);
        let accessed = filetime_to_local_datetime(cur.read_u64::<LittleEndian>().ok()?);
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

/// Parsed $FILE_NAME attribute (first 66 bytes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileNameAttr {
    pub parent_ref: u64,
    pub parent_seq: u16,
    pub allocated_size: u64,
    pub real_size: u64,
    pub name: String,
    pub flags: u32,
    pub created: String,
    pub modified: String,
    pub mft_modified: String,
    pub accessed: String,
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
        let created = filetime_to_local_datetime(cur.read_u64::<LittleEndian>().ok()?);
        let modified = filetime_to_local_datetime(cur.read_u64::<LittleEndian>().ok()?);
        let mft_modified = filetime_to_local_datetime(cur.read_u64::<LittleEndian>().ok()?);
        let accessed = filetime_to_local_datetime(cur.read_u64::<LittleEndian>().ok()?);
        let allocated_size = cur.read_u64::<LittleEndian>().ok()?;
        let real_size = cur.read_u64::<LittleEndian>().ok()?;
        let flags = cur.read_u32::<LittleEndian>().ok()?;
        cur.read_u32::<LittleEndian>().ok()?; // reparse value
        let name_len = cur.read_u8().ok()? as usize;
        cur.read_u8().ok()?; // namespace
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
            "parent": self.parent_ref,
            "allocated": self.allocated_size,
            "size": self.real_size,
            "created": self.created,
            "modified": self.modified,
            "mft_modified": self.mft_modified,
            "accessed": self.accessed,
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
    pub name: String,
    pub flags: u8,
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
    if raw.len() < 0x18 {
        return None;
    }
    let mut cur = Cursor::new(raw);
    cur.read_u32::<LittleEndian>().ok()?; // attr‑type
    cur.read_u32::<LittleEndian>().ok()?; // collation
    cur.read_u32::<LittleEndian>().ok()?; // idx blk size
    cur.read_u8().ok()?;
    cur.seek(SeekFrom::Current(3)).ok()?;
    let entries_offset = cur.read_u32::<LittleEndian>().ok()? as usize;
    let total_size = cur.read_u32::<LittleEndian>().ok()? as usize;
    cur.read_u32::<LittleEndian>().ok()?; // alloc sz
    let flags = cur.read_u8().ok()?;
    cur.seek(SeekFrom::Current(3)).ok()?;
    let start = entries_offset;
    let end = entries_offset + total_size;
    let mut off = start;
    let mut out = Vec::new();
    while off + 0x10 <= end && off + 0x10 <= raw.len() {
        let slice = &raw[off..];
        if let Some((entry, consumed)) = DirectoryEntry::from_slice(slice) {
            let f = entry.flags;
            if entry.name != "." && entry.name != ".." {
                out.push(entry);
            }
            if f & 0x02 != 0 {
                break;
            }
            off += consumed;
        } else {
            break;
        }
    }
    if flags & 0x01 != 0 {
        // Indicates there is an INDEX_ALLOCATION – handled elsewhere.
    }
    Some(out)
}
