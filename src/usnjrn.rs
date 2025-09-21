// Sources:
// - https://learn.microsoft.com/windows/win32/api/winioctl/ns-winioctl-usn_record_v2
// - https://learn.microsoft.com/windows/win32/api/winioctl/ns-winioctl-usn_record_v3
// - https://learn.microsoft.com/windows/win32/api/winioctl/ns-winioctl-usn_record_v4
// - https://learn.microsoft.com/windows/win32/fileio/file-attribute-constants
//
// $UsnJrnl:$J parser with v2/v3/v4 support + optional forensic enrichment

use byteorder::{LittleEndian, ReadBytesExt};
use chrono::{TimeZone, Utc};
use prettytable::{Table, row};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Read};

// --- ADD near the top of usnjrn.rs (below use ... lines) ---

// USN_REASON_* bit flags (see Microsoft docs)
pub const USN_REASON_DATA_OVERWRITE: u32 = 0x0000_0001;
pub const USN_REASON_DATA_EXTEND: u32 = 0x0000_0002;
pub const USN_REASON_DATA_TRUNCATION: u32 = 0x0000_0004;
pub const USN_REASON_NAMED_DATA_OVERWRITE: u32 = 0x0000_0010;
pub const USN_REASON_NAMED_DATA_EXTEND: u32 = 0x0000_0020;
pub const USN_REASON_NAMED_DATA_TRUNCATION: u32 = 0x0000_0040;
pub const USN_REASON_FILE_CREATE: u32 = 0x0000_0100;
pub const USN_REASON_FILE_DELETE: u32 = 0x0000_0200;
pub const USN_REASON_EA_CHANGE: u32 = 0x0000_0400;
pub const USN_REASON_SECURITY_CHANGE: u32 = 0x0000_0800;
pub const USN_REASON_RENAME_OLD_NAME: u32 = 0x0000_1000;
pub const USN_REASON_RENAME_NEW_NAME: u32 = 0x0000_2000;
pub const USN_REASON_INDEXABLE_CHANGE: u32 = 0x0000_4000;
pub const USN_REASON_BASIC_INFO_CHANGE: u32 = 0x0000_8000;
pub const USN_REASON_HARD_LINK_CHANGE: u32 = 0x0001_0000;
pub const USN_REASON_COMPRESSION_CHANGE: u32 = 0x0002_0000;
pub const USN_REASON_ENCRYPTION_CHANGE: u32 = 0x0004_0000;
pub const USN_REASON_OBJECT_ID_CHANGE: u32 = 0x0008_0000;
pub const USN_REASON_REPARSE_POINT_CHANGE: u32 = 0x0010_0000;
pub const USN_REASON_STREAM_CHANGE: u32 = 0x0020_0000;
pub const USN_REASON_TRANSACTED_CHANGE: u32 = 0x0040_0000;
pub const USN_REASON_INTEGRITY_CHANGE: u32 = 0x0080_0000;
pub const USN_REASON_CLOSE: u32 = 0x8000_0000;

/// Decode USN reason bitfield to a list of human-friendly flag names.
pub fn decode_usn_reasons(reason: u32) -> Vec<&'static str> {
    let mut v = Vec::new();
    if reason & USN_REASON_DATA_OVERWRITE != 0 {
        v.push("DATA_OVERWRITE");
    }
    if reason & USN_REASON_DATA_EXTEND != 0 {
        v.push("DATA_EXTEND");
    }
    if reason & USN_REASON_DATA_TRUNCATION != 0 {
        v.push("DATA_TRUNCATION");
    }
    if reason & USN_REASON_NAMED_DATA_OVERWRITE != 0 {
        v.push("ADS_OVERWRITE");
    }
    if reason & USN_REASON_NAMED_DATA_EXTEND != 0 {
        v.push("ADS_EXTEND");
    }
    if reason & USN_REASON_NAMED_DATA_TRUNCATION != 0 {
        v.push("ADS_TRUNCATION");
    }
    if reason & USN_REASON_FILE_CREATE != 0 {
        v.push("FILE_CREATE");
    }
    if reason & USN_REASON_FILE_DELETE != 0 {
        v.push("FILE_DELETE");
    }
    if reason & USN_REASON_EA_CHANGE != 0 {
        v.push("EA_CHANGE");
    }
    if reason & USN_REASON_SECURITY_CHANGE != 0 {
        v.push("SECURITY_CHANGE");
    }
    if reason & USN_REASON_RENAME_OLD_NAME != 0 {
        v.push("RENAME_OLD_NAME");
    }
    if reason & USN_REASON_RENAME_NEW_NAME != 0 {
        v.push("RENAME_NEW_NAME");
    }
    if reason & USN_REASON_INDEXABLE_CHANGE != 0 {
        v.push("INDEXABLE_CHANGE");
    }
    if reason & USN_REASON_BASIC_INFO_CHANGE != 0 {
        v.push("BASIC_INFO_CHANGE");
    }
    if reason & USN_REASON_HARD_LINK_CHANGE != 0 {
        v.push("HARD_LINK_CHANGE");
    }
    if reason & USN_REASON_COMPRESSION_CHANGE != 0 {
        v.push("COMPRESSION_CHANGE");
    }
    if reason & USN_REASON_ENCRYPTION_CHANGE != 0 {
        v.push("ENCRYPTION_CHANGE");
    }
    if reason & USN_REASON_OBJECT_ID_CHANGE != 0 {
        v.push("OBJECT_ID_CHANGE");
    }
    if reason & USN_REASON_REPARSE_POINT_CHANGE != 0 {
        v.push("REPARSE_POINT_CHANGE");
    }
    if reason & USN_REASON_STREAM_CHANGE != 0 {
        v.push("STREAM_CHANGE");
    }
    if reason & USN_REASON_TRANSACTED_CHANGE != 0 {
        v.push("TRANSACTED_CHANGE");
    }
    if reason & USN_REASON_INTEGRITY_CHANGE != 0 {
        v.push("INTEGRITY_CHANGE");
    }
    if reason & USN_REASON_CLOSE != 0 {
        v.push("CLOSE");
    }
    v
}

/// A single modified-range extent (USN v4 only).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UsnExtent {
    pub offset: i64, // byte offset into the file
    pub length: i64, // bytes
}

/// Unified USN record across v2/v3/v4.
/// - v2 uses 64-bit file refs (lower bits of the u128 fields).
/// - v3/v4 use FILE_ID_128 (128-bit file refs).
/// - v4 does NOT carry the filename; Windows guarantees the last v4 for a file is
///   followed by a v3 with at least USN_REASON_CLOSE that *does* include the name.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UsnRecord {
    pub record_len: u32,
    pub major_version: u16,
    pub minor_version: u16,

    /// 128-bit file references (lower 64 bits match the traditional NTFS reference number).
    pub file_ref: u128,
    pub parent_ref: u128,
    pub file_mft_record_number: u64,
    pub parent_mft_record_number: u64,
    pub usn: i64,
    pub timestamp: u64, // FILETIME (UTC)
    pub reason: u32,
    pub source_info: u32,
    pub security_id: u32,
    pub file_attrs: u32,

    /// File name (component only, *not* the full path). Absent on v4.
    pub name: Option<String>,

    /// v4 range tracking (optional)
    pub remaining_extents: Option<u32>,
    pub extents: Option<Vec<UsnExtent>>,
    pub parent_path: Option<String>,
    pub full_path: Option<String>,
    pub reused_records: Option<Vec<ReusedElement>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum ReuseReason {
    MultipleSequencesInJournal, // this FRN index shows >1 seq across the journal slice
    CurrentSeqDiffersFromUsn,   // current MFT seq != the USN record’s seq (file or parent)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReusedElement {
    pub index: u64,               // 48-bit FRN index
    pub current_seq: Option<u16>, // current MFT sequence if we looked it up
    pub seen_sequences: Vec<u16>, // distinct sequences seen for this index in the journal slice
    pub name: Option<String>,     // best name we had when we touched it in the path
    pub reason: Vec<ReuseReason>, // why we flagged it
}

impl UsnRecord {
    /// Lower 64-bit helpers for MFT lookups
    pub fn file_ref_u64(&self) -> u64 {
        (self.file_ref & 0x0000_FFFF_FFFF_FFFF) as u64
    }
    pub fn parent_ref_u64(&self) -> u64 {
        (self.parent_ref & 0x0000_FFFF_FFFF_FFFF) as u64
    }

    /// Sequence helpers for MFT reuse detection (high 16 bits of the lower 64).
    pub fn file_ref_seq(&self) -> u16 {
        let low64 = (self.file_ref & 0x0000_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF) as u64;
        ((low64 >> 48) & 0xFFFF) as u16
    }
    pub fn parent_ref_seq(&self) -> u16 {
        let low64 = (self.parent_ref & 0x0000_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF) as u64;
        ((low64 >> 48) & 0xFFFF) as u16
    }

    pub fn parse(buf: &[u8]) -> Option<Self> {
        let mut cur = Cursor::new(buf);

        let record_len = cur.read_u32::<LittleEndian>().ok()?;

        if record_len < 60 || (record_len as usize) > buf.len() || record_len % 8 != 0 {
            return None;
        }
        let major_version = cur.read_u16::<LittleEndian>().ok()?;
        let minor_version = cur.read_u16::<LittleEndian>().ok()?;

        match major_version {
            2 => Self::parse_v2(buf, record_len, major_version, minor_version),
            3 => Self::parse_v3(buf, record_len, major_version, minor_version),
            4 => Self::parse_v4(buf, record_len, major_version, minor_version),
            _ => None, // unknown future layout..?
        }
    }

    fn parse_v2(buf: &[u8], record_len: u32, maj: u16, min: u16) -> Option<Self> {
        // Layout per USN_RECORD_V2
        let mut c = Cursor::new(buf);
        c.set_position(8);
        let file_ref = c.read_u64::<LittleEndian>().ok()? as u128;
        let parent_ref = c.read_u64::<LittleEndian>().ok()? as u128;
        let usn = c.read_i64::<LittleEndian>().ok()?;
        let timestamp = c.read_u64::<LittleEndian>().ok()?;
        let reason = c.read_u32::<LittleEndian>().ok()?;
        let source_info = c.read_u32::<LittleEndian>().ok()?;
        let security_id = c.read_u32::<LittleEndian>().ok()?;
        let file_attrs = c.read_u32::<LittleEndian>().ok()?;
        let name_len = c.read_u16::<LittleEndian>().ok()? as usize;
        let name_offset = c.read_u16::<LittleEndian>().ok()? as usize;
        let name = read_utf16_name(buf, record_len as usize, name_offset, name_len)?;
        let file_mft_record_number = (file_ref & 0x0000_FFFF_FFFF_FFFF) as u64;
        let parent_mft_record_number = (parent_ref & 0x0000_FFFF_FFFF_FFFF) as u64;
        Some(Self {
            record_len,
            major_version: maj,
            minor_version: min,
            file_ref,
            parent_ref,
            file_mft_record_number,
            parent_mft_record_number,
            usn,
            timestamp,
            reason,
            source_info,
            security_id,
            file_attrs,
            name: Some(name),
            remaining_extents: None,
            extents: None,
            parent_path: None,
            full_path: None,
            reused_records: None,
        })
    }

    fn parse_v3(buf: &[u8], record_len: u32, maj: u16, min: u16) -> Option<Self> {
        // Layout per USN_RECORD_V3 (FILE_ID_128 for refs)
        let mut c = Cursor::new(buf);
        c.set_position(8);
        let file_ref = read_u128(&mut c).ok()?;
        let parent_ref = read_u128(&mut c).ok()?;
        let usn = c.read_i64::<LittleEndian>().ok()?;
        let timestamp = c.read_u64::<LittleEndian>().ok()?;
        let reason = c.read_u32::<LittleEndian>().ok()?;
        let source_info = c.read_u32::<LittleEndian>().ok()?;
        let security_id = c.read_u32::<LittleEndian>().ok()?;
        let file_attrs = c.read_u32::<LittleEndian>().ok()?;
        let name_len = c.read_u16::<LittleEndian>().ok()? as usize;
        let name_offset = c.read_u16::<LittleEndian>().ok()? as usize;
        let file_mft_record_number = (file_ref & 0x0000_FFFF_FFFF_FFFF) as u64;
        let parent_mft_record_number = (parent_ref & 0x0000_FFFF_FFFF_FFFF) as u64;
        let name = read_utf16_name(buf, record_len as usize, name_offset, name_len)?;

        Some(Self {
            record_len,
            major_version: maj,
            minor_version: min,
            file_ref,
            parent_ref,
            file_mft_record_number,
            parent_mft_record_number,
            usn,
            timestamp,
            reason,
            source_info,
            security_id,
            file_attrs,
            name: Some(name),
            remaining_extents: None,
            extents: None,
            parent_path: None,
            full_path: None,
            reused_records: None,
        })
    }

    fn parse_v4(buf: &[u8], record_len: u32, maj: u16, min: u16) -> Option<Self> {
        // Layout per USN_RECORD_V4 (no file name; has range-tracking extents)
        // Header already read (4+2+2). Next:
        let mut c = Cursor::new(buf);
        c.set_position(8);
        let file_ref = read_u128(&mut c).ok()?;
        let parent_ref = read_u128(&mut c).ok()?;
        let usn = c.read_i64::<LittleEndian>().ok()?;
        let timestamp = 0u64; // v4 header doesn't carry FILETIME; it's implied to be paired w/ v3
        let reason = c.read_u32::<LittleEndian>().ok()?;
        let source_info = c.read_u32::<LittleEndian>().ok()?;
        let remaining_extents = c.read_u32::<LittleEndian>().ok()?;
        let number_of_extents = c.read_u16::<LittleEndian>().ok()? as usize;
        let extent_size = c.read_u16::<LittleEndian>().ok()? as usize;
        let file_mft_record_number = (file_ref & 0x0000_FFFF_FFFF_FFFF) as u64;
        let parent_mft_record_number = (parent_ref & 0x0000_FFFF_FFFF_FFFF) as u64;
        // Extents array follows; each extent struct is (Offset, Length) as i64
        let mut extents = Vec::with_capacity(number_of_extents);
        for _ in 0..number_of_extents {
            if (c.position() as usize) + extent_size > record_len as usize {
                return None;
            }
            let off = c.read_i64::<LittleEndian>().ok()?;
            let len = c.read_i64::<LittleEndian>().ok()?;
            if extent_size > 16 {
                // skip any future-added fields
                let skip = extent_size - 16;
                let mut tmp = vec![0u8; skip];
                c.read_exact(&mut tmp).ok()?;
            }
            extents.push(UsnExtent {
                offset: off,
                length: len,
            });
        }

        Some(Self {
            record_len,
            major_version: maj,
            minor_version: min,
            file_ref,
            parent_ref,
            file_mft_record_number,
            parent_mft_record_number,
            usn,
            // v4 doesn't embed a timestamp; many readers copy the following v3's
            // TimeStamp for user-facing output. We keep 0 here to avoid misattribution.
            timestamp,
            reason,
            source_info,
            // v4 doesn't include SecurityId/FileAttributes; zeroed for consistency
            security_id: 0,
            file_attrs: 0,
            name: None,
            remaining_extents: Some(remaining_extents),
            extents: Some(extents),
            parent_path: None,
            full_path: None,
            reused_records: None,
        })
    }

    fn filetime_to_rfc3339(ft: u64) -> String {
        if ft == 0 {
            return String::new();
        }
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

    pub fn to_string(&self) -> String {
        let mut t = Table::new();
        t.add_row(row![
            "USN Record Version",
            format!("{}.{}", self.major_version, self.minor_version)
        ]);
        t.add_row(row![b -> "USN", self.usn]);
        if self.timestamp != 0 {
            t.add_row(row![b -> "Timestamp", Self::filetime_to_rfc3339(self.timestamp)]);
        }
        t.add_row(row![b -> "Reason", format!("0x{:08X}", self.reason)]);
        {
            let decoded = super::usnjrn::decode_usn_reasons(self.reason).join(" | ");
            if !decoded.is_empty() {
                t.add_row(row![b -> "Reason (decoded)", decoded]);
            }
        }
        if self.file_attrs != 0 {
            t.add_row(row![b -> "File Attrs", format!("0x{:08X}", self.file_attrs)]);
        }
        t.add_row(row![b -> "File Ref", format!("{:#x}", self.file_ref)]);
        t.add_row(row![b -> "Parent Ref", format!("{:#x}", self.parent_ref)]);
        t.add_row(row![b -> "File MFT record #", self.file_mft_record_number]);
        t.add_row(row![b -> "Parent MFT record #", self.parent_mft_record_number]);
        if let Some(n) = &self.name {
            t.add_row(row![b -> "Name", n]);
        }
        if let Some(pp) = &self.parent_path {
            t.add_row(row![b -> "Parent Path", pp]);
        }
        if let Some(fp) = &self.full_path {
            t.add_row(row![b -> "Full Path", fp]);
        }
        if let Some(exts) = &self.extents {
            let mut s = String::new();
            for (i, e) in exts.iter().enumerate() {
                use std::fmt::Write;
                let _ = write!(&mut s, "#{i}: off={} len={}; ", e.offset, e.length);
            }
            t.add_row(row![b -> "Extents (v4)", s.trim_end()]);
            if let Some(rem) = self.remaining_extents {
                t.add_row(row![b -> "RemainingExtents", rem]);
            }
        }
        if let Some(rr) = &self.reused_records {
            if !rr.is_empty() {
                let mut subtbl = prettytable::Table::new();
                subtbl.add_row(row!["Index", "Current Seq", "Seen Seqs", "Reasons", "Name"]);
                for e in rr {
                    subtbl.add_row(row![
                        e.index,
                        e.current_seq.map_or("-".to_string(), |s| s.to_string()),
                        if e.seen_sequences.is_empty() {
                            "-".to_string()
                        } else {
                            e.seen_sequences
                                .iter()
                                .map(|s| s.to_string())
                                .collect::<Vec<_>>()
                                .join(",")
                        },
                        e.reason
                            .iter()
                            .map(|r| format!("{:?}", r))
                            .collect::<Vec<_>>()
                            .join(" | "),
                        e.name.clone().unwrap_or_else(|| "-".into())
                    ]);
                }
                // Add the sub-table as a single cell in the main table
                t.add_row(row![b -> "Reused records", subtbl.to_string()]);
            }
        }
        t.to_string()
    }

    pub fn to_json(&self) -> Value {
        json!({
            "version": { "major": self.major_version, "minor": self.minor_version },
            "usn": self.usn,
            "timestamp": Self::filetime_to_rfc3339(self.timestamp),
            "timestamp_raw": self.timestamp,
            "reason": self.reason,
            "reason_flags": decode_usn_reasons(self.reason),
            "source_info": self.source_info,
            "security_id": self.security_id,
            "file_attrs": self.file_attrs,
            "file_ref_u128": self.file_ref.to_string(),
            "parent_ref_u128": self.parent_ref.to_string(),
            "file_mft_record_number": self.file_mft_record_number,
            "parent_mft_record_number": self.parent_mft_record_number,
            "file_ref": self.file_ref_u64(),
            "parent_ref": self.parent_ref_u64(),
            "name": self.name,
            "extents": self.extents,
            "remaining_extents": self.remaining_extents,
            "parent_path": self.parent_path,
            "full_path": self.full_path,
        })
    }
}

fn read_u128(c: &mut Cursor<&[u8]>) -> std::io::Result<u128> {
    let mut b = [0u8; 16];
    c.read_exact(&mut b)?;
    Ok(u128::from_le_bytes(b))
}

fn read_utf16_name(
    buf: &[u8],
    record_len: usize,
    name_off: usize,
    name_len: usize,
) -> Option<String> {
    if name_len == 0 {
        return Some(String::new());
    }
    if name_off == 0
        || name_len % 2 != 0
        || name_off + name_len > record_len
        || name_off + name_len > buf.len()
    {
        return None;
    }
    let raw = &buf[name_off..name_off + name_len];
    String::from_utf16(
        &raw.chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect::<Vec<_>>(),
    )
    .ok()
}

/// Heuristic: is there a plausible USN record header at `pos`?
fn looks_like_usn_header(buf: &[u8], pos: usize) -> bool {
    if pos + 8 > buf.len() {
        return false;
    }
    let rl = u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]) as usize;
    if rl < 60 || rl > (1 << 20) || rl % 8 != 0 || pos + rl > buf.len() {
        return false;
    }
    let maj = u16::from_le_bytes([buf[pos + 4], buf[pos + 5]]);
    matches!(maj, 2 | 3 | 4)
}

/// Parse a full `$J` stream into `UsnRecord`s (robust to padding/sparse).
pub fn parse_usn_journal(stream: &[u8]) -> Vec<UsnRecord> {
    let mut out = Vec::new();
    let mut pos = 0usize;

    // Fast-skip leading zeros/padding if present
    while pos + 60 <= stream.len() && !looks_like_usn_header(stream, pos) {
        pos += 8; // USN records are 8-byte aligned
    }

    while pos + 60 <= stream.len() {
        if !looks_like_usn_header(stream, pos) {
            pos += 8;
            continue;
        }
        if let Some(rec) = UsnRecord::parse(&stream[pos..]) {
            let next = pos + rec.record_len as usize;
            out.push(rec);
            pos = next;
        } else {
            pos += 8;
        }
    }
    out
}

/// For each FRN index, collect all distinct sequences seen in this journal slice.
pub fn build_reuse_index(records: &[UsnRecord]) -> HashMap<u64, HashSet<u16>> {
    let mut map: HashMap<u64, HashSet<u16>> = HashMap::new();

    for r in records {
        map.entry(r.file_ref_u64())
            .or_default()
            .insert(r.file_ref_seq());
        map.entry(r.parent_ref_u64())
            .or_default()
            .insert(r.parent_ref_seq());
    }
    map
}
