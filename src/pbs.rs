// Sources:
// - https://en.wikipedia.org/wiki/NTFS

//! Parse an NTFS Partition-Boot-Sector with std::io::Cursor
//! Cargo.toml →  byteorder = "1.5"

use byteorder::{LittleEndian, ReadBytesExt};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::{self, Cursor, Read};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PartitionBootSector {
    /* -- 0x00-0x0A ------------------------------------------ */
    pub jump_instruction: Vec<u8>, // x86 JMP + NOP
    pub oem_id: [u8; 8],           // "NTFS    "

    /* -- BIOS Parameter Block (BPB) – 0x0B-0x23 ------------- */
    pub bytes_per_sector: u16,   // 0x0B
    pub sectors_per_cluster: u8, // 0x0D
    pub reserved_sectors: u16,   // 0x0E
    pub unused1: [u8; 3],        // 0x10
    pub unused2: u16,            // 0x13
    pub media_descriptor: u8,    // 0x15 (0xF8 = hard disk)
    pub unused3: u16,            // 0x16
    pub sectors_per_track: u16,  // 0x18
    pub number_of_heads: u16,    // 0x1A
    pub hidden_sectors: u32,     // 0x1C
    pub unused4: u32,            // 0x20
    pub unused5: u32,            // 0x24

    /* -- Extended BPB – 0x28-0x53 ---------------------------- */
    pub total_sectors: u64,           // 0x28
    pub mft_cluster: u64,             // 0x30
    pub mft_mirror_cluster: u64,      // 0x38
    pub clusters_per_file_record: i8, // 0x40  (may be negative)
    pub unused6: [u8; 3],
    pub clusters_per_index_buffer: i8, // 0x44
    pub unused7: [u8; 3],
    pub volume_serial_number: u64, // 0x48
    pub checksum: u32,             // 0x50

    /* -- Bootstrap code & signature – 0x54-0x1FF ------------ */
    pub bootstrap_code: Vec<u8>,   // 0x54-0x1FD
    pub end_of_sector_marker: u16, // 0x1FE (0xAA55)
}

impl PartitionBootSector {
    pub const NTFS_OEM_ID: [u8; 8] = *b"NTFS    ";

    /// Parse the 512-byte sector into `PartitionBootSector`
    pub fn from_bytes(buf: &[u8]) -> io::Result<Self> {
        if buf.len() < 512 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Boot sector must be exactly 512 bytes",
            ));
        }
        let mut c = Cursor::new(buf);

        /* helper macros to reduce boilerplate */
        macro_rules! read_array {
            ($len:expr) => {{
                let mut tmp = [0u8; $len];
                c.read_exact(&mut tmp)?;
                tmp
            }};
        }
        macro_rules! read_u8 {
            () => {
                c.read_u8()?
            };
        }
        macro_rules! read_u16 {
            () => {
                c.read_u16::<LittleEndian>()?
            };
        }
        macro_rules! read_u32 {
            () => {
                c.read_u32::<LittleEndian>()?
            };
        }
        macro_rules! read_u64 {
            () => {
                c.read_u64::<LittleEndian>()?
            };
        }
        macro_rules! read_i8 {
            () => {
                c.read_i8()?
            };
        }

        Ok(Self {
            jump_instruction: read_array!(3).to_vec(),
            oem_id: read_array!(8),
            bytes_per_sector: read_u16!(),
            sectors_per_cluster: read_u8!(),
            reserved_sectors: read_u16!(),
            unused1: read_array!(3),
            unused2: read_u16!(),
            media_descriptor: read_u8!(),
            unused3: read_u16!(),
            sectors_per_track: read_u16!(),
            number_of_heads: read_u16!(),
            hidden_sectors: read_u32!(),
            unused4: read_u32!(),
            unused5: read_u32!(),
            total_sectors: read_u64!(),
            mft_cluster: read_u64!(),
            mft_mirror_cluster: read_u64!(),
            clusters_per_file_record: read_i8!(),
            unused6: read_array!(3),
            clusters_per_index_buffer: read_i8!(),
            unused7: read_array!(3),
            volume_serial_number: read_u64!(),
            checksum: read_u32!(),
            bootstrap_code: read_array!(426).to_vec(),
            end_of_sector_marker: read_u16!(),
        })
    }
    /// Check if the oem_id is valid
    pub fn oem_id_is_valid(&self) -> bool {
        self.oem_id == Self::NTFS_OEM_ID
    }

    /// Compute actual bytes per file-record segment
    pub fn file_record_size(&self) -> u32 {
        if self.clusters_per_file_record > 0 {
            self.clusters_per_file_record as u32
                * self.sectors_per_cluster as u32
                * self.bytes_per_sector as u32
        } else {
            1u32 << (-self.clusters_per_file_record as u32)
        }
    }

    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({}))
    }

    pub fn to_string(&self) -> String {
        "to_do".to_string()
    }
}
