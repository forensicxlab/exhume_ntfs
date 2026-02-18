// Sources:
// - https://en.wikipedia.org/wiki/NTFS

//! Parse an NTFS Partition-Boot-Sector with std::io::Cursor
//! Cargo.toml →  byteorder = "1.5"

use byteorder::{LittleEndian, ReadBytesExt};
use capstone::prelude::*;
use prettytable::{Table, row};
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
    pub media_descriptor: u8,    // 0x15
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
    pub clusters_per_file_record: i8, // 0x40
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
    pub const BITLOCKER_OEM_ID: [u8; 8] = *b"-FVE-FS-";

    /// Parse the 512-byte sector into `PartitionBootSector`
    pub fn from_bytes(buf: &[u8]) -> io::Result<Self> {
        if buf.len() < 512 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Boot sector must be exactly 512 bytes",
            ));
        }
        let mut c = Cursor::new(buf);

        /* classical helper macros */
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

    /// Check if the partition is BitLocker-encrypted.
    ///
    /// BitLocker replaces the NTFS OEM identifier with `-FVE-FS-` in the
    /// volume boot sector.
    pub fn is_bitlocker(&self) -> bool {
        self.oem_id == Self::BITLOCKER_OEM_ID
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

    /// Get the size of one cluster
    pub fn cluster_size(&self) -> u32 {
        self.sectors_per_cluster as u32 * self.bytes_per_sector as u32
    }

    /// Get the logical byte address of the MFT
    pub fn mft_address(&self) -> u64 {
        self.mft_cluster * self.cluster_size() as u64
    }

    /// Get the logical byte address of the MFT mirror
    pub fn mft_backup(&self) -> u64 {
        self.mft_mirror_cluster * self.cluster_size() as u64
    }

    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({}))
    }

    pub fn to_string(&self) -> String {
        let mut table = Table::new();

        table.add_row(row!["Field", "Value"]);
        table.add_row(row![
            "OEM ID",
            String::from_utf8_lossy(&self.oem_id).trim().to_string()
        ]);
        table.add_row(row!["Bytes per sector", self.bytes_per_sector.to_string()]);
        table.add_row(row![
            "Sectors per cluster",
            self.sectors_per_cluster.to_string()
        ]);
        table.add_row(row!["Reserved sectors", self.reserved_sectors.to_string()]);
        table.add_row(row![
            "Media descriptor",
            format!("{:02X}", self.media_descriptor)
        ]);
        table.add_row(row![
            "Sectors per track",
            self.sectors_per_track.to_string()
        ]);
        table.add_row(row!["Number of heads", self.number_of_heads.to_string()]);
        table.add_row(row!["Hidden sectors", self.hidden_sectors.to_string()]);
        table.add_row(row!["Total sectors", self.total_sectors.to_string()]);
        table.add_row(row!["MFT cluster", self.mft_cluster.to_string()]);
        table.add_row(row![
            "MFT mirror cluster",
            self.mft_mirror_cluster.to_string()
        ]);
        table.add_row(row![
            "File record size (bytes)",
            self.file_record_size().to_string()
        ]);
        table.add_row(row![
            "Cluster size (bytes)",
            self.cluster_size().to_string()
        ]);
        table.add_row(row!["MFT address", format!("0x{:X}", self.mft_address())]);
        table.add_row(row!["MFT backup", format!("0x{:X}", self.mft_backup())]);
        table.add_row(row![
            "Volume serial number",
            format!("0x{:X}", self.volume_serial_number)
        ]);
        table.add_row(row![
            "End of sector marker",
            format!("{:04X}", self.end_of_sector_marker)
        ]);
        table.to_string()
    }

    pub fn disassemble_bootstrap_code(&self) -> String {
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode16)
            .build()
            .unwrap();

        let insns = cs.disasm_all(&self.bootstrap_code, 0x7C00).unwrap();

        let mut result = String::new();
        for i in insns.iter() {
            result.push_str(&format!(
                "0x{:04X}:\t{}\t{}\n",
                i.address(),
                i.mnemonic().unwrap_or(""),
                i.op_str().unwrap_or("")
            ));
        }
        result
    }
}
