use std::error::Error;
use std::io::{Read, Seek, SeekFrom};

use pbs::PartitionBootSector;

// Sources:
// - https://dubeyko.com/development/FileSystems/NTFS/ntfsdoc.pdf
// - https://en.wikipedia.org/wiki/NTFS
pub mod pbs;

pub struct NTFS<T: Read + Seek> {
    pub pbs: PartitionBootSector,
    pub body: T,
}

impl<T: Read + Seek> NTFS<T> {
    pub fn new(mut body: T) -> Result<Self, String> {
        // Read the partition boot sector of size 512bytes
        let mut sp_data = vec![0u8; 0x400];
        body.read_exact(&mut sp_data).map_err(|e| e.to_string())?;

        let pbs = match PartitionBootSector::from_bytes(&sp_data) {
            Ok(pbs) => pbs,
            Err(message) => {
                eprintln!("{:?}", message);
                return Err(message.to_string());
            }
        };
        if pbs.oem_id_is_valid() {
            Ok(NTFS { pbs, body })
        } else {
            Err("The OEM Identifier is not valid".to_string())
        }
    }
}
