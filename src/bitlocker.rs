use aes::{Aes128, Aes256};
use cipher::KeyInit;
use std::io::{BufReader, Error, ErrorKind, Read, Seek, SeekFrom};
use xts_mode::{get_tweak_default, Xts128};

pub enum BitLockerXts {
    Aes128(Xts128<Aes128>),
    Aes256(Xts128<Aes256>),
}

pub struct BitLockerStream<T: Read + Seek> {
    inner: BufReader<T>,
    xts: BitLockerXts,
    stream_pos: u64,
    sector_size: u64,
    encrypted_offset: u64,
}

impl<T: Read + Seek> BitLockerStream<T> {
    pub fn new(inner: T, fvek: &[u8], sector_size: u64) -> std::io::Result<Self> {
        let mut xts = if fvek.len() == 32 {
            let (key1, key2) = fvek.split_at(16);
            let cipher1 = Aes128::new_from_slice(key1).map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid FVEK slice length"))?;
            let cipher2 = Aes128::new_from_slice(key2).map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid FVEK slice length"))?;
            BitLockerXts::Aes128(Xts128::<Aes128>::new(cipher1, cipher2))
        } else if fvek.len() == 64 {
            let (key1, key2) = fvek.split_at(32);
            let cipher1 = Aes256::new_from_slice(key1).map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid FVEK slice length"))?;
            let cipher2 = Aes256::new_from_slice(key2).map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid FVEK slice length"))?;
            BitLockerXts::Aes256(Xts128::<Aes256>::new(cipher1, cipher2))
        } else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Unsupported FVEK length: {}. Expected 32 for AES-128-XTS or 64 for AES-256-XTS.", fvek.len()),
            ));
        };

        // Wrap the inner stream in a 1MB BufReader to dramatically reduce disk seek/read virtualization overhead.
        let mut inner_buffered = BufReader::with_capacity(1024 * 1024, inner);
        
        let mut scan_buf = vec![0u8; 1024 * 1024]; // 1MB batch read
        let max_scan_bytes = 250 * 1024 * 1024;
        let mut current_physical_offset: u64 = 0;
        let mut encrypted_offset = 0;
        
        while current_physical_offset < max_scan_bytes {
            inner_buffered.seek(SeekFrom::Start(current_physical_offset))?;
            
            let mut n = 0;
            while n < scan_buf.len() {
                let bytes_read = inner_buffered.read(&mut scan_buf[n..])?;
                if bytes_read == 0 { break; }
                n += bytes_read;
            }
            if n < sector_size as usize { break; }
            
            let valid_bytes = n - (n % sector_size as usize);
            let mut current_sec = current_physical_offset / sector_size;
            let mut found = false;
            
            for chunk in scan_buf[..valid_bytes].chunks_mut(sector_size as usize) {
                match &mut xts {
                    BitLockerXts::Aes128(x) => {
                        x.decrypt_area(chunk, sector_size as usize, current_sec as u128, get_tweak_default);
                    }
                    BitLockerXts::Aes256(x) => {
                        x.decrypt_area(chunk, sector_size as usize, current_sec as u128, get_tweak_default);
                    }
                }
                if chunk.len() >= 11 && &chunk[3..11] == b"NTFS    " {
                    encrypted_offset = current_sec * sector_size;
                    found = true;
                    break;
                }
                current_sec += 1;
            }
            if found {
                break;
            }
            current_physical_offset += valid_bytes as u64;
        }

        inner_buffered.seek(SeekFrom::Start(encrypted_offset))?;
        
        Ok(Self {
            inner: inner_buffered,
            xts,
            stream_pos: 0,
            sector_size,
            encrypted_offset,
        })
    }
}

impl<T: Read + Seek> Read for BitLockerStream<T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let start_pos = self.stream_pos;

        // Force alignment to encryption sector size for simplification
        // MFT queries are naturally aligned to cluster size (e.g. 4096), which is divisible by sector size (512).
        if start_pos % self.sector_size != 0 {
            return Err(Error::new(ErrorKind::InvalidInput, "Unaligned Bitlocker stream read is not supported"));
        }

        let bytes_to_read = buf.len() - (buf.len() % self.sector_size as usize); 
        if bytes_to_read == 0 {
            return Err(Error::new(ErrorKind::InvalidInput, "Buffer smaller than one sector size"));
        }

        // Calculate physical read position
        let physical_start = if start_pos < self.encrypted_offset {
            self.encrypted_offset + start_pos
        } else {
            start_pos
        };
        
        // Seek to the true physical location before reading
        self.inner.seek(SeekFrom::Start(physical_start))?;
        
        let n = self.inner.read(&mut buf[..bytes_to_read])?;
        if n == 0 { return Ok(0); }

        let n_sectors = n / self.sector_size as usize;
        let valid_bytes = n_sectors * self.sector_size as usize;

        if valid_bytes > 0 {
             let data = &mut buf[..valid_bytes];
             
             // The AES tweak is always the absolute physical sector of the partition
             let mut current_global_sec = physical_start / self.sector_size;
             
             for chunk in data.chunks_mut(self.sector_size as usize) {
                 match &mut self.xts {
                     BitLockerXts::Aes128(xts) => {
                         xts.decrypt_area(chunk, self.sector_size as usize, current_global_sec as u128, get_tweak_default);
                     }
                     BitLockerXts::Aes256(xts) => {
                         xts.decrypt_area(chunk, self.sector_size as usize, current_global_sec as u128, get_tweak_default);
                     }
                 }
                 current_global_sec += 1;
             }

             self.stream_pos += valid_bytes as u64;
             
             // In BitLockerStream, we don't attempt to leave the inner stream pointer precisely at inner's Current if we read a partial tail sector.
             // Because we explicitly seek before every read based on `stream_pos`.
             
             return Ok(valid_bytes);
        } else {
             return Err(Error::new(ErrorKind::UnexpectedEof, "Failed to read a full BitLocker sector"));
        }
    }
}

impl<T: Read + Seek> Seek for BitLockerStream<T> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(off) => off,
            SeekFrom::Current(off) => {
                let current = self.stream_pos as i64;
                if current + off < 0 {
                     return Err(Error::new(ErrorKind::InvalidInput, "Seek before start of stream"));
                }
                (current + off) as u64
            }
            SeekFrom::End(_) => return Err(Error::new(ErrorKind::Unsupported, "SeekFrom::End not supported in BitLockerStream")),
        };
        self.stream_pos = new_pos;
        
        // We defer the physical seek to read() to avoid side effects if read() isn't called.
        // But for completeness, we can seek inner here as well.
        let physical_pos = if new_pos < self.encrypted_offset {
            self.encrypted_offset + new_pos
        } else {
            new_pos
        };
        self.inner.seek(SeekFrom::Start(physical_pos))?;
        
        Ok(new_pos)
    }
}
