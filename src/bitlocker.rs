//! Metadata-driven, read-only BitLocker volume transformation.
//!
//! The supported subset is deliberately narrow: Windows 7-or-later AES-XTS
//! volumes with a relocated volume-header block. Layout is read from the boot
//! sector and redundant FVE metadata rather than found by scanning ciphertext.
//! Unsupported or ambiguous conversion states fail closed.
//!
//! Virtual-sector handling follows the libbde format documentation: the
//! relocated volume header is mapped only over its declared logical range,
//! while the physical relocated-header and three 64 KiB Windows 7 FVE metadata
//! reservation ranges appear as zeroes in the decrypted view.

use aes::{Aes128, Aes256};
use cipher::{BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit};
use exhume_body::VolumeReader;
use rayon::prelude::*;
use std::fmt;
use std::io::{BufReader, Error, ErrorKind, Read, Seek, SeekFrom};
use xts_mode::{Xts128, get_tweak_default};

const BITLOCKER_SIGNATURE: &[u8; 8] = b"-FVE-FS-";
const NTFS_SIGNATURE: &[u8; 8] = b"NTFS    ";
const WINDOWS_7_BOOT_ENTRY_POINT: [u8; 3] = [0xeb, 0x58, 0x90];

// 4967d63b-2e29-4ad8-8399-f6a339e3d001 in on-disk GUID byte order.
const BITLOCKER_IDENTIFIER: [u8; 16] = [
    0x3b, 0xd6, 0x67, 0x49, 0x29, 0x2e, 0xd8, 0x4a, 0x83, 0x99, 0xf6, 0xa3, 0x39, 0xe3, 0xd0, 0x01,
];

// 92a84d3b-dd80-4d0e-9e4e-b1e3284eaed8 (used-space-only encryption).
// This transform cannot determine which otherwise ordinary sectors were
// encrypted, so accepting it would produce silent corruption.
const USED_SPACE_ONLY_IDENTIFIER: [u8; 16] = [
    0x3b, 0x4d, 0xa8, 0x92, 0x80, 0xdd, 0x0e, 0x4d, 0x9e, 0x4e, 0xb1, 0xe3, 0x28, 0x4e, 0xae, 0xd8,
];

const FVE_BLOCK_HEADER_SIZE: u64 = 64;
const FVE_METADATA_HEADER_SIZE: usize = 48;

// Windows 7 FVE2.{GUID}.[123] reservations are 64 KiB and libbde deliberately
// virtualizes that complete range, not merely the variable metadata payload.
// We expose this size in BitLockerLayout rather than hiding the assumption.
const WINDOWS_7_METADATA_REGION_SIZE: u64 = 65_536;
const MAX_FVE_METADATA_PAYLOAD_SIZE: usize =
    WINDOWS_7_METADATA_REGION_SIZE as usize - FVE_BLOCK_HEADER_SIZE as usize;

const FVE_BLOCK_VERSION_WINDOWS_7: u16 = 2;
const FVE_METADATA_VERSION: u32 = 1;
const FVE_ENTRY_TYPE_VOLUME_HEADER_BLOCK: u16 = 0x000f;
const FVE_VALUE_TYPE_OFFSET_AND_SIZE: u16 = 0x000f;
const FULLY_ENCRYPTED_STATE: u16 = 0x0004;

// Small and partial-sector reads remain serial: scheduling work costs more
// than it saves there. Export reads are normally 16 MiB, so split those into a
// bounded number of sector-aligned jobs without monopolizing every host core.
const PARALLEL_XTS_MIN_BYTES: usize = 4 * 1024 * 1024;
const PARALLEL_XTS_MAX_JOBS: usize = 8;

/// Sector-data encryption method recorded in the FVE metadata header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BitLockerEncryptionMethod {
    AesXts128 = 0x8004,
    AesXts256 = 0x8005,
}

impl BitLockerEncryptionMethod {
    fn from_raw(value: u32) -> std::io::Result<Self> {
        match value {
            0x8004 => Ok(Self::AesXts128),
            0x8005 => Ok(Self::AesXts256),
            _ => Err(invalid_data(format!(
                "unsupported BitLocker encryption method 0x{value:08x}; only AES-XTS-128 (0x8004) and AES-XTS-256 (0x8005) are supported"
            ))),
        }
    }

    pub fn fvek_len(self) -> usize {
        match self {
            Self::AesXts128 => 32,
            Self::AesXts256 => 64,
        }
    }
}

/// How the raw encrypted-volume boundary was interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptedBoundaryInterpretation {
    /// A zero field means no partial-decryption boundary is active.
    NotPresent,
    /// The metadata field was already relative to the partition start.
    PartitionRelative,
    /// The metadata field was an absolute-disk byte position; the partition
    /// offset supplied by the caller was subtracted.
    AbsoluteDisk,
}

/// Geometry needed to interpret volume-relative and absolute-disk fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitLockerVolumeOptions {
    volume_len: u64,
    expected_sector_size: u64,
    partition_offset_bytes: u64,
}

impl BitLockerVolumeOptions {
    pub fn new(volume_len: u64, expected_sector_size: u64) -> Self {
        Self {
            volume_len,
            expected_sector_size,
            partition_offset_bytes: 0,
        }
    }

    pub fn with_partition_offset_bytes(mut self, partition_offset_bytes: u64) -> Self {
        self.partition_offset_bytes = partition_offset_bytes;
        self
    }

    pub fn volume_len(self) -> u64 {
        self.volume_len
    }

    pub fn expected_sector_size(self) -> u64 {
        self.expected_sector_size
    }

    pub fn partition_offset_bytes(self) -> u64 {
        self.partition_offset_bytes
    }
}

/// A byte range relative to the start of the BitLocker partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitLockerRange {
    offset: u64,
    length: u64,
}

impl BitLockerRange {
    pub fn offset(self) -> u64 {
        self.offset
    }

    pub fn length(self) -> u64 {
        self.length
    }

    pub fn end(self) -> u64 {
        self.offset + self.length
    }

    fn contains(self, offset: u64) -> bool {
        offset >= self.offset && offset < self.end()
    }
}

/// Parsed and validated block geometry for a supported BitLocker volume.
///
/// This type intentionally contains no key material. Its `Debug` output is
/// safe for logs and derivative manifests.
#[derive(Clone, PartialEq, Eq)]
pub struct BitLockerLayout {
    volume_len: u64,
    partition_offset_bytes: u64,
    sector_size: u64,
    block_header_version: u16,
    raw_encrypted_volume_size: u64,
    encrypted_boundary: u64,
    encrypted_boundary_interpretation: EncryptedBoundaryInterpretation,
    metadata_offsets: [u64; 3],
    metadata_region_size: u64,
    metadata_payload_size: u32,
    selected_metadata_copy: usize,
    relocated_header: BitLockerRange,
    encryption_method: BitLockerEncryptionMethod,
    layout_identifier: [u8; 16],
    volume_identifier: [u8; 16],
}

impl fmt::Debug for BitLockerLayout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BitLockerLayout")
            .field("volume_len", &self.volume_len)
            .field("partition_offset_bytes", &self.partition_offset_bytes)
            .field("sector_size", &self.sector_size)
            .field("block_header_version", &self.block_header_version)
            .field("raw_encrypted_volume_size", &self.raw_encrypted_volume_size)
            .field("encrypted_boundary", &self.encrypted_boundary)
            .field(
                "encrypted_boundary_interpretation",
                &self.encrypted_boundary_interpretation,
            )
            .field("metadata_offsets", &self.metadata_offsets)
            .field("metadata_region_size", &self.metadata_region_size)
            .field("metadata_payload_size", &self.metadata_payload_size)
            .field("selected_metadata_copy", &self.selected_metadata_copy)
            .field("relocated_header", &self.relocated_header)
            .field("encryption_method", &self.encryption_method)
            .field("layout_identifier", &self.layout_identifier)
            .field("volume_identifier", &self.volume_identifier)
            .finish()
    }
}

impl BitLockerLayout {
    /// Discover geometry without using a key.
    pub fn discover<T: Read + Seek>(
        inner: &mut T,
        options: BitLockerVolumeOptions,
    ) -> std::io::Result<Self> {
        let volume_len = options.volume_len;
        if volume_len < 512 {
            return Err(invalid_input(
                "BitLocker volume is smaller than one boot sector",
            ));
        }

        let mut boot = [0u8; 512];
        read_exact_at(inner, 0, &mut boot)?;
        if boot[..3] != WINDOWS_7_BOOT_ENTRY_POINT {
            return Err(invalid_data(
                "unsupported BitLocker volume header; only Windows 7-or-later headers with relocated volume-header metadata are supported",
            ));
        }
        if &boot[3..11] != BITLOCKER_SIGNATURE {
            return Err(invalid_data("missing BitLocker -FVE-FS- signature"));
        }

        let mut layout_identifier = [0u8; 16];
        layout_identifier.copy_from_slice(&boot[160..176]);
        if layout_identifier == USED_SPACE_ONLY_IDENTIFIER {
            return Err(invalid_data(
                "BitLocker used-space-only encryption is not supported safely by this volume transform",
            ));
        }
        if layout_identifier != BITLOCKER_IDENTIFIER {
            return Err(invalid_data(
                "unsupported BitLocker volume identifier (BitLocker To Go and unknown layouts are not accepted)",
            ));
        }

        let sector_size = le_u16(&boot, 11)? as u64;
        if !matches!(sector_size, 512 | 1024 | 2048 | 4096) {
            return Err(invalid_data(format!(
                "invalid BitLocker sector size {sector_size}"
            )));
        }
        if options.expected_sector_size != 0 && options.expected_sector_size != sector_size {
            return Err(invalid_data(format!(
                "BitLocker sector size {sector_size} does not match expected sector size {}",
                options.expected_sector_size
            )));
        }
        if volume_len % sector_size != 0 {
            return Err(invalid_input(format!(
                "BitLocker volume length {volume_len} is not a multiple of sector size {sector_size}"
            )));
        }

        let metadata_offsets = [
            le_u64(&boot, 176)?,
            le_u64(&boot, 184)?,
            le_u64(&boot, 192)?,
        ];
        validate_metadata_ranges(metadata_offsets, volume_len, sector_size)?;

        let mut valid = Vec::new();
        let mut corrupt_reasons = Vec::new();
        for (index, offset) in metadata_offsets.iter().copied().enumerate() {
            match parse_metadata_copy(inner, offset, metadata_offsets, volume_len, sector_size) {
                Ok(copy) => valid.push((index, copy)),
                Err(CopyFailure::Corrupt(reason)) => {
                    corrupt_reasons.push(format!("copy {}: {reason}", index + 1));
                }
                Err(CopyFailure::Unsafe(reason)) => return Err(invalid_data(reason)),
            }
        }
        let Some((selected_metadata_copy, selected)) = valid.first().cloned() else {
            return Err(invalid_data(format!(
                "no structurally valid BitLocker metadata copy ({})",
                corrupt_reasons.join("; ")
            )));
        };
        for (_, candidate) in valid.iter().skip(1) {
            if candidate.safety_geometry() != selected.safety_geometry() {
                return Err(invalid_data(
                    "BitLocker metadata copies disagree on security-critical volume geometry",
                ));
            }
        }

        let relocated_header = BitLockerRange {
            offset: selected.volume_header_offset,
            length: selected.volume_header_size,
        };
        validate_range(
            relocated_header,
            volume_len,
            sector_size,
            "relocated volume header",
        )?;
        if relocated_header.offset == 0 || relocated_header.length == 0 {
            return Err(invalid_data(
                "BitLocker metadata has no reconstructable relocated volume header",
            ));
        }
        if metadata_offsets.iter().any(|offset| {
            ranges_overlap(
                relocated_header,
                BitLockerRange {
                    offset: *offset,
                    length: WINDOWS_7_METADATA_REGION_SIZE,
                },
            )
        }) {
            return Err(invalid_data(
                "BitLocker relocated volume header overlaps an FVE metadata reservation",
            ));
        }
        let logical_header = BitLockerRange {
            offset: 0,
            length: relocated_header.length,
        };
        if ranges_overlap(relocated_header, logical_header)
            || metadata_offsets.iter().any(|offset| {
                ranges_overlap(
                    logical_header,
                    BitLockerRange {
                        offset: *offset,
                        length: WINDOWS_7_METADATA_REGION_SIZE,
                    },
                )
            })
        {
            return Err(invalid_data(
                "BitLocker virtual-sector ranges conflict with the logical volume-header range",
            ));
        }

        let (encrypted_boundary, encrypted_boundary_interpretation) = interpret_encrypted_boundary(
            selected.raw_encrypted_volume_size,
            volume_len,
            options.partition_offset_bytes,
            sector_size,
        )?;

        Ok(Self {
            volume_len,
            partition_offset_bytes: options.partition_offset_bytes,
            sector_size,
            block_header_version: selected.block_header_version,
            raw_encrypted_volume_size: selected.raw_encrypted_volume_size,
            encrypted_boundary,
            encrypted_boundary_interpretation,
            metadata_offsets,
            metadata_region_size: WINDOWS_7_METADATA_REGION_SIZE,
            metadata_payload_size: selected.metadata_payload_size,
            selected_metadata_copy,
            relocated_header,
            encryption_method: selected.encryption_method,
            layout_identifier,
            volume_identifier: selected.volume_identifier,
        })
    }

    pub fn volume_len(&self) -> u64 {
        self.volume_len
    }
    pub fn partition_offset_bytes(&self) -> u64 {
        self.partition_offset_bytes
    }
    pub fn sector_size(&self) -> u64 {
        self.sector_size
    }
    pub fn block_header_version(&self) -> u16 {
        self.block_header_version
    }
    pub fn raw_encrypted_volume_size(&self) -> u64 {
        self.raw_encrypted_volume_size
    }
    pub fn encrypted_boundary(&self) -> u64 {
        self.encrypted_boundary
    }
    pub fn encrypted_boundary_interpretation(&self) -> EncryptedBoundaryInterpretation {
        self.encrypted_boundary_interpretation
    }
    pub fn metadata_offsets(&self) -> [u64; 3] {
        self.metadata_offsets
    }
    pub fn metadata_region_size(&self) -> u64 {
        self.metadata_region_size
    }
    pub fn metadata_payload_size(&self) -> u32 {
        self.metadata_payload_size
    }
    pub fn selected_metadata_copy(&self) -> usize {
        self.selected_metadata_copy
    }
    pub fn relocated_header(&self) -> BitLockerRange {
        self.relocated_header
    }
    pub fn encryption_method(&self) -> BitLockerEncryptionMethod {
        self.encryption_method
    }
    /// The constant BitLocker layout identifier from the boot header.
    pub fn layout_identifier(&self) -> [u8; 16] {
        self.layout_identifier
    }
    /// The evidence-specific volume GUID from the FVE metadata header.
    pub fn volume_identifier(&self) -> [u8; 16] {
        self.volume_identifier
    }

    fn zero_ranges(&self) -> impl Iterator<Item = BitLockerRange> + '_ {
        self.metadata_offsets
            .iter()
            .copied()
            .map(|offset| BitLockerRange {
                offset,
                length: self.metadata_region_size,
            })
            .chain(std::iter::once(self.relocated_header))
    }
}

#[derive(Clone)]
struct ParsedMetadataCopy {
    block_header_version: u16,
    raw_encrypted_volume_size: u64,
    volume_header_offset: u64,
    volume_header_size: u64,
    metadata_payload_size: u32,
    encryption_method: BitLockerEncryptionMethod,
    volume_identifier: [u8; 16],
}

impl ParsedMetadataCopy {
    fn safety_geometry(&self) -> (u16, u64, u64, u64, u32, BitLockerEncryptionMethod, [u8; 16]) {
        (
            self.block_header_version,
            self.raw_encrypted_volume_size,
            self.volume_header_offset,
            self.volume_header_size,
            self.metadata_payload_size,
            self.encryption_method,
            self.volume_identifier,
        )
    }
}

enum CopyFailure {
    Corrupt(String),
    Unsafe(String),
}

fn parse_metadata_copy<T: Read + Seek>(
    inner: &mut T,
    offset: u64,
    boot_metadata_offsets: [u64; 3],
    volume_len: u64,
    sector_size: u64,
) -> Result<ParsedMetadataCopy, CopyFailure> {
    let mut prefix = [0u8; 64 + FVE_METADATA_HEADER_SIZE];
    read_exact_at(inner, offset, &mut prefix)
        .map_err(|e| CopyFailure::Corrupt(format!("cannot read metadata header: {e}")))?;

    if &prefix[..8] != BITLOCKER_SIGNATURE {
        return Err(CopyFailure::Corrupt("missing -FVE-FS- signature".into()));
    }
    let version = le_u16(&prefix, 10)
        .map_err(|e| CopyFailure::Corrupt(format!("invalid block version: {e}")))?;
    if version != FVE_BLOCK_VERSION_WINDOWS_7 {
        return Err(CopyFailure::Unsafe(format!(
            "unsupported BitLocker metadata block version {version}; Windows Vista reconstruction is not implemented"
        )));
    }

    let state = le_u16(&prefix, 12)
        .map_err(|e| CopyFailure::Corrupt(format!("invalid state field: {e}")))?;
    let state_copy = le_u16(&prefix, 14)
        .map_err(|e| CopyFailure::Corrupt(format!("invalid state-copy field: {e}")))?;
    if state != FULLY_ENCRYPTED_STATE || state_copy != FULLY_ENCRYPTED_STATE {
        return Err(CopyFailure::Unsafe(format!(
            "ambiguous BitLocker conversion/protection state 0x{state:04x}/0x{state_copy:04x}; only 0x0004/0x0004 is supported"
        )));
    }

    let raw_encrypted_volume_size = le_u64(&prefix, 16)
        .map_err(|e| CopyFailure::Corrupt(format!("invalid encrypted-volume size: {e}")))?;
    let volume_header_sectors = le_u32(&prefix, 28)
        .map_err(|e| CopyFailure::Corrupt(format!("invalid volume-header sectors: {e}")))?
        as u64;
    let copy_metadata_offsets = [
        le_u64(&prefix, 32).map_err(|e| CopyFailure::Corrupt(e.to_string()))?,
        le_u64(&prefix, 40).map_err(|e| CopyFailure::Corrupt(e.to_string()))?,
        le_u64(&prefix, 48).map_err(|e| CopyFailure::Corrupt(e.to_string()))?,
    ];
    if copy_metadata_offsets != boot_metadata_offsets {
        return Err(CopyFailure::Corrupt(
            "metadata copy offsets disagree with the BitLocker boot sector".into(),
        ));
    }

    let volume_header_offset = le_u64(&prefix, 56)
        .map_err(|e| CopyFailure::Corrupt(format!("invalid volume-header offset: {e}")))?;
    let volume_header_size = volume_header_sectors
        .checked_mul(sector_size)
        .ok_or_else(|| CopyFailure::Corrupt("volume-header size overflow".into()))?;
    if volume_header_size == 0 {
        return Err(CopyFailure::Unsafe(
            "BitLocker metadata declares no reconstructable volume-header sectors".into(),
        ));
    }
    let header_range = BitLockerRange {
        offset: volume_header_offset,
        length: volume_header_size,
    };
    validate_range(
        header_range,
        volume_len,
        sector_size,
        "relocated volume header",
    )
    .map_err(|e| CopyFailure::Corrupt(e.to_string()))?;

    let metadata_base = FVE_BLOCK_HEADER_SIZE as usize;
    let metadata_payload_size = le_u32(&prefix, metadata_base)
        .map_err(|e| CopyFailure::Corrupt(format!("invalid metadata size: {e}")))?;
    let metadata_version = le_u32(&prefix, metadata_base + 4)
        .map_err(|e| CopyFailure::Corrupt(format!("invalid metadata version: {e}")))?;
    let metadata_header_size = le_u32(&prefix, metadata_base + 8)
        .map_err(|e| CopyFailure::Corrupt(format!("invalid metadata header size: {e}")))?;
    let metadata_size_copy = le_u32(&prefix, metadata_base + 12)
        .map_err(|e| CopyFailure::Corrupt(format!("invalid metadata size copy: {e}")))?;
    if metadata_version != FVE_METADATA_VERSION {
        return Err(CopyFailure::Corrupt(format!(
            "unsupported FVE metadata version {metadata_version}"
        )));
    }
    if metadata_header_size as usize != FVE_METADATA_HEADER_SIZE {
        return Err(CopyFailure::Corrupt(format!(
            "unexpected FVE metadata header size {metadata_header_size}"
        )));
    }
    if metadata_payload_size != metadata_size_copy {
        return Err(CopyFailure::Corrupt(
            "FVE metadata size and size-copy disagree".into(),
        ));
    }
    let payload_len = metadata_payload_size as usize;
    if !(FVE_METADATA_HEADER_SIZE..=MAX_FVE_METADATA_PAYLOAD_SIZE).contains(&payload_len) {
        return Err(CopyFailure::Corrupt(format!(
            "FVE metadata payload size {metadata_payload_size} is out of bounds"
        )));
    }

    let raw_method = le_u32(&prefix, metadata_base + 36)
        .map_err(|e| CopyFailure::Corrupt(format!("invalid encryption method: {e}")))?;
    let encryption_method = BitLockerEncryptionMethod::from_raw(raw_method)
        .map_err(|e| CopyFailure::Unsafe(e.to_string()))?;
    let mut volume_identifier = [0u8; 16];
    volume_identifier.copy_from_slice(&prefix[metadata_base + 16..metadata_base + 32]);

    let mut metadata = vec![0u8; payload_len];
    read_exact_at(inner, offset + FVE_BLOCK_HEADER_SIZE, &mut metadata)
        .map_err(|e| CopyFailure::Corrupt(format!("cannot read metadata payload: {e}")))?;

    let mut entry_offset = FVE_METADATA_HEADER_SIZE;
    let mut declared_header_range = None;
    while entry_offset + 8 <= metadata.len() {
        let entry_header = &metadata[entry_offset..entry_offset + 8];
        if entry_header.iter().all(|byte| *byte == 0) {
            break;
        }
        let entry_size = le_u16(&metadata, entry_offset)
            .map_err(|e| CopyFailure::Corrupt(format!("invalid metadata entry size: {e}")))?
            as usize;
        if entry_size < 8 || entry_offset + entry_size > metadata.len() {
            return Err(CopyFailure::Corrupt(format!(
                "FVE metadata entry at relative offset {entry_offset} is out of bounds"
            )));
        }
        let entry_type =
            le_u16(&metadata, entry_offset + 2).map_err(|e| CopyFailure::Corrupt(e.to_string()))?;
        let value_type =
            le_u16(&metadata, entry_offset + 4).map_err(|e| CopyFailure::Corrupt(e.to_string()))?;
        if entry_type == FVE_ENTRY_TYPE_VOLUME_HEADER_BLOCK
            && value_type == FVE_VALUE_TYPE_OFFSET_AND_SIZE
        {
            if entry_size < 24 {
                return Err(CopyFailure::Corrupt(
                    "FVE volume-header entry is shorter than its offset/size tuple".into(),
                ));
            }
            let entry_range = BitLockerRange {
                offset: le_u64(&metadata, entry_offset + 8)
                    .map_err(|e| CopyFailure::Corrupt(e.to_string()))?,
                length: le_u64(&metadata, entry_offset + 16)
                    .map_err(|e| CopyFailure::Corrupt(e.to_string()))?,
            };
            if let Some(previous) = declared_header_range {
                if previous != entry_range {
                    return Err(CopyFailure::Corrupt(
                        "multiple FVE volume-header entries disagree".into(),
                    ));
                }
            }
            declared_header_range = Some(entry_range);
        }
        entry_offset += entry_size;
    }

    let Some(declared_header_range) = declared_header_range else {
        return Err(CopyFailure::Corrupt(
            "FVE metadata has no volume-header offset/size entry".into(),
        ));
    };
    if declared_header_range != header_range {
        return Err(CopyFailure::Corrupt(
            "FVE volume-header entry disagrees with the metadata block header".into(),
        ));
    }

    Ok(ParsedMetadataCopy {
        block_header_version: version,
        raw_encrypted_volume_size,
        volume_header_offset,
        volume_header_size,
        metadata_payload_size,
        encryption_method,
        volume_identifier,
    })
}

fn interpret_encrypted_boundary(
    raw: u64,
    volume_len: u64,
    partition_offset: u64,
    sector_size: u64,
) -> std::io::Result<(u64, EncryptedBoundaryInterpretation)> {
    if raw == 0 {
        // This is the exact convention used by libbde: a zero boundary disables
        // pass-through and subjects all non-virtual sectors to the configured
        // cipher. We accept it only after the 0x0004/0x0004 state check above.
        return Ok((volume_len, EncryptedBoundaryInterpretation::NotPresent));
    }

    let relative = (raw <= volume_len && raw % sector_size == 0).then_some(raw);
    let absolute = raw
        .checked_sub(partition_offset)
        .filter(|boundary| *boundary <= volume_len && *boundary % sector_size == 0);

    // The FVE v2 block header does not carry a flag identifying the coordinate
    // system used by this field. The documented/specification interpretation is
    // partition-relative, so it must win whenever it is internally valid. Some
    // acquired volumes (including the AFF integration fixture) store an
    // absolute-disk boundary greater than the partition length; absolute-disk
    // interpretation is therefore a compatibility fallback only when the
    // partition-relative interpretation is impossible.
    match (relative, absolute) {
        (Some(boundary), _) => Ok((boundary, EncryptedBoundaryInterpretation::PartitionRelative)),
        (None, Some(boundary)) if partition_offset != 0 => {
            Ok((boundary, EncryptedBoundaryInterpretation::AbsoluteDisk))
        }
        _ => Err(invalid_data(format!(
            "BitLocker encrypted-volume size {raw} is neither a valid partition-relative nor absolute-disk boundary"
        ))),
    }
}

fn validate_metadata_ranges(
    offsets: [u64; 3],
    volume_len: u64,
    sector_size: u64,
) -> std::io::Result<()> {
    for (index, offset) in offsets.iter().copied().enumerate() {
        if offset == 0 {
            return Err(invalid_data(format!(
                "BitLocker metadata copy {} has a zero offset",
                index + 1
            )));
        }
        validate_range(
            BitLockerRange {
                offset,
                length: WINDOWS_7_METADATA_REGION_SIZE,
            },
            volume_len,
            sector_size,
            "metadata copy",
        )?;
    }
    for first in 0..offsets.len() {
        for second in (first + 1)..offsets.len() {
            if ranges_overlap(
                BitLockerRange {
                    offset: offsets[first],
                    length: WINDOWS_7_METADATA_REGION_SIZE,
                },
                BitLockerRange {
                    offset: offsets[second],
                    length: WINDOWS_7_METADATA_REGION_SIZE,
                },
            ) {
                return Err(invalid_data("BitLocker metadata regions overlap"));
            }
        }
    }
    Ok(())
}

fn validate_range(
    range: BitLockerRange,
    volume_len: u64,
    sector_size: u64,
    label: &str,
) -> std::io::Result<()> {
    if range.offset % sector_size != 0 || range.length % sector_size != 0 {
        return Err(invalid_data(format!(
            "BitLocker {label} is not sector aligned"
        )));
    }
    let Some(end) = range.offset.checked_add(range.length) else {
        return Err(invalid_data(format!("BitLocker {label} range overflows")));
    };
    if end > volume_len {
        return Err(invalid_data(format!(
            "BitLocker {label} range exceeds the partition"
        )));
    }
    Ok(())
}

fn ranges_overlap(first: BitLockerRange, second: BitLockerRange) -> bool {
    first.offset < second.end() && second.offset < first.end()
}

pub enum BitLockerXts {
    Aes128(Xts128<Aes128>),
    Aes256(Xts128<Aes256>),
}

impl BitLockerXts {
    fn new(method: BitLockerEncryptionMethod, fvek: &[u8]) -> std::io::Result<Self> {
        let expected = method.fvek_len();
        if fvek.len() != expected {
            return Err(invalid_input(format!(
                "FVEK length {} does not match {:?}; expected {expected} bytes",
                fvek.len(),
                method
            )));
        }
        match method {
            BitLockerEncryptionMethod::AesXts128 => {
                let (key1, key2) = fvek.split_at(16);
                let cipher1 = Aes128::new_from_slice(key1)
                    .map_err(|_| invalid_input("invalid AES-XTS-128 FVEK component length"))?;
                let cipher2 = Aes128::new_from_slice(key2)
                    .map_err(|_| invalid_input("invalid AES-XTS-128 FVEK component length"))?;
                Ok(Self::Aes128(Xts128::<Aes128>::new(cipher1, cipher2)))
            }
            BitLockerEncryptionMethod::AesXts256 => {
                let (key1, key2) = fvek.split_at(32);
                let cipher1 = Aes256::new_from_slice(key1)
                    .map_err(|_| invalid_input("invalid AES-XTS-256 FVEK component length"))?;
                let cipher2 = Aes256::new_from_slice(key2)
                    .map_err(|_| invalid_input("invalid AES-XTS-256 FVEK component length"))?;
                Ok(Self::Aes256(Xts128::<Aes256>::new(cipher1, cipher2)))
            }
        }
    }

    fn decrypt(&mut self, data: &mut [u8], sector_size: usize, first_sector: u64) {
        debug_assert!(sector_size >= 16);
        debug_assert_eq!(data.len() % sector_size, 0);

        // `xts-mode` resets the tweak at each `sector_size` boundary and adds
        // the chunk index to `first_sector`. Passing complete, sector-aligned
        // areas avoids redundant dispatch while preserving exactly the same
        // BitLocker tweak sequence.
        match self {
            Self::Aes128(xts) => decrypt_xts_area(xts, data, sector_size, first_sector),
            Self::Aes256(xts) => decrypt_xts_area(xts, data, sector_size, first_sector),
        }
    }
}

fn decrypt_xts_area<C>(xts: &Xts128<C>, data: &mut [u8], sector_size: usize, first_sector: u64)
where
    C: BlockEncrypt + BlockDecrypt + BlockCipher + Sync,
{
    if data.len() < PARALLEL_XTS_MIN_BYTES {
        xts.decrypt_area(data, sector_size, first_sector as u128, get_tweak_default);
        return;
    }

    let available_jobs = rayon::current_num_threads().min(PARALLEL_XTS_MAX_JOBS);
    if available_jobs <= 1 {
        xts.decrypt_area(data, sector_size, first_sector as u128, get_tweak_default);
        return;
    }

    let sector_count = data.len() / sector_size;
    let job_count = available_jobs.min(sector_count);
    let sectors_per_job = sector_count.div_ceil(job_count);
    let bytes_per_job = sectors_per_job * sector_size;

    data.par_chunks_mut(bytes_per_job)
        .enumerate()
        .for_each(|(job_index, chunk)| {
            let sector_offset = job_index * sectors_per_job;
            xts.decrypt_area(
                chunk,
                sector_size,
                first_sector as u128 + sector_offset as u128,
                get_tweak_default,
            );
        });
}

/// A bounded, seekable decrypted view of a supported BitLocker volume.
pub struct BitLockerStream<T: Read + Seek> {
    inner: BufReader<T>,
    xts: BitLockerXts,
    layout: BitLockerLayout,
    stream_pos: u64,
    sector_cache: Vec<u8>,
    cached_logical_sector: Option<u64>,
}

impl<T: Read + Seek> BitLockerStream<T> {
    /// Compatibility constructor. Absolute-disk metadata fields cannot be
    /// interpreted when the partition offset is unknown; use
    /// `new_with_options` for an image partition.
    pub fn new(mut inner: T, fvek: &[u8], sector_size: u64) -> std::io::Result<Self> {
        let volume_len = inner.seek(SeekFrom::End(0))?;
        inner.seek(SeekFrom::Start(0))?;
        Self::new_with_len(inner, fvek, sector_size, volume_len)
    }

    /// Compatibility constructor for bounded sources whose partition offset is
    /// zero or whose metadata boundary is volume-relative.
    pub fn new_with_len(
        inner: T,
        fvek: &[u8],
        sector_size: u64,
        volume_len: u64,
    ) -> std::io::Result<Self> {
        Self::new_with_options(
            inner,
            fvek,
            BitLockerVolumeOptions::new(volume_len, sector_size),
        )
    }

    /// Preferred constructor. `partition_offset_bytes` in the options is
    /// required when the FVE encrypted-volume boundary is absolute-disk based.
    pub fn new_with_options(
        mut inner: T,
        fvek: &[u8],
        options: BitLockerVolumeOptions,
    ) -> std::io::Result<Self> {
        let layout = BitLockerLayout::discover(&mut inner, options)?;
        Self::from_layout(inner, fvek, layout)
    }

    /// Reuse a previously discovered layout. The key is still validated against
    /// independent NTFS boot-sector and MFT invariants.
    pub fn from_layout(inner: T, fvek: &[u8], layout: BitLockerLayout) -> std::io::Result<Self> {
        let xts = BitLockerXts::new(layout.encryption_method, fvek)?;
        let sector_size = layout.sector_size as usize;
        let mut stream = Self {
            inner: BufReader::with_capacity(1024 * 1024, inner),
            xts,
            layout,
            stream_pos: 0,
            sector_cache: vec![0u8; sector_size],
            cached_logical_sector: None,
        };
        stream.validate_ntfs_key()?;
        Ok(stream)
    }

    pub fn layout(&self) -> &BitLockerLayout {
        &self.layout
    }

    pub fn len(&self) -> u64 {
        self.layout.volume_len
    }

    pub fn is_empty(&self) -> bool {
        self.layout.volume_len == 0
    }

    fn validate_ntfs_key(&mut self) -> std::io::Result<()> {
        let sector_size = self.layout.sector_size as usize;
        let mut boot = vec![0u8; sector_size];
        self.read_logical_sector(0, &mut boot)?;
        if &boot[3..11] != NTFS_SIGNATURE {
            return Err(invalid_data(
                "FVEK validation failed: reconstructed volume header is not NTFS",
            ));
        }
        if le_u16(&boot, 11)? as u64 != self.layout.sector_size {
            return Err(invalid_data(
                "FVEK validation failed: reconstructed NTFS sector size is inconsistent",
            ));
        }
        if boot[510] != 0x55 || boot[511] != 0xaa {
            return Err(invalid_data(
                "FVEK validation failed: reconstructed NTFS boot signature is invalid",
            ));
        }

        let sectors_per_cluster = boot[13] as u64;
        if sectors_per_cluster == 0 || !sectors_per_cluster.is_power_of_two() {
            return Err(invalid_data(
                "FVEK validation failed: invalid NTFS sectors-per-cluster value",
            ));
        }
        let total_sectors = le_u64(&boot, 40)?;
        let total_bytes = total_sectors
            .checked_mul(self.layout.sector_size)
            .ok_or_else(|| invalid_data("FVEK validation failed: NTFS volume-size overflow"))?;
        if total_sectors == 0 || total_bytes > self.layout.volume_len {
            return Err(invalid_data(
                "FVEK validation failed: reconstructed NTFS volume size is out of bounds",
            ));
        }

        let cluster_size = sectors_per_cluster
            .checked_mul(self.layout.sector_size)
            .ok_or_else(|| invalid_data("FVEK validation failed: NTFS cluster-size overflow"))?;
        let mft_cluster = le_u64(&boot, 48)?;
        let mft_offset = mft_cluster
            .checked_mul(cluster_size)
            .ok_or_else(|| invalid_data("FVEK validation failed: NTFS MFT offset overflow"))?;
        let mft_end = mft_offset
            .checked_add(self.layout.sector_size)
            .ok_or_else(|| invalid_data("FVEK validation failed: NTFS MFT range overflow"))?;
        if mft_end > self.layout.volume_len {
            return Err(invalid_data(
                "FVEK validation failed: reconstructed NTFS MFT is outside the volume",
            ));
        }
        let mut mft_sector = vec![0u8; sector_size];
        self.read_logical_sector(mft_offset, &mut mft_sector)?;
        if &mft_sector[..4] != b"FILE" {
            return Err(invalid_data(
                "FVEK validation failed: NTFS MFT record zero signature is invalid",
            ));
        }

        self.cached_logical_sector = None;
        self.stream_pos = 0;
        Ok(())
    }

    fn read_logical_sector(
        &mut self,
        logical_sector_start: u64,
        output: &mut [u8],
    ) -> std::io::Result<()> {
        let sector_size = self.layout.sector_size as usize;
        if output.len() != sector_size || logical_sector_start % self.layout.sector_size != 0 {
            return Err(invalid_input(
                "internal BitLocker sector read is not aligned",
            ));
        }
        let logical_sector_end = logical_sector_start
            .checked_add(self.layout.sector_size)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::UnexpectedEof,
                    "BitLocker sector range overflows the bounded volume",
                )
            })?;
        if logical_sector_end > self.layout.volume_len {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "BitLocker sector exceeds the bounded volume",
            ));
        }

        // Logical header sectors take precedence: their physical source lies in
        // a range that is zero only when addressed at its original location.
        if logical_sector_start >= self.layout.relocated_header.length
            && self
                .layout
                .zero_ranges()
                .any(|range| range.contains(logical_sector_start))
        {
            output.fill(0);
            return Ok(());
        }

        let physical_start = if logical_sector_start < self.layout.relocated_header.length {
            self.layout.relocated_header.offset + logical_sector_start
        } else {
            logical_sector_start
        };
        read_exact_at(&mut self.inner, physical_start, output)?;
        if physical_start < self.layout.encrypted_boundary {
            self.xts.decrypt(
                output,
                sector_size,
                physical_start / self.layout.sector_size,
            );
        }
        Ok(())
    }

    fn ensure_cached(&mut self, logical_sector_start: u64) -> std::io::Result<()> {
        if self.cached_logical_sector == Some(logical_sector_start) {
            return Ok(());
        }
        let mut sector = std::mem::take(&mut self.sector_cache);
        self.read_logical_sector(logical_sector_start, &mut sector)?;
        self.sector_cache = sector;
        self.cached_logical_sector = Some(logical_sector_start);
        Ok(())
    }

    fn segment_at(&self, logical_start: u64) -> Segment {
        if logical_start < self.layout.relocated_header.length {
            let physical_start = self.layout.relocated_header.offset + logical_start;
            let mut end = self.layout.relocated_header.length;
            if physical_start < self.layout.encrypted_boundary
                && self.layout.encrypted_boundary < self.layout.relocated_header.end()
            {
                end = end.min(self.layout.encrypted_boundary - self.layout.relocated_header.offset);
            }
            return Segment {
                physical_start,
                end,
                zero: false,
                encrypted: physical_start < self.layout.encrypted_boundary,
            };
        }

        for range in self.layout.zero_ranges() {
            if range.contains(logical_start) {
                return Segment {
                    physical_start: logical_start,
                    end: range.end(),
                    zero: true,
                    encrypted: false,
                };
            }
        }

        let next_zero = self
            .layout
            .zero_ranges()
            .filter(|range| range.offset > logical_start)
            .map(|range| range.offset)
            .min()
            .unwrap_or(self.layout.volume_len);
        let encrypted = logical_start < self.layout.encrypted_boundary;
        let boundary = if encrypted {
            self.layout.encrypted_boundary
        } else {
            self.layout.volume_len
        };
        Segment {
            physical_start: logical_start,
            end: next_zero.min(boundary),
            zero: false,
            encrypted,
        }
    }
}

struct Segment {
    physical_start: u64,
    end: u64,
    zero: bool,
    encrypted: bool,
}

impl<T: Read + Seek> Read for BitLockerStream<T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() || self.stream_pos >= self.layout.volume_len {
            return Ok(0);
        }
        let available = (self.layout.volume_len - self.stream_pos).min(buf.len() as u64) as usize;
        let sector_size = self.layout.sector_size as usize;
        let mut written = 0usize;

        while written < available {
            let logical = self.stream_pos;
            let within_sector = (logical % self.layout.sector_size) as usize;
            let remaining = available - written;
            if within_sector != 0 || remaining < sector_size {
                let sector_start = logical - within_sector as u64;
                self.ensure_cached(sector_start)?;
                let count = remaining.min(sector_size - within_sector);
                buf[written..written + count]
                    .copy_from_slice(&self.sector_cache[within_sector..within_sector + count]);
                self.stream_pos += count as u64;
                written += count;
                continue;
            }

            let segment = self.segment_at(logical);
            let segment_bytes = (segment.end - logical) as usize;
            let full_bytes = remaining.min(segment_bytes) / sector_size * sector_size;
            if full_bytes == 0 {
                return Err(invalid_data("invalid zero-length BitLocker segment"));
            }
            let target = &mut buf[written..written + full_bytes];
            if segment.zero {
                target.fill(0);
            } else {
                read_exact_at(&mut self.inner, segment.physical_start, target)?;
                if segment.encrypted {
                    self.xts.decrypt(
                        target,
                        sector_size,
                        segment.physical_start / self.layout.sector_size,
                    );
                }
            }
            self.cached_logical_sector = None;
            self.stream_pos += full_bytes as u64;
            written += full_bytes;
        }
        Ok(written)
    }
}

impl<T: Read + Seek> Seek for BitLockerStream<T> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let (base, delta) = match pos {
            SeekFrom::Start(offset) => {
                self.stream_pos = offset;
                return Ok(offset);
            }
            SeekFrom::Current(delta) => (self.stream_pos, delta),
            SeekFrom::End(delta) => (self.layout.volume_len, delta),
        };
        let new_pos = (base as i128)
            .checked_add(delta as i128)
            .filter(|value| *value >= 0 && *value <= u64::MAX as i128)
            .ok_or_else(|| invalid_input("seek outside the representable BitLocker volume range"))?
            as u64;
        self.stream_pos = new_pos;
        Ok(new_pos)
    }
}

impl<T: Read + Seek + Send> VolumeReader for BitLockerStream<T> {
    fn volume_len(&self) -> u64 {
        self.layout.volume_len
    }

    fn sector_size(&self) -> u32 {
        // Discovery only accepts 512, 1024, 2048, or 4096.
        self.layout.sector_size as u32
    }
}

fn read_exact_at<T: Read + Seek>(
    inner: &mut T,
    offset: u64,
    buf: &mut [u8],
) -> std::io::Result<()> {
    inner.seek(SeekFrom::Start(offset))?;
    inner.read_exact(buf)
}

fn le_u16(data: &[u8], offset: usize) -> std::io::Result<u16> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or_else(|| invalid_data("truncated little-endian u16 field"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn le_u32(data: &[u8], offset: usize) -> std::io::Result<u32> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or_else(|| invalid_data("truncated little-endian u32 field"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn le_u64(data: &[u8], offset: usize) -> std::io::Result<u64> {
    let bytes = data
        .get(offset..offset + 8)
        .ok_or_else(|| invalid_data("truncated little-endian u64 field"))?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn invalid_input(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const SECTOR_SIZE: usize = 512;
    const VOLUME_LEN: usize = 2 * 1024 * 1024;
    const METADATA_OFFSETS: [u64; 3] = [0x10000, 0x20000, 0x30000];
    const RELOCATED_HEADER_OFFSET: u64 = 0x40000;
    const RELOCATED_HEADER_SIZE: usize = 8192;
    const PARTITION_OFFSET: u64 = 0x5000_0000;
    const TEST_VOLUME_IDENTIFIER: [u8; 16] = [
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef,
    ];
    const FVEK_128: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    struct SyntheticVolume {
        encrypted: Vec<u8>,
        clear_view: Vec<u8>,
    }

    fn build_synthetic(
        method: BitLockerEncryptionMethod,
        key: &[u8],
        raw_boundary: u64,
        relative_boundary: u64,
    ) -> SyntheticVolume {
        let mut clear = vec![0u8; VOLUME_LEN];
        for (index, byte) in clear.iter_mut().enumerate() {
            *byte = ((index * 31 + index / SECTOR_SIZE) & 0xff) as u8;
        }

        write_ntfs_boot_sector(&mut clear[..SECTOR_SIZE]);
        let mft_offset = 8 * 8 * SECTOR_SIZE;
        clear[mft_offset..mft_offset + 4].copy_from_slice(b"FILE");
        let last_sector = VOLUME_LEN - SECTOR_SIZE;
        let boot = clear[..SECTOR_SIZE].to_vec();
        clear[last_sector..].copy_from_slice(&boot);

        let mut encrypted = clear.clone();
        let mut xts = BitLockerXts::new(method, key).unwrap();
        encrypt_sectors(&mut xts, &mut encrypted[..relative_boundary as usize], 0);

        let relocated_start = RELOCATED_HEADER_OFFSET as usize;
        encrypted[relocated_start..relocated_start + RELOCATED_HEADER_SIZE]
            .copy_from_slice(&clear[..RELOCATED_HEADER_SIZE]);
        encrypt_sectors(
            &mut xts,
            &mut encrypted[relocated_start..relocated_start + RELOCATED_HEADER_SIZE],
            RELOCATED_HEADER_OFFSET / SECTOR_SIZE as u64,
        );

        write_bitlocker_boot_sector(&mut encrypted[..SECTOR_SIZE]);
        for offset in METADATA_OFFSETS {
            write_metadata_copy(&mut encrypted, offset as usize, method, 4, 4, raw_boundary);
        }

        let mut clear_view = clear;
        for offset in METADATA_OFFSETS {
            clear_view[offset as usize..offset as usize + WINDOWS_7_METADATA_REGION_SIZE as usize]
                .fill(0);
        }
        clear_view[relocated_start..relocated_start + RELOCATED_HEADER_SIZE].fill(0);
        SyntheticVolume {
            encrypted,
            clear_view,
        }
    }

    fn normal_fixture(method: BitLockerEncryptionMethod, key: &[u8]) -> SyntheticVolume {
        build_synthetic(method, key, VOLUME_LEN as u64, VOLUME_LEN as u64)
    }

    fn write_ntfs_boot_sector(sector: &mut [u8]) {
        sector.fill(0);
        sector[..3].copy_from_slice(&[0xeb, 0x52, 0x90]);
        sector[3..11].copy_from_slice(NTFS_SIGNATURE);
        sector[11..13].copy_from_slice(&(SECTOR_SIZE as u16).to_le_bytes());
        sector[13] = 8;
        sector[40..48].copy_from_slice(&((VOLUME_LEN / SECTOR_SIZE - 1) as u64).to_le_bytes());
        sector[48..56].copy_from_slice(&8u64.to_le_bytes());
        sector[56..64].copy_from_slice(&2u64.to_le_bytes());
        sector[64] = 0xf6;
        sector[68] = 1;
        sector[510] = 0x55;
        sector[511] = 0xaa;
    }

    fn write_bitlocker_boot_sector(sector: &mut [u8]) {
        sector.fill(0);
        sector[..3].copy_from_slice(&WINDOWS_7_BOOT_ENTRY_POINT);
        sector[3..11].copy_from_slice(BITLOCKER_SIGNATURE);
        sector[11..13].copy_from_slice(&(SECTOR_SIZE as u16).to_le_bytes());
        sector[160..176].copy_from_slice(&BITLOCKER_IDENTIFIER);
        for (index, offset) in METADATA_OFFSETS.iter().enumerate() {
            let start = 176 + index * 8;
            sector[start..start + 8].copy_from_slice(&offset.to_le_bytes());
        }
        sector[510] = 0x55;
        sector[511] = 0xaa;
    }

    fn write_metadata_copy(
        volume: &mut [u8],
        offset: usize,
        method: BitLockerEncryptionMethod,
        state: u16,
        state_copy: u16,
        raw_boundary: u64,
    ) {
        let region = &mut volume[offset..offset + WINDOWS_7_METADATA_REGION_SIZE as usize];
        region.fill(0);
        region[..8].copy_from_slice(BITLOCKER_SIGNATURE);
        region[8..10].copy_from_slice(&64u16.to_le_bytes());
        region[10..12].copy_from_slice(&FVE_BLOCK_VERSION_WINDOWS_7.to_le_bytes());
        region[12..14].copy_from_slice(&state.to_le_bytes());
        region[14..16].copy_from_slice(&state_copy.to_le_bytes());
        region[16..24].copy_from_slice(&raw_boundary.to_le_bytes());
        region[28..32]
            .copy_from_slice(&((RELOCATED_HEADER_SIZE / SECTOR_SIZE) as u32).to_le_bytes());
        for (index, metadata_offset) in METADATA_OFFSETS.iter().enumerate() {
            let start = 32 + index * 8;
            region[start..start + 8].copy_from_slice(&metadata_offset.to_le_bytes());
        }
        region[56..64].copy_from_slice(&RELOCATED_HEADER_OFFSET.to_le_bytes());

        let metadata_size = (FVE_METADATA_HEADER_SIZE + 24) as u32;
        region[64..68].copy_from_slice(&metadata_size.to_le_bytes());
        region[68..72].copy_from_slice(&FVE_METADATA_VERSION.to_le_bytes());
        region[72..76].copy_from_slice(&(FVE_METADATA_HEADER_SIZE as u32).to_le_bytes());
        region[76..80].copy_from_slice(&metadata_size.to_le_bytes());
        region[80..96].copy_from_slice(&TEST_VOLUME_IDENTIFIER);
        region[100..104].copy_from_slice(&(method as u32).to_le_bytes());

        let entry = 64 + FVE_METADATA_HEADER_SIZE;
        region[entry..entry + 2].copy_from_slice(&24u16.to_le_bytes());
        region[entry + 2..entry + 4]
            .copy_from_slice(&FVE_ENTRY_TYPE_VOLUME_HEADER_BLOCK.to_le_bytes());
        region[entry + 4..entry + 6].copy_from_slice(&FVE_VALUE_TYPE_OFFSET_AND_SIZE.to_le_bytes());
        region[entry + 6..entry + 8].copy_from_slice(&1u16.to_le_bytes());
        region[entry + 8..entry + 16].copy_from_slice(&RELOCATED_HEADER_OFFSET.to_le_bytes());
        region[entry + 16..entry + 24]
            .copy_from_slice(&(RELOCATED_HEADER_SIZE as u64).to_le_bytes());
    }

    fn encrypt_sectors(xts: &mut BitLockerXts, data: &mut [u8], first_sector: u64) {
        for (index, sector) in data.chunks_exact_mut(SECTOR_SIZE).enumerate() {
            let sector_number = first_sector + index as u64;
            match xts {
                BitLockerXts::Aes128(value) => value.encrypt_area(
                    sector,
                    SECTOR_SIZE,
                    sector_number as u128,
                    get_tweak_default,
                ),
                BitLockerXts::Aes256(value) => value.encrypt_area(
                    sector,
                    SECTOR_SIZE,
                    sector_number as u128,
                    get_tweak_default,
                ),
            }
        }
    }

    /// The pre-batching implementation, retained only as an independent test
    /// oracle and for the opt-in performance comparison below.
    fn decrypt_sectors_reference(
        xts: &mut BitLockerXts,
        data: &mut [u8],
        sector_size: usize,
        first_sector: u64,
    ) {
        for (index, sector) in data.chunks_exact_mut(sector_size).enumerate() {
            let sector_number = first_sector + index as u64;
            match xts {
                BitLockerXts::Aes128(value) => value.decrypt_area(
                    sector,
                    sector_size,
                    sector_number as u128,
                    get_tweak_default,
                ),
                BitLockerXts::Aes256(value) => value.decrypt_area(
                    sector,
                    sector_size,
                    sector_number as u128,
                    get_tweak_default,
                ),
            }
        }
    }

    fn deterministic_ciphertext(len: usize) -> Vec<u8> {
        (0..len)
            .map(|index| {
                let mixed = index
                    .wrapping_mul(0x9e37_79b1)
                    .rotate_left((index & 31) as u32);
                (mixed ^ (mixed >> 11)) as u8
            })
            .collect()
    }

    #[test]
    fn bulk_xts_decryption_matches_sectorwise_reference() {
        let fvek_256 = [0x5au8; 64];
        let configurations = [
            (BitLockerEncryptionMethod::AesXts128, &FVEK_128[..]),
            (BitLockerEncryptionMethod::AesXts256, &fvek_256[..]),
        ];

        for (method, key) in configurations {
            for sector_size in [512usize, 1024, 4096] {
                for sector_count in [1usize, 3, 257] {
                    for first_sector in [0u64, 1, 0x1234_5678_9abc] {
                        let ciphertext = deterministic_ciphertext(sector_size * sector_count);
                        let mut expected = ciphertext.clone();
                        let mut reference = BitLockerXts::new(method, key).unwrap();
                        decrypt_sectors_reference(
                            &mut reference,
                            &mut expected,
                            sector_size,
                            first_sector,
                        );

                        let mut actual = ciphertext;
                        let mut bulk = BitLockerXts::new(method, key).unwrap();
                        bulk.decrypt(&mut actual, sector_size, first_sector);
                        assert_eq!(
                            actual, expected,
                            "method={method:?}, sector_size={sector_size}, sector_count={sector_count}, first_sector={first_sector}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn parallel_xts_decryption_matches_sectorwise_reference() {
        let fvek_256 = [0xa5u8; 64];
        let configurations = [
            (
                BitLockerEncryptionMethod::AesXts128,
                &FVEK_128[..],
                512usize,
            ),
            (
                BitLockerEncryptionMethod::AesXts256,
                &fvek_256[..],
                4096usize,
            ),
        ];
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap();

        for (method, key, sector_size) in configurations {
            let len = PARALLEL_XTS_MIN_BYTES + sector_size * 7;
            let ciphertext = deterministic_ciphertext(len);
            let mut expected = ciphertext.clone();
            let mut reference = BitLockerXts::new(method, key).unwrap();
            decrypt_sectors_reference(&mut reference, &mut expected, sector_size, 0x1234_5678);

            let mut actual = ciphertext;
            let mut parallel = BitLockerXts::new(method, key).unwrap();
            pool.install(|| parallel.decrypt(&mut actual, sector_size, 0x1234_5678));
            assert_eq!(actual, expected, "method={method:?}");
        }
    }

    #[test]
    fn bulk_stream_read_crosses_all_virtual_and_encryption_boundaries() {
        let encrypted_boundary = VOLUME_LEN as u64 - 4096;
        let fixture = build_synthetic(
            BitLockerEncryptionMethod::AesXts128,
            &FVEK_128,
            encrypted_boundary,
            encrypted_boundary,
        );
        let mut stream = BitLockerStream::new_with_len(
            Cursor::new(fixture.encrypted),
            &FVEK_128,
            SECTOR_SIZE as u64,
            VOLUME_LEN as u64,
        )
        .unwrap();

        let mut actual = vec![0u8; VOLUME_LEN];
        stream.read_exact(&mut actual).unwrap();
        assert_eq!(actual, fixture.clear_view);
    }

    /// Opt-in microbenchmark comparing the previous serial sectorwise dispatch
    /// with the bounded parallel area path. It asserts output equivalence but
    /// deliberately has no timing assertion because CI hosts have variable
    /// load.
    #[test]
    #[ignore = "performance comparison; run with --release --ignored --nocapture"]
    fn benchmark_bulk_xts_decryption_against_sectorwise_dispatch() {
        use std::time::{Duration, Instant};

        const ROUNDS: usize = 3;
        for bytes in [16 * 1024 * 1024, 64 * 1024 * 1024] {
            let ciphertext = deterministic_ciphertext(bytes);
            let mut sectorwise_best = Duration::MAX;
            let mut bulk_best = Duration::MAX;

            for _ in 0..ROUNDS {
                let mut sectorwise_output = ciphertext.clone();
                let mut sectorwise =
                    BitLockerXts::new(BitLockerEncryptionMethod::AesXts128, &FVEK_128).unwrap();
                let started = Instant::now();
                decrypt_sectors_reference(
                    &mut sectorwise,
                    &mut sectorwise_output,
                    SECTOR_SIZE,
                    0x1234,
                );
                sectorwise_best = sectorwise_best.min(started.elapsed());

                let mut bulk_output = ciphertext.clone();
                let mut bulk =
                    BitLockerXts::new(BitLockerEncryptionMethod::AesXts128, &FVEK_128).unwrap();
                let started = Instant::now();
                bulk.decrypt(&mut bulk_output, SECTOR_SIZE, 0x1234);
                bulk_best = bulk_best.min(started.elapsed());

                assert_eq!(bulk_output, sectorwise_output);
            }

            eprintln!(
                "BitLocker AES-XTS-128, {bytes} bytes: sectorwise={sectorwise_best:?}, parallel={bulk_best:?}, speedup={:.3}x",
                sectorwise_best.as_secs_f64() / bulk_best.as_secs_f64()
            );
        }
    }

    #[test]
    fn discovers_layout_and_maps_only_declared_header_range() {
        let fixture = normal_fixture(BitLockerEncryptionMethod::AesXts128, &FVEK_128);
        let mut stream = BitLockerStream::new(
            Cursor::new(fixture.encrypted),
            &FVEK_128,
            SECTOR_SIZE as u64,
        )
        .unwrap();
        assert_eq!(stream.layout().metadata_offsets(), METADATA_OFFSETS);
        assert_eq!(stream.layout().metadata_region_size(), 65_536);
        assert_eq!(stream.layout().metadata_payload_size(), 72);
        assert_eq!(stream.layout().layout_identifier(), BITLOCKER_IDENTIFIER);
        assert_eq!(stream.layout().volume_identifier(), TEST_VOLUME_IDENTIFIER);
        assert_eq!(
            stream.layout().relocated_header(),
            BitLockerRange {
                offset: RELOCATED_HEADER_OFFSET,
                length: RELOCATED_HEADER_SIZE as u64,
            }
        );

        let mut first = vec![0u8; RELOCATED_HEADER_SIZE + SECTOR_SIZE];
        stream.read_exact(&mut first).unwrap();
        assert_eq!(first, fixture.clear_view[..first.len()]);
        assert_ne!(&first[RELOCATED_HEADER_SIZE..], &first[..SECTOR_SIZE]);
    }

    #[test]
    fn supports_unaligned_cross_sector_reads_and_seek_from_end() {
        let fixture = normal_fixture(BitLockerEncryptionMethod::AesXts128, &FVEK_128);
        let mut stream = BitLockerStream::new_with_len(
            Cursor::new(fixture.encrypted),
            &FVEK_128,
            SECTOR_SIZE as u64,
            VOLUME_LEN as u64,
        )
        .unwrap();
        stream.seek(SeekFrom::Start(507)).unwrap();
        let mut cross = vec![0u8; 1031];
        stream.read_exact(&mut cross).unwrap();
        assert_eq!(cross, fixture.clear_view[507..507 + cross.len()]);

        assert_eq!(
            stream.seek(SeekFrom::End(-777)).unwrap(),
            VOLUME_LEN as u64 - 777
        );
        let mut tail = vec![0u8; 777];
        stream.read_exact(&mut tail).unwrap();
        assert_eq!(tail, fixture.clear_view[VOLUME_LEN - 777..]);
        assert_eq!(stream.read(&mut [0u8; 1]).unwrap(), 0);
    }

    #[test]
    fn zeroes_complete_metadata_and_relocated_storage_ranges() {
        let fixture = normal_fixture(BitLockerEncryptionMethod::AesXts128, &FVEK_128);
        let mut stream = BitLockerStream::new(
            Cursor::new(fixture.encrypted),
            &FVEK_128,
            SECTOR_SIZE as u64,
        )
        .unwrap();
        for offset in METADATA_OFFSETS
            .into_iter()
            .chain(std::iter::once(RELOCATED_HEADER_OFFSET))
        {
            stream.seek(SeekFrom::Start(offset - 9)).unwrap();
            let mut data = vec![0xa5; SECTOR_SIZE + 18];
            stream.read_exact(&mut data).unwrap();
            assert_eq!(
                data,
                fixture.clear_view[offset as usize - 9..offset as usize + SECTOR_SIZE + 9]
            );
        }

        for offset in METADATA_OFFSETS {
            stream.seek(SeekFrom::Start(offset)).unwrap();
            let mut reservation = vec![0xa5; WINDOWS_7_METADATA_REGION_SIZE as usize];
            stream.read_exact(&mut reservation).unwrap();
            assert!(reservation.iter().all(|byte| *byte == 0));
        }
        stream
            .seek(SeekFrom::Start(RELOCATED_HEADER_OFFSET))
            .unwrap();
        let mut relocated = vec![0xa5; RELOCATED_HEADER_SIZE];
        stream.read_exact(&mut relocated).unwrap();
        assert!(relocated.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn interprets_absolute_boundary_and_passes_clear_tail_through() {
        let boundary = VOLUME_LEN as u64 - 4096;
        let raw = PARTITION_OFFSET + boundary;
        let fixture = build_synthetic(
            BitLockerEncryptionMethod::AesXts128,
            &FVEK_128,
            raw,
            boundary,
        );
        let options = BitLockerVolumeOptions::new(VOLUME_LEN as u64, SECTOR_SIZE as u64)
            .with_partition_offset_bytes(PARTITION_OFFSET);
        let mut stream =
            BitLockerStream::new_with_options(Cursor::new(fixture.encrypted), &FVEK_128, options)
                .unwrap();
        assert_eq!(stream.layout().encrypted_boundary(), boundary);
        assert_eq!(
            stream.layout().encrypted_boundary_interpretation(),
            EncryptedBoundaryInterpretation::AbsoluteDisk
        );
        stream.seek(SeekFrom::Start(boundary - 512)).unwrap();
        let mut around_boundary = vec![0u8; 1536];
        stream.read_exact(&mut around_boundary).unwrap();
        assert_eq!(
            around_boundary,
            fixture.clear_view[boundary as usize - 512..boundary as usize + 1024]
        );
    }

    #[test]
    fn prefers_spec_partition_relative_boundary_when_both_coordinates_fit() {
        let fixture = normal_fixture(BitLockerEncryptionMethod::AesXts128, &FVEK_128);
        // With this non-zero disk offset, raw == volume_len could also be
        // arithmetically interpreted as a smaller absolute-disk boundary. The
        // specification-relative interpretation must take precedence.
        let options = BitLockerVolumeOptions::new(VOLUME_LEN as u64, SECTOR_SIZE as u64)
            .with_partition_offset_bytes(0x1_0000);
        let mut stream =
            BitLockerStream::new_with_options(Cursor::new(fixture.encrypted), &FVEK_128, options)
                .unwrap();
        assert_eq!(stream.layout().encrypted_boundary(), VOLUME_LEN as u64);
        assert_eq!(
            stream.layout().encrypted_boundary_interpretation(),
            EncryptedBoundaryInterpretation::PartitionRelative
        );

        stream.seek(SeekFrom::End(-1024)).unwrap();
        let mut tail = [0u8; 1024];
        stream.read_exact(&mut tail).unwrap();
        assert_eq!(tail, fixture.clear_view[VOLUME_LEN - 1024..]);
    }

    #[test]
    fn falls_back_from_corrupt_primary_copy() {
        let mut fixture = normal_fixture(BitLockerEncryptionMethod::AesXts128, &FVEK_128);
        let first = METADATA_OFFSETS[0] as usize;
        fixture.encrypted[first..first + 8].fill(0);
        let stream = BitLockerStream::new(
            Cursor::new(fixture.encrypted),
            &FVEK_128,
            SECTOR_SIZE as u64,
        )
        .unwrap();
        assert_eq!(stream.layout().selected_metadata_copy(), 1);
    }

    #[test]
    fn rejects_disagreeing_valid_copies_and_partial_state() {
        let mut disagree = normal_fixture(BitLockerEncryptionMethod::AesXts128, &FVEK_128);
        let second = METADATA_OFFSETS[1] as usize;
        disagree.encrypted[second + 16..second + 24]
            .copy_from_slice(&((VOLUME_LEN - SECTOR_SIZE) as u64).to_le_bytes());
        let error = BitLockerStream::new(
            Cursor::new(disagree.encrypted),
            &FVEK_128,
            SECTOR_SIZE as u64,
        )
        .err()
        .unwrap();
        assert!(error.to_string().contains("disagree"));

        let mut partial = normal_fixture(BitLockerEncryptionMethod::AesXts128, &FVEK_128);
        for offset in METADATA_OFFSETS {
            write_metadata_copy(
                &mut partial.encrypted,
                offset as usize,
                BitLockerEncryptionMethod::AesXts128,
                5,
                1,
                VOLUME_LEN as u64,
            );
        }
        let error = BitLockerStream::new(
            Cursor::new(partial.encrypted),
            &FVEK_128,
            SECTOR_SIZE as u64,
        )
        .err()
        .unwrap();
        assert!(error.to_string().contains("conversion/protection state"));
    }

    #[test]
    fn validates_key_without_exposing_it() {
        let fixture = normal_fixture(BitLockerEncryptionMethod::AesXts128, &FVEK_128);
        let wrong_key = [0xabu8; 32];
        let error = BitLockerStream::new(
            Cursor::new(fixture.encrypted),
            &wrong_key,
            SECTOR_SIZE as u64,
        )
        .err()
        .unwrap();
        let message = error.to_string();
        assert!(message.contains("FVEK validation failed"));
        assert!(!message.contains(&hex::encode(wrong_key)));
    }

    #[test]
    fn supports_metadata_declared_aes_xts_256() {
        let key = [0x5au8; 64];
        let fixture = normal_fixture(BitLockerEncryptionMethod::AesXts256, &key);
        let stream =
            BitLockerStream::new(Cursor::new(fixture.encrypted), &key, SECTOR_SIZE as u64).unwrap();
        assert_eq!(
            stream.layout().encryption_method(),
            BitLockerEncryptionMethod::AesXts256
        );
    }

    #[test]
    fn seek_bounds_match_a_bounded_read_only_stream() {
        let fixture = normal_fixture(BitLockerEncryptionMethod::AesXts128, &FVEK_128);
        let mut stream = BitLockerStream::new(
            Cursor::new(fixture.encrypted),
            &FVEK_128,
            SECTOR_SIZE as u64,
        )
        .unwrap();

        assert_eq!(stream.seek(SeekFrom::Start(0)).unwrap(), 0);
        assert!(stream.seek(SeekFrom::Current(-1)).is_err());
        assert!(
            stream
                .seek(SeekFrom::End(-(VOLUME_LEN as i64) - 1))
                .is_err()
        );
        assert_eq!(stream.seek(SeekFrom::End(0)).unwrap(), VOLUME_LEN as u64);
        assert_eq!(stream.read(&mut [0u8; 8]).unwrap(), 0);

        // As with std::fs::File, seeking beyond EOF is allowed; reads remain
        // bounded and return EOF until repositioned.
        assert_eq!(
            stream
                .seek(SeekFrom::Start(VOLUME_LEN as u64 + 4096))
                .unwrap(),
            VOLUME_LEN as u64 + 4096
        );
        assert_eq!(stream.read(&mut [0u8; 8]).unwrap(), 0);
        assert_eq!(stream.seek(SeekFrom::Start(0)).unwrap(), 0);
        let mut signature = [0u8; 11];
        stream.read_exact(&mut signature).unwrap();
        assert_eq!(&signature[3..], NTFS_SIGNATURE);
    }

    /// Opt-in real-evidence test. No evidence path or key is stored in source.
    #[test]
    #[ignore = "requires EXHUME_BITLOCKER_TEST_* environment variables"]
    fn opens_real_image_when_configured() {
        use exhume_body::{Body, BodySlice};

        let Ok(path) = std::env::var("EXHUME_BITLOCKER_TEST_IMAGE") else {
            return;
        };
        let format =
            std::env::var("EXHUME_BITLOCKER_TEST_FORMAT").unwrap_or_else(|_| "auto".to_owned());
        let offset: u64 = std::env::var("EXHUME_BITLOCKER_TEST_OFFSET")
            .expect("EXHUME_BITLOCKER_TEST_OFFSET")
            .parse()
            .expect("decimal partition offset");
        let length: u64 = std::env::var("EXHUME_BITLOCKER_TEST_LENGTH")
            .expect("EXHUME_BITLOCKER_TEST_LENGTH")
            .parse()
            .expect("decimal partition length");
        let fvek = hex::decode(
            std::env::var("EXHUME_BITLOCKER_TEST_FVEK_HEX")
                .expect("EXHUME_BITLOCKER_TEST_FVEK_HEX"),
        )
        .expect("hex FVEK");

        let body = Body::new(path, &format);
        let slice = BodySlice::new(&body, offset, length).expect("partition BodySlice");
        let options = BitLockerVolumeOptions::new(length, 512).with_partition_offset_bytes(offset);
        let stream = BitLockerStream::new_with_options(slice, &fvek, options)
            .expect("metadata-driven BitLocker stream");
        eprintln!("{:#?}", stream.layout());
        assert_eq!(stream.len(), length);
    }
}
