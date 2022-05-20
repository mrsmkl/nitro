// Copyright 2021-2022, Offchain Labs, Inc.
// For license information, see https://github.com/nitro/blob/master/LICENSE

use serde::{Deserialize, Serialize};
use std::{
    borrow::Borrow,
    fmt,
    fs::File,
    io::Read,
    ops::{Deref, DerefMut},
    path::Path,
};
use wasmparser::{TableType, Type};
use crate::HashResult;

/// cbindgen:field-names=[bytes]
#[derive(Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(C)]
pub struct Bytes32(pub [u8; 32]);

impl HashResult for Bytes32 {
}

impl Deref for Bytes32 {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Into<Vec<u8>> for Bytes32 {
    fn into(self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl DerefMut for Bytes32 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AsRef<[u8]> for Bytes32 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Borrow<[u8]> for Bytes32 {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for Bytes32 {
    fn from(x: [u8; 32]) -> Self {
        Self(x)
    }
}

impl From<u32> for Bytes32 {
    fn from(x: u32) -> Self {
        let mut b = [0u8; 32];
        b[(32 - 4)..].copy_from_slice(&x.to_be_bytes());
        Self(b)
    }
}

impl From<u64> for Bytes32 {
    fn from(x: u64) -> Self {
        let mut b = [0u8; 32];
        b[(32 - 8)..].copy_from_slice(&x.to_be_bytes());
        Self(b)
    }
}

impl From<usize> for Bytes32 {
    fn from(x: usize) -> Self {
        let mut b = [0u8; 32];
        b[(32 - (usize::BITS as usize / 8))..].copy_from_slice(&x.to_be_bytes());
        Self(b)
    }
}

impl IntoIterator for Bytes32 {
    type Item = u8;
    type IntoIter = std::array::IntoIter<u8, 32>;

    fn into_iter(self) -> Self::IntoIter {
        IntoIterator::into_iter(self.0)
    }
}

type GenericBytes32 = digest::generic_array::GenericArray<u8, digest::generic_array::typenum::U32>;

impl From<GenericBytes32> for Bytes32 {
    fn from(x: GenericBytes32) -> Self {
        <[u8; 32]>::from(x).into()
    }
}

impl fmt::Display for Bytes32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self))
    }
}

impl fmt::Debug for Bytes32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self))
    }
}

impl From<DeprecatedTableType> for TableType {
    fn from(table: DeprecatedTableType) -> Self {
        Self {
            element_type: match table.ty {
                DeprecatedRefType::FuncRef => Type::FuncRef,
                DeprecatedRefType::ExternRef => Type::ExternRef,
            },
            initial: table.limits.minimum_size,
            maximum: table.limits.maximum_size,
        }
    }
}

/// A Vec<u8> allocated with libc::malloc
pub struct CBytes {
    ptr: *mut u8,
    len: usize,
}

impl CBytes {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    pub unsafe fn from_raw_parts(ptr: *mut u8, len: usize) -> Self {
        Self { ptr, len }
    }
}

impl Default for CBytes {
    fn default() -> Self {
        Self {
            ptr: std::ptr::null_mut(),
            len: 0,
        }
    }
}

// TODO: remove this when re-initializing the rollup
// this is kept around to deserialize old binaries
#[derive(Serialize, Deserialize)]
pub enum DeprecatedRefType {
    FuncRef,
    ExternRef,
}

// TODO: remove this when re-initializing the rollup
// this is kept around to deserialize old binaries
#[derive(Serialize, Deserialize)]
pub struct DeprecatedLimits {
    pub minimum_size: u32,
    pub maximum_size: Option<u32>,
}

// TODO: remove this when re-initializing the rollup
// this is kept around to deserialize old binaries
#[derive(Serialize, Deserialize)]
pub struct DeprecatedTableType {
    pub ty: DeprecatedRefType,
    pub limits: DeprecatedLimits,
}

impl From<TableType> for DeprecatedTableType {
    fn from(table: TableType) -> Self {
        Self {
            ty: match table.element_type {
                Type::FuncRef => DeprecatedRefType::FuncRef,
                Type::ExternRef => DeprecatedRefType::ExternRef,
                x => panic!("impossible table type {:?}", x),
            },
            limits: DeprecatedLimits {
                minimum_size: table.initial,
                maximum_size: table.maximum,
            },
        }
    }
}

impl From<&[u8]> for CBytes {
    fn from(slice: &[u8]) -> Self {
        if slice.is_empty() {
            return Self::default();
        }
        unsafe {
            let ptr = libc::malloc(slice.len()) as *mut u8;
            if ptr.is_null() {
                panic!("Failed to allocate memory instantiating CBytes");
            }
            std::ptr::copy_nonoverlapping(slice.as_ptr(), ptr, slice.len());
            Self {
                ptr,
                len: slice.len(),
            }
        }
    }
}

impl Drop for CBytes {
    fn drop(&mut self) {
        unsafe { libc::free(self.ptr as _) }
    }
}

impl Clone for CBytes {
    fn clone(&self) -> Self {
        self.as_slice().into()
    }
}

impl Deref for CBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsRef<[u8]> for CBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl Borrow<[u8]> for CBytes {
    fn borrow(&self) -> &[u8] {
        self.as_slice()
    }
}

#[derive(Clone)]
pub struct CBytesIntoIter(CBytes, usize);

impl Iterator for CBytesIntoIter {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        if self.1 >= self.0.len {
            return None;
        }
        let byte = self.0[self.1];
        self.1 += 1;
        Some(byte)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.0.len - self.1;
        (len, Some(len))
    }
}

impl IntoIterator for CBytes {
    type Item = u8;
    type IntoIter = CBytesIntoIter;

    fn into_iter(self) -> CBytesIntoIter {
        CBytesIntoIter(self, 0)
    }
}

pub fn file_bytes(path: &Path) -> eyre::Result<Vec<u8>> {
    let mut f = File::open(path)?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    Ok(buf)
}
