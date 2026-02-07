use core::{
    ops::{Deref, DerefMut},
    ptr::{self, NonNull},
};

use wdk_sys::{
    _MODE::KernelMode,
    GENERIC_ALL, HANDLE, OBJ_KERNEL_HANDLE, PEPROCESS, PETHREAD, PsProcessType, PsThreadType,
    ULONG,
    ntddk::{ObOpenObjectByPointer, ZwClose},
};

use crate::raw::AsRawObject;
use crate::{
    kobject::KernelObject,
    ntstatus::{Result, cvt},
    raw::AsRawHandle,
};

/// an abstract concept for "close kernel handle"
///
/// # Noteworthy
/// ***Not*** all the kernel handles use the same semantic as `ZwClose`
/// which means some "special" handles that can not be "closed" using `ZwClose` as they may not actually reference
/// a kernel object, but just a plain structure, for example: a HANDLE returned from `KeRegisterNmiCallback`.
/// user should override this method if that happens
pub trait CloseHandle {
    fn close(&self);
}

/// A owned kernel object handle wrapper, not a generic handle wrapper
///
/// # Safety
/// since the underlying handle of a `ObjectHandle` is wrapped within a `NonNull`
/// so it is can be safely transfer native kernel API
#[repr(transparent)]
pub struct ObjectHandle(NonNull<core::ffi::c_void>);

impl ObjectHandle {
    pub const fn new(h: HANDLE) -> Self {
        Self(NonNull::new(h).unwrap())
    }

    pub fn get(&self) -> HANDLE {
        self.0.as_ptr()
    }
}

/// convert from an owned `KernelObject`
pub trait FromOwnedObject<T> {
    fn from_kobject(object: &KernelObject<T>) -> Result<ObjectHandle>;
}

// convert from a raw PEPROCESS and take ownership of its handle
pub trait FromRawProcess {
    fn from_process(process: PEPROCESS, access: ULONG) -> Result<ObjectHandle>;
}

// convert from a raw PETHREAD and take ownership of its handle
pub trait FromRawThread {
    fn from_thread(thread: PETHREAD, access: ULONG) -> Result<ObjectHandle>;
}

impl FromRawProcess for ObjectHandle {
    fn from_process(process: PEPROCESS, access: ULONG) -> Result<ObjectHandle> {
        let mut handle: HANDLE = ptr::null_mut();
        unsafe {
            cvt(ObOpenObjectByPointer(
                process.cast(),
                OBJ_KERNEL_HANDLE as _,
                ptr::null_mut(),
                access,
                *PsProcessType,
                KernelMode as _,
                &mut handle,
            ))
            .map(|_| Self(NonNull::new(handle).unwrap()))
        }
    }
}

impl FromRawThread for ObjectHandle {
    fn from_thread(thread: PETHREAD, access: ULONG) -> Result<ObjectHandle> {
        let mut handle: HANDLE = ptr::null_mut();

        unsafe {
            cvt(ObOpenObjectByPointer(
                thread.cast(),
                OBJ_KERNEL_HANDLE as _,
                ptr::null_mut(),
                access,
                *PsThreadType,
                KernelMode as _,
                &mut handle,
            ))
            .map(|_| Self(NonNull::new(handle).unwrap()))
        }
    }
}

impl AsRawHandle for ObjectHandle {
    fn as_raw(&self) -> HANDLE {
        self.0.as_ptr()
    }
}

// FIXME: convert from a undocumented kernel object type is dangerous !!
// we need sepcializations here
impl<T> FromOwnedObject<T> for ObjectHandle {
    fn from_kobject(object: &KernelObject<T>) -> Result<ObjectHandle> {
        let mut handle: HANDLE = ptr::null_mut();

        cvt(unsafe {
            ObOpenObjectByPointer(
                object.as_raw().cast(),
                OBJ_KERNEL_HANDLE,
                ptr::null_mut(),
                GENERIC_ALL,
                ptr::null_mut(),
                KernelMode as _,
                &mut handle,
            )
        })?;

        Ok(ObjectHandle(NonNull::new(handle).unwrap()))
    }
}

impl CloseHandle for ObjectHandle {
    fn close(&self) {
        let _ = unsafe { ZwClose(self.0.as_ptr()) };
    }
}

impl Drop for ObjectHandle {
    fn drop(&mut self) {
        self.close();
    }
}

/// A generic owned handle that close the underlying `HANDLE` using `CloseHandle`
///
/// useful for these customized handle types that implement `AsRawHandle` and `CloseHandle`
#[repr(transparent)]
pub struct OwnedHandle<T: CloseHandle>(T);

impl<T: CloseHandle> OwnedHandle<T> {
    pub const fn new(value: T) -> Self {
        Self(value)
    }
}

impl<T: CloseHandle> Deref for OwnedHandle<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: CloseHandle> DerefMut for OwnedHandle<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: CloseHandle> Drop for OwnedHandle<T> {
    fn drop(&mut self) {
        self.0.close();
    }
}
