use core::{
    ptr::{self, NonNull},
    time::Duration,
};

use wdk::nt_success;
use wdk_sys::{
    _KPROCESS, _KTHREAD,
    _KWAIT_REASON::Executive,
    _MODE::KernelMode,
    GENERIC_ALL, HANDLE, LARGE_INTEGER, NTSTATUS, PEPROCESS, PETHREAD, PVOID, PsProcessType,
    PsThreadType, STATUS_ALERTED, STATUS_SUCCESS, STATUS_TIMEOUT, STATUS_USER_APC,
    ntddk::{
        KeWaitForSingleObject, ObReferenceObjectByHandle, ObfDereferenceObject,
        PsLookupProcessByProcessId, PsLookupThreadByThreadId,
    },
};

use crate::{
    handle::ObjectHandle,
    ntstatus::{NtError, cvt},
    raw::{AsRawHandle, AsRawObject},
};

#[repr(transparent)]
pub struct WaitResult(i32);

impl WaitResult {
    pub const fn new(status: NTSTATUS) -> Self {
        Self(status)
    }

    /// The wait was succeed
    #[inline]
    pub fn success(self) -> bool {
        self.0 == STATUS_SUCCESS
    }

    /// The wait was interrupted to deliver an alert to the calling thread
    #[inline]
    pub fn alerted(self) -> bool {
        self.0 == STATUS_ALERTED
    }

    /// The wait was interrupted to deliver a user asynchronous procedure call (APC) to the calling thread
    #[inline]
    pub fn apc_delivered(self) -> bool {
        self.0 == STATUS_USER_APC
    }

    /// wait timed out
    #[inline]
    pub fn timed_out(self) -> bool {
        self.0 == STATUS_TIMEOUT
    }
}

/// kernel dispatchable object must implement this trait, just like Process, Thread, Event, Semaphore, Timer etc.
pub trait Dispatchable: AsRawObject {
    fn wait(&self, alertable: bool) -> WaitResult {
        let status = unsafe {
            KeWaitForSingleObject(
                <Self as AsRawObject>::as_raw(self).cast(),
                Executive,
                KernelMode as _,
                alertable as u8,
                ptr::null_mut(),
            )
        };

        WaitResult::new(status)
    }

    fn wait_for(&self, ms: Duration, alertable: bool) -> WaitResult {
        let mut timeout = LARGE_INTEGER {
            QuadPart: -1 * ms.as_nanos() as i64 / 100,
        };

        let status = unsafe {
            KeWaitForSingleObject(
                <Self as AsRawObject>::as_raw(self).cast(),
                Executive,
                KernelMode as _,
                alertable as u8,
                &mut timeout,
            )
        };

        WaitResult::new(status)
    }
}

/// for a kernel object we must release the reference count when no needed
///
/// a owned kernel object must implement this trait, it will be called in `Drop`
pub trait Dereference: AsRawObject {
    fn release(&mut self) {
        let ptr = <Self as AsRawObject>::as_raw(self);

        unsafe { ObfDereferenceObject(ptr.cast()); }
    }
}

/// A owned kernel object wrapper
#[repr(transparent)]
pub struct KernelObject<T>(NonNull<T>);
// pub struct KernelObject<T>(*mut T);

impl<T> KernelObject<T> {
    /// inner value should not be null
    pub fn new(value: *mut T) -> Self {
        Self(NonNull::new(value).unwrap())
    }

    pub fn as_ptr(&self) -> *mut T {
        self.0.as_ptr()
    }

    pub fn as_ref(&self) -> &T {
        unsafe { self.0.as_ref() }
    }

    pub fn as_mut(&mut self) -> &mut T {
        unsafe { self.0.as_mut() }
    }
}

/// convert from a raw system process HANDLE and take ownership of its underlying object
pub trait FromRawProcessHandle {
    fn from_process_handle(handle: HANDLE, access: u32)
    -> Result<KernelObject<_KPROCESS>, NtError>;
}

/// convert from a raw system process HANDLE and take ownership of its underlying object
pub trait FromRawThreadHandle {
    fn from_thread_handle(id: HANDLE, access: u32) -> Result<KernelObject<_KTHREAD>, NtError>;
}

pub trait FromProcessId {
    fn from_process_id(id: HANDLE) -> Result<KernelObject<_KPROCESS>, NtError>;
}

pub trait FromThreadId {
    fn from_thread_id(id: HANDLE) -> Result<KernelObject<_KTHREAD>, NtError>;
}

impl FromRawProcessHandle for KernelObject<_KPROCESS> {
    fn from_process_handle(
        handle: HANDLE,
        access: u32,
    ) -> Result<KernelObject<_KPROCESS>, NtError> {
        let mut value: PVOID = ptr::null_mut();

        let status = unsafe {
            ObReferenceObjectByHandle(
                handle,
                access,
                *PsProcessType,
                KernelMode as _,
                &mut value,
                ptr::null_mut(),
            )
        };

        if !nt_success(status) {
            return Err(NtError::from(status));
        }

        Ok(KernelObject::new(value.cast()))
    }
}

impl FromRawThreadHandle for KernelObject<_KTHREAD> {
    fn from_thread_handle(h: HANDLE, access: u32) -> Result<KernelObject<_KTHREAD>, NtError> {
        let mut value: PVOID = ptr::null_mut();

        let status = unsafe {
            ObReferenceObjectByHandle(
                h,
                access,
                *PsThreadType,
                KernelMode as _,
                &mut value,
                ptr::null_mut(),
            )
        };

        if !nt_success(status) {
            return Err(NtError::from(status));
        }

        Ok(KernelObject::new(value.cast()))
    }
}

// specialize for type ObjectRef<_KPROCESS>
impl FromProcessId for KernelObject<_KPROCESS> {
    fn from_process_id(id: HANDLE) -> Result<KernelObject<_KPROCESS>, NtError> {
        let mut value: PEPROCESS = ptr::null_mut();

        unsafe {
            let status = PsLookupProcessByProcessId(id, &mut value);

            if !nt_success(status) {
                return Err(NtError::from(status));
            }
        }

        Ok(KernelObject::new(value))
    }
}

// specialize for type ObjectRef<_KTHREAD>
impl FromThreadId for KernelObject<_KTHREAD> {
    fn from_thread_id(id: HANDLE) -> Result<KernelObject<_KTHREAD>, NtError> {
        let mut value: PETHREAD = ptr::null_mut();

        unsafe {
            let status = PsLookupThreadByThreadId(id, &mut value);

            if !nt_success(status) {
                return Err(NtError::from(status));
            }
        }

        Ok(KernelObject::new(value))
    }
}

/// kernel object from a owned kernel handle, take ownership of its underlying object, error may emitted
pub trait FromOwnedHandle {
    type Target;

    fn from_handle(handle: &ObjectHandle) -> Result<KernelObject<Self::Target>, NtError>;
}

impl<T> AsRawObject for KernelObject<T> {
    type Target = T;
    fn as_raw(&self) -> *mut Self::Target {
        self.0.as_ptr()
    }
}

// implement `Dispatchable`
impl Dispatchable for KernelObject<_KPROCESS> {}

// implement `Dispatchable`
impl Dispatchable for KernelObject<_KTHREAD> {}

// implement `Dereference` for all `T`
impl<T> Dereference for KernelObject<T> {}

impl<T> FromOwnedHandle for KernelObject<T> {
    type Target = T;

    fn from_handle(handle: &ObjectHandle) -> Result<KernelObject<Self::Target>, NtError> {
        let mut object: *mut core::ffi::c_void = ptr::null_mut();

        let status = unsafe {
            ObReferenceObjectByHandle(
                handle.as_raw(),
                GENERIC_ALL,
                ptr::null_mut(),
                KernelMode as _,
                &mut object,
                ptr::null_mut(),
            )
        };

        cvt(status)?;

        Ok(KernelObject::new(object.cast()))
    }
}

impl<T> Drop for KernelObject<T> {
    fn drop(&mut self) {
        self.release();
    }
}

pub type ProcessObject = KernelObject<_KPROCESS>;
pub type ThreadObject = KernelObject<_KTHREAD>;
