use core::{mem, ptr, time::Duration};

use wdk_sys::{
    _KSEMAPHORE,
    _POOL_TYPE::NonPagedPoolNx,
    PRKSEMAPHORE, STATUS_INSUFFICIENT_RESOURCES,
    ntddk::{ExFreePoolWithTag, KeInitializeSemaphore, KeReadStateSemaphore, KeReleaseSemaphore},
};

use crate::{
    kobject::{Dispatchable, WaitResult},
    ntstatus::{NtError, Result},
    raw::AsRawObject,
    utils::ex_allocate_pool_zero,
};

const SEMA_TAG: u32 = u32::from_ne_bytes(*b"ames");

/// A kernel Semaphore object wrapper
#[repr(transparent)]
pub struct Semaphore(PRKSEMAPHORE);

impl Semaphore {
    /// allocate a new semaphore object on the kernel heap
    ///
    /// # Parameters
    /// - count: specifies the initial count value to be assigned to the semaphore. This value must be positive.
    ///  A nonzero value sets the initial state of the semaphore to signaled.
    /// - limit: specifies the maximum count value that the semaphore can attain.
    /// This value must be positive. It determines how many waiting threads become eligible for execution when the semaphore is
    /// set to the signaled state and can therefore access the resource that the semaphore protects.
    /// it is normaly be set to `thread::available_parallelism`
    pub fn new(count: i32, limit: i32) -> Result<Self> {
        let layout =
            ex_allocate_pool_zero(NonPagedPoolNx, mem::size_of::<_KSEMAPHORE>() as _, SEMA_TAG);

        if layout.is_null() {
            return Err(NtError::new(STATUS_INSUFFICIENT_RESOURCES));
        }

        unsafe {
            KeInitializeSemaphore(layout.cast(), count, limit);
        }

        Ok(Self(layout.cast()))
    }

    /// release the semaphore by `count`
    #[inline]
    pub fn release(&self, count: i32) {
        unsafe {
            KeReleaseSemaphore(self.0, 0, count, 0);
        }
    }

    /// see https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kereleasesemaphore for details
    #[inline]
    pub fn release_wait(&self, count: i32) -> WaitResult {
        unsafe {
            KeReleaseSemaphore(self.0, 0, count, 1);

            self.wait(false)
        }
    }

    #[inline]
    pub fn release_wait_for(&self, count: i32, time: Duration) -> WaitResult {
        unsafe {
            KeReleaseSemaphore(self.0, 0, count, 1);

            self.wait_for(time, false)
        }
    }

    /// read the state of this semaphore
    ///
    /// # Return value
    /// - true, the semaphore object is in signaled state
    /// - false, the semaphore object is in not-signaled state
    #[inline]
    pub fn get_state(&self) -> bool {
        unsafe { KeReadStateSemaphore(self.0) != 0 }
    }
}

impl AsRawObject for Semaphore {
    type Target = _KSEMAPHORE;
    fn as_raw(&self) -> *mut Self::Target {
        self.0
    }
}

impl Dispatchable for Semaphore {}

impl Drop for Semaphore {
    fn drop(&mut self) {
        unsafe {
            ExFreePoolWithTag(self.0.cast(), SEMA_TAG);
        }
    }
}

unsafe impl Send for Semaphore {}
unsafe impl Sync for Semaphore {}
