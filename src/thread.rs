use core::mem::MaybeUninit;
use core::num::NonZero;
use core::ops::{Deref, DerefMut};
use core::{mem, ptr};

use alloc::boxed::Box;
use wdk::nt_success;
use wdk_sys::LARGE_INTEGER;
use wdk_sys::ntddk::{KeQueryActiveProcessorCount, ObfDereferenceObject};
use wdk_sys::{
    _KWAIT_REASON::Executive,
    _MODE::KernelMode,
    _THREADINFOCLASS::ThreadBasicInformation,
    CLIENT_ID, FALSE, GENERIC_ALL, HANDLE, LONG, NTSTATUS, OBJ_KERNEL_HANDLE, PETHREAD, PULONG,
    PVOID, PsThreadType, STATUS_SUCCESS, THREAD_QUERY_LIMITED_INFORMATION, ULONG,
    ntddk::{KeWaitForSingleObject, ObReferenceObjectByHandle, PsCreateSystemThread, ZwClose},
};

use crate::NtCurrentProcess;
use crate::{
    initialize_object_attributes,
    ntstatus::{NtError, Result, cvt},
};

#[repr(C)]
pub struct THREAD_BASIC_INFORMATION {
    pub ExitStatus: LONG,
    pub TebBaseAddress: PVOID,
    pub ClientId: CLIENT_ID,
    pub AffinityMask: usize,
    pub Priority: LONG,
    pub BasePriority: LONG,
}

impl Default for THREAD_BASIC_INFORMATION {
    fn default() -> Self {
        unsafe { MaybeUninit::zeroed().assume_init() }
    }
}

unsafe extern "C" {
    pub fn ZwQueryInformationThread(
        ThreadHandle: HANDLE,
        ThreadInformationClass: ULONG,
        ThreadInformation: PVOID,
        ThreadInformationLength: ULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;

}

#[repr(transparent)]
pub struct OwnedHandle(HANDLE);

impl OwnedHandle {
    pub fn as_raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        let _ = unsafe { ZwClose(self.0) };
    }
}

impl Deref for OwnedHandle {
    type Target = HANDLE;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for OwnedHandle {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[repr(transparent)]
pub struct JoinHandle(OwnedHandle);

impl JoinHandle {
    pub fn is_finished(&self) -> bool {
        let mut thread: PVOID = ptr::null_mut();

        let mut status = unsafe {
            ObReferenceObjectByHandle(
                *self.0,
                THREAD_QUERY_LIMITED_INFORMATION,
                *PsThreadType,
                KernelMode as _,
                &mut thread,
                ptr::null_mut(),
            )
        };

        if !nt_success(status) {
            return false;
        }

        let mut timeout = LARGE_INTEGER { QuadPart: 0 };

        status = unsafe {
            KeWaitForSingleObject(
                thread,
                Executive as _,
                KernelMode as _,
                FALSE as _,
                &mut timeout,
            )
        };

        status == STATUS_SUCCESS
    }

    pub fn join(self) -> Result<NTSTATUS> {
        let mut thread: PVOID = ptr::null_mut();

        let mut status = unsafe {
            ObReferenceObjectByHandle(
                *self.0,
                THREAD_QUERY_LIMITED_INFORMATION,
                *PsThreadType,
                KernelMode as _,
                &mut thread,
                ptr::null_mut(),
            )
        };

        cvt(status)?;

        status = unsafe {
            KeWaitForSingleObject(
                thread,
                Executive as _,
                KernelMode as _,
                FALSE as _,
                ptr::null_mut(),
            )
        };

        cvt(status)?;

        unsafe { ObfDereferenceObject(thread) };

        // unconditionally set self.exit_status no matter a wait failure or a query failure occurrs
        let mut length: ULONG = 0;
        let mut info = THREAD_BASIC_INFORMATION::default();

        status = unsafe {
            ZwQueryInformationThread(
                *self.0,
                ThreadBasicInformation as _,
                &mut info as *mut _ as *mut _,
                mem::size_of::<THREAD_BASIC_INFORMATION>() as _,
                &mut length,
            )
        };

        cvt(status)?;

        Ok(info.ExitStatus)
    }
}

/// trampolion for `F`, using static binding here
///
/// `F` is inferred as `impl Fn` which rust know it exactly, it is essentially a function pointer.
/// so the call `ctx()` here will call the function pointer "passed in" from `spawn` method
extern "C" fn start_routine_stub<F: FnOnce()>(context: PVOID) {
    let ctx: Box<F> = unsafe { Box::from_raw(mem::transmute::<_, *mut F>(context)) };

    ctx();
}

pub fn available_parallelism() -> NonZero<usize> {
    let num_cores = unsafe { KeQueryActiveProcessorCount(ptr::null_mut()) };

    NonZero::new(num_cores as usize).unwrap()
}

pub fn spawn<F: FnOnce() + Send + 'static>(f: F) -> Result<JoinHandle> {
    let mut handle: HANDLE = ptr::null_mut();

    unsafe {
        let mut attr = initialize_object_attributes!(
            ptr::null_mut(),
            OBJ_KERNEL_HANDLE,
            ptr::null_mut(),
            ptr::null_mut()
        );

        // `F` is inferred as `impl Fn`
        let buf = Box::new(f);

        // Box will be dropped in `start_routine_stub::<F>`
        let context = Box::into_raw(buf);

        let status = PsCreateSystemThread(
            &mut handle,
            GENERIC_ALL,
            &mut attr,
            NtCurrentProcess,
            ptr::null_mut(),
            Some(start_routine_stub::<F>),
            context.cast(),
        );

        if !nt_success(status) {
            let _ = Box::from_raw(context);
            return Err(NtError::from(status));
        }
    }

    Ok(JoinHandle(OwnedHandle(handle)))
}

pub mod this_thread {
    use core::{arch::x86_64::_mm_pause, time::Duration};

    use wdk_sys::{
        _MODE::KernelMode,
        FALSE, LARGE_INTEGER, ULONG,
        ntddk::{KeDelayExecutionThread, PsGetCurrentThreadId},
    };

    use crate::handle_to_ulong;

    pub fn sleep(ms: Duration) {
        let mut timeout = LARGE_INTEGER {
            QuadPart: -1 * ms.as_nanos() as i64 / 100,
        };

        unsafe {
            let _ = KeDelayExecutionThread(KernelMode as i8, FALSE as u8, &mut timeout);
        }
    }

    pub fn pause() {
        unsafe { _mm_pause() };
    }

    pub fn id() -> u32 {
        unsafe { handle_to_ulong!(PsGetCurrentThreadId()) }
    }
}
