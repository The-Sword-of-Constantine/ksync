use core::{
    mem::{self},
    ptr,
};

use alloc::boxed::Box;
use wdk_sys::{
    _KDPC,
    _POOL_TYPE::NonPagedPoolNx,
    ALL_PROCESSOR_GROUPS, PKDPC, PVOID, STATUS_INSUFFICIENT_RESOURCES,
    ntddk::{
        ExFreePoolWithTag, KeInitializeDpc, KeInitializeThreadedDpc, KeInsertQueueDpc,
        KeQueryActiveProcessorCountEx, KeSetTargetProcessorDpc,
    },
};

use crate::{
    ntstatus::{NtError, Result},
    utils::ex_allocate_pool_zero,
};

const DPC_TAG: u32 = u32::from_ne_bytes(*b"cpdk");

/// A owned Ordinary DPC
///
/// keep DPC resident in memory until dropped user, can re-insert this DPC repeatedly
#[repr(transparent)]
pub struct Dpc(PKDPC);

impl Dpc {
    pub fn new<F: Fn()>(f: F) -> Result<Self> {
        let layout = ex_allocate_pool_zero(NonPagedPoolNx, mem::size_of::<_KDPC>() as _, DPC_TAG);

        if layout.is_null() {
            return Err(NtError::new(STATUS_INSUFFICIENT_RESOURCES));
        }

        let callback = Box::new(f);

        unsafe {
            KeInitializeDpc(
                layout.cast(),
                Some(deferred_routine_stub::<F>),
                Box::into_raw(callback).cast(),
            );
        }

        Ok(Self(layout.cast()))
    }

    pub fn get(&self) -> PKDPC {
        self.0
    }

    pub fn set_affinity(&self, core: u32) {
        unsafe {
            KeSetTargetProcessorDpc(self.0, core as _);
        }
    }

    pub fn activate(&self) {
        unsafe {
            KeInsertQueueDpc(self.0, ptr::null_mut(), ptr::null_mut());
        }
    }
}

impl Drop for Dpc {
    fn drop(&mut self) {
        unsafe {
            ExFreePoolWithTag(self.0.cast(), DPC_TAG);
        }
    }
}

/// A owned Threaded DPC
///
/// keep DPC resident in memory until dropped, user can re-insert this DPC repeatedly
#[repr(transparent)]
pub struct ThreadedDpc(PKDPC);

impl ThreadedDpc {
    pub fn new<F: Fn()>(f: F) -> Result<Self> {
        let layout = ex_allocate_pool_zero(NonPagedPoolNx, mem::size_of::<_KDPC>() as _, DPC_TAG);

        if layout.is_null() {
            return Err(NtError::new(STATUS_INSUFFICIENT_RESOURCES));
        }

        let callback = Box::new(f);

        unsafe {
            KeInitializeThreadedDpc(
                layout.cast(),
                Some(deferred_routine_stub::<F>),
                Box::into_raw(callback).cast(),
            );
        }

        Ok(Self(layout.cast()))
    }

    pub fn get(&self) -> PKDPC {
        self.0
    }

    pub fn activate(&self) {
        unsafe {
            KeInsertQueueDpc(self.0, ptr::null_mut(), ptr::null_mut());
        }
    }
}

impl Drop for ThreadedDpc {
    fn drop(&mut self) {
        unsafe {
            ExFreePoolWithTag(self.0.cast(), DPC_TAG);
        }
    }
}

/// create a Ordinary DPC for "run only once" semantic
fn create_ordinary_dpc<F: FnOnce()>(f: F) -> Result<PKDPC> {
    let layout = ex_allocate_pool_zero(NonPagedPoolNx, mem::size_of::<_KDPC>() as _, DPC_TAG);

    if layout.is_null() {
        return Err(NtError::new(STATUS_INSUFFICIENT_RESOURCES));
    }

    let callback = Box::new(f);

    unsafe {
        KeInitializeDpc(
            layout.cast(),
            Some(deferred_routine_once_stub::<F>),
            Box::into_raw(callback).cast(),
        );
    }

    Ok(layout.cast())
}

/// create a Threaded DPC for "run only once" semantic
fn create_threaded_dpc<F: FnOnce()>(f: F) -> Result<PKDPC> {
    let layout = ex_allocate_pool_zero(NonPagedPoolNx, mem::size_of::<_KDPC>() as _, DPC_TAG);

    if layout.is_null() {
        return Err(NtError::new(STATUS_INSUFFICIENT_RESOURCES));
    }

    let callback = Box::new(f);

    unsafe {
        KeInitializeThreadedDpc(
            layout.cast(),
            Some(deferred_routine_once_stub::<F>),
            Box::into_raw(callback).cast(),
        );
    }

    Ok(layout.cast())
}

/// run a ordinary DPC only once
pub fn run_once<F: FnOnce() + 'static>(f: F) {
    if let Ok(dpc) = create_ordinary_dpc(f) {
        unsafe {
            KeInsertQueueDpc(dpc, ptr::null_mut(), ptr::null_mut());
        }
    }
}

/// run a ordinary DPC only once on specified `core`
pub fn run_once_core<F: FnOnce() + 'static>(f: F, core: u32) {
    if let Ok(dpc) = create_ordinary_dpc(f) {
        unsafe {
            KeSetTargetProcessorDpc(dpc, core as _);
            KeInsertQueueDpc(dpc, ptr::null_mut(), ptr::null_mut());
        }
    }
}

/// run a ordinary DPC on all CPU cores only once
pub fn run_once_per_core<F: Fn() + 'static>(f: F) {
    let num_cores = unsafe { KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS as _) };

    for i in 0..num_cores {
        if let Ok(dpc) = create_ordinary_dpc(&f) {
            unsafe {
                KeSetTargetProcessorDpc(dpc, i as _);
                KeInsertQueueDpc(dpc, ptr::null_mut(), ptr::null_mut());
            }
        }
    }
}

/// run a threaded DPC only once
pub fn run_once_threaded<F: FnOnce() + 'static>(f: F) {
    if let Ok(dpc) = create_threaded_dpc(f) {
        unsafe {
            KeInsertQueueDpc(dpc, ptr::null_mut(), ptr::null_mut());
        }
    }
}

/// DPC callback stub routine
extern "C" fn deferred_routine_stub<F: FnOnce()>(
    dpc: PKDPC,
    context: PVOID,
    arg1: PVOID,
    arg2: PVOID,
) {
    let callback: Box<F> = unsafe { Box::from_raw(mem::transmute::<_, *mut F>(context)) };

    callback();
}

extern "C" fn deferred_routine_once_stub<F: FnOnce()>(
    dpc: PKDPC,
    context: PVOID,
    arg1: PVOID,
    arg2: PVOID,
) {
    let callback: Box<F> = unsafe { Box::from_raw(mem::transmute::<_, *mut F>(context)) };

    callback();

    unsafe {
        ExFreePoolWithTag(dpc.cast(), DPC_TAG);
    }
}
