use core::{mem, ptr};

use alloc::boxed::Box;
use wdk_sys::{
    _WORK_QUEUE_TYPE::DelayedWorkQueue,
    PDEVICE_OBJECT, PIO_WORKITEM, PVOID, STATUS_INSUFFICIENT_RESOURCES,
    ntddk::{IoAllocateWorkItem, IoFreeWorkItem, IoQueueWorkItemEx},
};

use crate::ntstatus::{NtError, Result};

/// Owned Active workitem wrapper
pub struct WorkItem {
    inner: PIO_WORKITEM,
    callback: Box<dyn Fn()>,
}

impl WorkItem {
    /// Create a workitem
    pub fn new<F: Fn() + 'static>(f: F, device: PDEVICE_OBJECT) -> Result<Self> {
        let workitem = unsafe { IoAllocateWorkItem(device) };

        if workitem.is_null() {
            return Err(NtError::new(STATUS_INSUFFICIENT_RESOURCES));
        }

        Ok(Self {
            inner: workitem,
            callback: Box::new(f),
        })
    }

    /// run it in system worker thread
    ///
    /// this method does a few tricks here, see the following comments
    pub fn activate(&self) {
        unsafe {
            // allocate context Box for WorkItem, it will store a 16 byte "fat pointer" extracted from `self.callback`
            // it will be dropped in context of `worker_routine_stub`
            let mut context = Box::new([0u8; mem::size_of::<&dyn Fn()>()]);

            // this is essentially a "fat pointer" with 16 bytes on stack
            let callback = self.callback.as_ref();

            // copy 16 bytes "fat pointer" into a Box of [u8; 16]
            ptr::write(context.as_mut_ptr() as _, callback);

            // pass the raw pointer of [u8; 16] to native API
            IoQueueWorkItemEx(
                self.inner,
                Some(worker_routine_stub),
                DelayedWorkQueue,
                Box::into_raw(context) as _,
            );
        }
    }

    /// post a worker into system thread directly, it manage memory automatically
    pub fn post<F: FnOnce() + 'static>(f: F, device: PDEVICE_OBJECT) -> Result<()> {
        let callback = Box::new(f);

        let workitem = unsafe { IoAllocateWorkItem(device) };

        if workitem.is_null() {
            return Err(NtError::new(STATUS_INSUFFICIENT_RESOURCES));
        }

        unsafe {
            IoQueueWorkItemEx(
                workitem,
                Some(worker_routine_oneshot_stub::<F>),
                DelayedWorkQueue,
                Box::into_raw(callback) as _,
            );
        }

        Ok(())
    }
}

extern "C" fn worker_routine_oneshot_stub<F: FnOnce()>(
    IoObject: PVOID,
    Context: PVOID,
    IoWorkItem: PIO_WORKITEM,
) {
    let callback = unsafe { Box::from_raw(mem::transmute::<_, *mut F>(Context)) };

    callback();

    unsafe {
        IoFreeWorkItem(IoWorkItem.cast());
    }
}

/// [1] Potential bugs here
/// since we pass down a Box of [u8; 16] here, so we ***MUST*** free it "as it is".
/// ***DO NOT*** do something like this:
/// ```
/// let _ = unsafe { Box::from_raw(mem::transmute::<_, *mut &dyn Fn()>(Context)) };
/// ```
/// Box will try to free whatever inside as a type of `dyn Fn()` thus free the `callback` registered in `WorkItem::new()`, that's not what we want to see
/// It will cause double-free bug here, as the owned type `WorkItem` also stores a copy of `callback`.
///
/// # The Internals - How Box construct and destruct the *dyn* type
/// ## Construction
/// `Box` construct the `dyn T` using the following three steps
/// - construct the T on the heap which means allocate memory on heap and construct it in place
/// - construct a "fat pointer" that consist of two normal pointers, one is pointed to `T` itself and the other is pointed to the `vtable` of `T`
/// - after all this is done, store the "fat pointer" into Box itself, it now contains only the "fat pointer" and can be moved safely
///
/// ## Destruction
/// it happens whenn a `Box` goes out of its scope which means `drop` method of `Box` will be called, this has two steps
/// - `Box` extract second part of the "fat pointer" called "vtable pointer" and find a `drop` method in it, then call it with
/// first part of the "fat pointer" called "object pointer", like this: `drop(self)`
/// - finally `Box` will try to free the memory of object pointer occupied, leave the vtable pointer unchanged(it is allocated in .text section, free is not necessary)
///
/// # NoteWorthy
/// - the drop progress of a `Box` may changed depends on `T`, as we can see a `dyn` type is "special" in construction / destruction of a `Box`.
/// non-dyn types are easy to construct & destruct
/// - a `*mut dyn T` type do not has the same memory layout of a regular raw pointer(*mut _), it is just a syntax sugar for "a pointer to a dyn type"
/// it essentailly occupy 16 bytes in memory, the same as `&mut dyn T`, but this is not the case as `*mut &dyn T` which is treat same as a raw pointer,
/// that is why we can get variable of `&mut dyn T` that occupy 16 bytes on stack while we can also get a raw pointer variable of `*mut &dyn T` that points to it
extern "C" fn worker_routine_stub(IoObject: PVOID, Context: PVOID, IoWorkItem: PIO_WORKITEM) {
    let callback = unsafe { mem::transmute::<_, *mut &dyn Fn()>(Context) };

    unsafe { (*callback)() };

    // destroy `Context`
    // see comments above [1]
    let _ = unsafe { Box::from_raw(Context as *mut [u8; mem::size_of::<&dyn Fn()>()]) };
}
