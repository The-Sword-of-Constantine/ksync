use crate::{
    ntstatus::{NtError, Result, cvt},
    utils::ex_allocate_pool_zero,
};
use core::{
    cell::UnsafeCell,
    fmt::{Debug, Display},
    mem::{self},
    ops::{Deref, DerefMut},
    ptr::{self, NonNull, drop_in_place},
};
use wdk_sys::{
    _EVENT_TYPE::SynchronizationEvent,
    _POOL_TYPE::NonPagedPoolNx,
    APC_LEVEL, DISPATCH_LEVEL, ERESOURCE, FALSE, FAST_MUTEX, FM_LOCK_BIT, KGUARDED_MUTEX, KIRQL,
    KLOCK_QUEUE_HANDLE, KSPIN_LOCK, PKLOCK_QUEUE_HANDLE, PVOID, SIZE_T,
    STATUS_INSUFFICIENT_RESOURCES, STATUS_SUCCESS, STATUS_UNSUCCESSFUL, TRUE, ULONG,
    ntddk::{
        ExAcquireFastMutex, ExAcquireResourceExclusiveLite, ExAcquireResourceSharedLite,
        ExDeleteResourceLite, ExFreePoolWithTag, ExInitializeResourceLite, ExReleaseFastMutex,
        ExReleaseResourceLite, ExTryToAcquireFastMutex, KeAcquireGuardedMutex,
        KeAcquireInStackQueuedSpinLock, KeAcquireInStackQueuedSpinLockAtDpcLevel,
        KeAcquireSpinLockAtDpcLevel, KeAcquireSpinLockRaiseToDpc, KeGetCurrentIrql,
        KeInitializeEvent, KeInitializeGuardedMutex, KeInitializeSpinLock, KeReleaseGuardedMutex,
        KeReleaseInStackQueuedSpinLock, KeReleaseInStackQueuedSpinLockFromDpcLevel,
        KeReleaseSpinLock, KeReleaseSpinLockFromDpcLevel, KeTryToAcquireGuardedMutex,
        KeTryToAcquireSpinLockAtDpcLevel, memset,
    },
};

fn ExInitializeFastMutex(fast_mutex: *mut FAST_MUTEX) {
    unsafe {
        core::ptr::write_volatile(&mut (*fast_mutex).Count, FM_LOCK_BIT as i32);

        (*fast_mutex).Owner = core::ptr::null_mut();
        (*fast_mutex).Contention = 0;
        KeInitializeEvent(&mut (*fast_mutex).Event, SynchronizationEvent, FALSE as _)
    }
}

const MUTEX_TAG: ULONG = u32::from_ne_bytes(*b"xetm");

pub trait Mutex {
    type Target: Mutex;

    fn init(&self) -> Result<()>;

    fn shareable() -> bool {
        false
    }

    fn lock(&self);

    fn try_lock(&self) -> bool {
        unimplemented!("try_lock")
    }

    fn lock_shared(&self) {
        unimplemented!("lock_shared")
    }

    fn try_lock_shared(&self) -> bool {
        unimplemented!("try_lock_shared")
    }

    fn unlock_shared(&self) {
        unimplemented!("unlock_shared")
    }

    fn unlock(&self);

    fn irql_ok() -> bool {
        return unsafe { KeGetCurrentIrql() <= APC_LEVEL as u8 };
    }
}

pub trait QueuedMutex {
    type Target: QueuedMutex;

    fn init(&mut self) -> Result<()>;

    fn lock(&self, handle: PKLOCK_QUEUE_HANDLE);

    fn unlock(&self, handle: PKLOCK_QUEUE_HANDLE);

    fn irql_ok() -> bool {
        return unsafe { KeGetCurrentIrql() <= DISPATCH_LEVEL as u8 };
    }
}

pub struct EmptyMutex;

#[repr(transparent)]
pub struct FastMutex(UnsafeCell<FAST_MUTEX>);

#[repr(transparent)]
pub struct GuardedMutex(UnsafeCell<KGUARDED_MUTEX>);

#[repr(transparent)]
pub struct ResourceMutex(UnsafeCell<ERESOURCE>);

#[repr(transparent)]
pub struct SpinMutex(UnsafeCell<SpinLockInner>);

impl Mutex for EmptyMutex {
    type Target = Self;

    fn init(&self) -> Result<()> {
        Ok(())
    }

    fn lock(&self) {}

    fn unlock(&self) {}
}

impl Mutex for FastMutex {
    type Target = Self;

    fn init(&self) -> Result<()> {
        ExInitializeFastMutex(self.0.get());
        Ok(())
    }

    fn try_lock(&self) -> bool {
        unsafe { ExTryToAcquireFastMutex(self.0.get()) != 0 }
    }

    fn lock(&self) {
        unsafe {
            ExAcquireFastMutex(self.0.get());
        }
    }

    fn unlock(&self) {
        unsafe { ExReleaseFastMutex(self.0.get()) };
    }
}

impl Mutex for GuardedMutex {
    type Target = Self;

    fn init(&self) -> Result<()> {
        unsafe { KeInitializeGuardedMutex(self.0.get()) };
        Ok(())
    }

    fn try_lock(&self) -> bool {
        unsafe { KeTryToAcquireGuardedMutex(self.0.get()) != 0 }
    }

    fn lock(&self) {
        unsafe {
            KeAcquireGuardedMutex(self.0.get());
        }
    }

    fn unlock(&self) {
        unsafe { KeReleaseGuardedMutex(self.0.get()) };
    }
}

impl Mutex for ResourceMutex {
    type Target = Self;

    fn init(&self) -> Result<()> {
        cvt(unsafe { ExInitializeResourceLite(self.0.get()) })
    }

    fn shareable() -> bool {
        true
    }

    fn try_lock(&self) -> bool {
        unsafe { ExAcquireResourceExclusiveLite(self.0.get(), FALSE as _) != 0 }
    }

    fn lock(&self) {
        unsafe {
            ExAcquireResourceExclusiveLite(self.0.get(), TRUE as _);
        }
    }

    fn unlock(&self) {
        unsafe { ExReleaseResourceLite(self.0.get()) };
    }

    fn try_lock_shared(&self) -> bool {
        unsafe { ExAcquireResourceSharedLite(self.0.get(), FALSE as _) != 0 }
    }

    fn lock_shared(&self) {
        unsafe {
            ExAcquireResourceSharedLite(self.0.get(), TRUE as _);
        }
    }

    fn unlock_shared(&self) {
        unsafe {
            ExReleaseResourceLite(self.0.get());
        }
    }
}

impl Drop for ResourceMutex {
    fn drop(&mut self) {
        unsafe {
            let _ = ExDeleteResourceLite(self.0.get());
        }
    }
}

struct SpinLockInner {
    irql: KIRQL,
    lock: KSPIN_LOCK,
}

impl Mutex for SpinMutex {
    type Target = Self;

    fn init(&self) -> Result<()> {
        unsafe {
            (*self.0.get()).irql = 0;
            KeInitializeSpinLock(&mut (*self.0.get()).lock);
        }

        Ok(())
    }

    fn try_lock(&self) -> bool {
        if unsafe { KeGetCurrentIrql() } == DISPATCH_LEVEL as _ {
            unsafe { KeTryToAcquireSpinLockAtDpcLevel(&mut (*self.0.get()).lock) != 0 }
        } else {
            false
        }
    }

    /// a spin lock can be used in IRQL >= DISPATCH_LEVEL and a more efficient function provided by Microsoft
    ///
    /// see https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keacquirespinlockatdpclevel for details
    fn lock(&self) {
        unsafe {
            let inner = &mut (*self.0.get());

            let irql = KeGetCurrentIrql();

            if irql >= DISPATCH_LEVEL as _ {
                KeAcquireSpinLockAtDpcLevel(&mut inner.lock);
            } else {
                inner.irql = KeAcquireSpinLockRaiseToDpc(&mut inner.lock);
            }
        }
    }

    fn unlock(&self) {
        unsafe {
            let inner = &mut (*self.0.get());

            let irql = KeGetCurrentIrql();

            if irql >= DISPATCH_LEVEL as _ {
                KeReleaseSpinLockFromDpcLevel(&mut inner.lock);
            } else {
                KeReleaseSpinLock(&mut inner.lock, inner.irql);
            }
        }
    }

    /// a spin lock can safely be held at any IRQL
    fn irql_ok() -> bool {
        true
    }
}

impl QueuedMutex for QueuedSpinMutex {
    type Target = Self;

    fn init(&mut self) -> Result<()> {
        unsafe { KeInitializeSpinLock(self.0.get_mut()) }
        Ok(())
    }

    /// a queued spin lock can be safely held at IRQL >= DISPATCH_LEVEL
    ///
    /// see https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keacquireinstackqueuedspinlockatdpclevel for details
    fn lock(&self, handle: PKLOCK_QUEUE_HANDLE) {
        let irql = unsafe { KeGetCurrentIrql() };

        if irql >= DISPATCH_LEVEL as _ {
            unsafe {
                KeAcquireInStackQueuedSpinLockAtDpcLevel(self.0.get(), handle);
            }
        } else {
            unsafe { KeAcquireInStackQueuedSpinLock(self.0.get(), handle) }
        }
    }

    fn unlock(&self, handle: PKLOCK_QUEUE_HANDLE) {
        let irql = unsafe { KeGetCurrentIrql() };

        if irql >= DISPATCH_LEVEL as _ {
            unsafe {
                KeReleaseInStackQueuedSpinLockFromDpcLevel(handle);
            }
        } else {
            unsafe { KeReleaseInStackQueuedSpinLock(handle) };
        }
    }

    /// a queued spin lock can be safely held at any IRQL
    fn irql_ok() -> bool {
        true
    }
}

/// the internal layout for `Locked<T,M>`
///
/// this has the same layout as `QueuedInnerData`
struct InnerData<T, M: Mutex> {
    mutex: M::Target,
    data: T,
}

/// a strategy lock wrapper for FastMutex, GuardMutex, Spinlock, Resources
///
/// it is used combined with FastMutex, GuardedMutex, SpinMutex, and ResourceMutex types
///
/// see https://doc.rust-lang.org/std/sync/struct.Mutex.html for details
///
/// # Example
/// - unique access
/// ```
/// let shared_counter = FastLocked::new(0u32).unwrap();
/// if let Ok(mut counter) = shared_counter.lock {
///     *counter += 1;
/// }
/// ```
/// - shared access, `M` must implement shared operations
/// ```
/// let shared_counter = FastLocked::new(0u32).unwrap();
/// if let Ok(counter) = shared_counter.lock_shared() {
///     println!("counter = {}", counter);
/// }
/// ```
///
/// - dereference
/// ```
/// let shared_counter = FastLocked::new(0u32).unwrap();
/// println!("counter = {}", *shared_counter);
/// ```
#[repr(transparent)]
pub struct Locked<T, M>
where
    M: Mutex,
{
    inner: NonNull<InnerData<T, M>>,
}

impl<T, M: Mutex> Locked<T, M> {
    pub fn new(data: T) -> Result<Self> {
        let layout = ex_allocate_pool_zero(
            NonPagedPoolNx,
            mem::size_of::<InnerData<T, M>>() as _,
            MUTEX_TAG,
        ) as *mut InnerData<T, M>;

        if layout.is_null() {
            return Err(STATUS_INSUFFICIENT_RESOURCES.into());
        }

        // initialize underlying mutex
        unsafe { (&(*layout).mutex).init()? };

        // unsafe { layout.as_mut().unwrap().mutex.init() }?;

        unsafe {
            // Rust does not actually "move" the `InnerData` into the memory location where the raw pointer `layout` points to
            // it copy it instead and then call the drop on temporary `InnerData`
            // yes this is a trap here, that's why we use a `ptr::write` to ensure the temporary `InnerData` will
            // not be dropped upon it goes out of scope, since we will drop it manually in `Locked::drop()`
            // The following code is wrong, the temporary `InnerData` will be droppd in place which is not we want
            //*layout = InnerData { ... }
            ptr::write(&mut (*layout).data, data);
        };

        Ok(Self {
            inner: NonNull::new(layout).expect("can not allocate memory for Locked<T,M>"),
        })
    }

    /// Returns a mutable reference to the underlying data.
    ///
    /// # Safety
    /// Since this call borrows the Mutex mutably, no actual locking needs to take place – the mutable borrow statically guarantees no locks exist.
    /// a `&mut T` can not be used across thread bound, since `thread::spawn` requires `FnOne() + 'static`
    pub fn get_mut(&mut self) -> &mut T {
        unsafe { &mut self.inner.as_mut().data }
    }

    /// Set the inner value with `value`
    pub fn set(&mut self, value: T) {
        unsafe { self.inner.as_mut().data = value }
    }

    pub fn get_cloned(&self) -> Result<T>
    where
        T: Clone,
    {
        self.lock().map(|v| v.clone())
    }

    /// returns a `MutexGuard` for exclusive access
    ///
    /// the caller can gain a mutable or immutable ref to `T` through `MutexGuard`</br>
    /// the `MutexGuard` implement both `Deref` and `DerefMut` to ensure this
    pub fn lock(&self) -> Result<MutexGuard<'_, true, T, M>> {
        if !M::irql_ok() {
            Err(NtError::from(STATUS_UNSUCCESSFUL))
        } else {
            Ok(MutexGuard::new(self))
        }
    }

    /// returns a `MutexGuard` for shared access
    ///
    /// the caller can only gain a immutable ref of `T` through `MutexGuard`
    ///
    /// ***NOTE***:
    ///
    /// maybe we need a some type like `SharedMutexGuard` that only implements `Deref`?
    /// but i think using compile-time constant here is a good choice
    pub fn lock_shared(&self) -> Result<MutexGuard<'_, false, T, M>> {
        if !M::irql_ok() {
            Err(NtError::from(STATUS_UNSUCCESSFUL))
        } else {
            // this is a wrong usage of a unshareable Mutex, we can not get a `shareable` MutexGuard from a `unshareable` Mutex
            // the result of M::shareable() will be optmized as compile-time constant, so it is zero-cost
            if !M::shareable() {
                #[cfg(debug_assertions)]
                panic!("Can not call lock_shared on a unshareable Mutex");

                Err(NtError::from(STATUS_UNSUCCESSFUL))
            } else {
                Ok(MutexGuard { locker: self })
            }
        }
    }
}

impl<T, M> Default for Locked<T, M>
where
    T: Default,
    M: Mutex,
{
    fn default() -> Self {
        let layout = ex_allocate_pool_zero(
            NonPagedPoolNx,
            mem::size_of::<InnerData<T, M>>() as _,
            MUTEX_TAG,
        ) as *mut InnerData<T, M>;

        if layout.is_null() {
            panic!("No Sufficient Memory")
        }

        unsafe {
            let _ = layout
                .as_mut()
                .unwrap()
                .mutex
                .init()
                .inspect_err(|_| panic!("Mutex failed to initialize"));
            layout.as_mut().unwrap().data = Default::default();
        };

        Self {
            inner: NonNull::new(layout).unwrap(),
        }
    }
}

impl<T, M: Mutex> Deref for Locked<T, M> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { &self.inner.as_ref().data }
    }
}

// FIXME: get a mutable reference from a `Locked<T>` is not safe
impl<T, M: Mutex> DerefMut for Locked<T, M> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut self.inner.as_mut().data }
    }
}

impl<T, M: Mutex> Drop for Locked<T, M> {
    fn drop(&mut self) {
        unsafe {
            drop_in_place(&mut self.inner.as_mut().data);

            drop_in_place(&mut self.inner.as_mut().mutex);

            ExFreePoolWithTag(self.inner.as_ptr().cast(), MUTEX_TAG);
        }
    }
}

impl<T: Display, M: Mutex> Debug for Locked<T, M> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Locked{{{}}}", unsafe { &(*self.inner.as_ptr()).data })
    }
}

/// An RAII implementation of a "scoped lock" of a mutex. When this structure is
/// dropped (falls out of scope), the lock will be unlocked.
///
/// # Parameters
/// - EXCLUSIVE: indicates if the lock should be held exclusive
/// - T: the procted data type
/// - M: the underlying mutex
///
/// # SAFETY
/// the protected `T` can be borrowed as mutable only if the lock can be held exclusively</br>
/// otherwise it is an error and the `DerefMut()` will panic
pub struct MutexGuard<'a, const EXCLUSIVE: bool, T, M: Mutex> {
    locker: &'a Locked<T, M>,
}

impl<'a, const EXCLUSIVE: bool, T, M: Mutex> MutexGuard<'a, EXCLUSIVE, T, M> {
    fn new(locker: &'a Locked<T, M>) -> Self {
        if EXCLUSIVE {
            unsafe { (*locker.inner.as_ptr()).mutex.lock() };
        } else {
            unsafe { (*locker.inner.as_ptr()).mutex.lock_shared() }
        }

        Self { locker }
    }
}

impl<'a, const EXCLUSIVE: bool, T, M: Mutex> Deref for MutexGuard<'a, EXCLUSIVE, T, M> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { &self.locker.inner.as_ref().data }
    }
}

impl<'a, const EXCLUSIVE: bool, T, M: Mutex> DerefMut for MutexGuard<'a, EXCLUSIVE, T, M> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: we can get a mut ref of `T` only when MutexGuard is `locked` exclusively
        // otherwise fail the operation
        if EXCLUSIVE {
            unsafe { &mut (*self.locker.inner.as_ptr()).data }
        } else {
            panic!("can not get a mutable ref of `T` when the lock is not held exclusively");
        }
    }
}

impl<'a, const EXCLUSIVE: bool, T, M: Mutex> Drop for MutexGuard<'a, EXCLUSIVE, T, M> {
    fn drop(&mut self) {
        unsafe {
            if EXCLUSIVE {
                (*self.locker.inner.as_ptr()).mutex.unlock();
            } else {
                (*self.locker.inner.as_ptr()).mutex.unlock_shared();
            }
        }
    }
}

pub struct QueuedEmptyMutex;

impl QueuedMutex for QueuedEmptyMutex {
    type Target = Self;

    fn init(&mut self) -> Result<()> {
        Ok(())
    }

    fn lock(&self, _handle: PKLOCK_QUEUE_HANDLE) {
    }

    fn unlock(&self, _handle: PKLOCK_QUEUE_HANDLE) {
    }
}

/// see `SpinMutex` for details
#[repr(transparent)]
pub struct QueuedSpinMutex(UnsafeCell<KSPIN_LOCK>);

struct QueuedInnerData<T, M: QueuedMutex> {
    mutex: M::Target,
    data: T,
}

/// a strategy lock wrapper for Queued Spin Locks
///
/// a Queued Spin Lock is a special spin lock that can improve system performance, see
/// https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/queued-spin-locks for details
///
/// # Example
/// ```
/// let mut handle = LockedQuueHandle::new();
/// if let Ok(mut counter) = shared_counter.lock(&mut handle) {
///     *counter += 1;
/// }
/// ```
#[repr(transparent)]
pub struct StackQueueLocked<T, M: QueuedMutex> {
    inner: NonNull<QueuedInnerData<T, M>>,
}

impl<T, M: QueuedMutex> StackQueueLocked<T, M> {
    pub fn new(data: T) -> Result<Self> {
        let layout = ex_allocate_pool_zero(
            NonPagedPoolNx,
            mem::size_of::<QueuedInnerData<T, M>>() as _,
            MUTEX_TAG,
        ) as *mut QueuedInnerData<T, M>;

        if layout.is_null() {
            return Err(STATUS_INSUFFICIENT_RESOURCES.into());
        }

        unsafe { layout.as_mut().unwrap().mutex.init() }?;

        unsafe {
            ptr::write(&mut (*layout).data, data);
        }

        Ok(Self {
            inner: NonNull::new(layout).unwrap(),
        })
    }

    pub fn get_mut(&mut self) -> &mut T {
        unsafe { &mut self.inner.as_mut().data }
    }

    pub fn set(&mut self, value: T) {
        unsafe { self.inner.as_mut().data = value };
    }

    pub fn get_cloned(&self) -> Result<T>
    where
        T: Clone,
    {
        let mut handle = LockedQuueHandle::new();

        self.lock(&mut handle).map(|v| v.clone())
    }

    pub fn lock<'a>(
        &'a self,
        handle: &'a mut LockedQuueHandle,
    ) -> Result<InStackMutexGuard<'a, T, M>> {
        if !M::irql_ok() {
            Err(NtError::from(STATUS_UNSUCCESSFUL))
        } else {
            unsafe { (*self.inner.as_ptr()).mutex.lock(&mut handle.0) };

            Ok(InStackMutexGuard {
                handle,
                locker: self,
            })
        }
    }
}

impl<T, M> Default for StackQueueLocked<T, M>
where
    T: Default,
    M: QueuedMutex,
{
    fn default() -> Self {
        let layout = ex_allocate_pool_zero(
            NonPagedPoolNx,
            mem::size_of::<QueuedInnerData<T, M>>() as _,
            MUTEX_TAG,
        ) as *mut QueuedInnerData<T, M>;

        if layout.is_null() {
            panic!("No Sufficient Memory")
        }

        unsafe {
            let _ = layout
                .as_mut()
                .unwrap()
                .mutex
                .init()
                .inspect_err(|_| panic!("Mutex failed to initialize"));
            layout.as_mut().unwrap().data = Default::default();
        };

        Self {
            inner: NonNull::new(layout).unwrap(),
        }
    }
}

impl<T, M: QueuedMutex> Deref for StackQueueLocked<T, M> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { &self.inner.as_ref().data }
    }
}

// FIXME: get a mutable reference from a `StackQueueLocked<T>` is not safe
impl<T, M: QueuedMutex> DerefMut for StackQueueLocked<T, M> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut self.inner.as_mut().data }
    }
}

impl<T: Display, M: QueuedMutex> Debug for StackQueueLocked<T, M> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "StackQueueLocked{{{}}}", unsafe {
            &(*self.inner.as_ptr()).data
        })
    }
}

impl<T, M: QueuedMutex> Drop for StackQueueLocked<T, M> {
    fn drop(&mut self) {
        unsafe {
            drop_in_place(&mut (*self.inner.as_ptr()).data);

            drop_in_place(&mut self.inner.as_mut().mutex);

            ExFreePoolWithTag(self.inner.as_ptr().cast(), MUTEX_TAG);
        }
    }
}

#[repr(transparent)]
pub struct LockedQuueHandle(KLOCK_QUEUE_HANDLE);

impl LockedQuueHandle {
    pub fn new() -> Self {
        Self(KLOCK_QUEUE_HANDLE::default())
    }
}

pub struct InStackMutexGuard<'a, T, M: QueuedMutex> {
    handle: &'a mut LockedQuueHandle,
    locker: &'a StackQueueLocked<T, M>,
}

impl<'a, T, M: QueuedMutex> Deref for InStackMutexGuard<'a, T, M> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &self.locker.inner.as_ref().data }
    }
}

impl<'a, T, M: QueuedMutex> DerefMut for InStackMutexGuard<'a, T, M> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut (*self.locker.inner.as_ptr()).data }
    }
}

impl<'a, T, M: QueuedMutex> Drop for InStackMutexGuard<'a, T, M> {
    fn drop(&mut self) {
        unsafe {
            (*self.locker.inner.as_ptr())
                .mutex
                .unlock(&mut self.handle.0);
        }
    }
}

unsafe impl<T: Send, M: Mutex> Send for Locked<T, M> {}
unsafe impl<T: Sync, M: Mutex> Sync for Locked<T, M> {}

unsafe impl<T: Send, M: QueuedMutex> Send for StackQueueLocked<T, M> {}
unsafe impl<T: Sync, M: QueuedMutex> Sync for StackQueueLocked<T, M> {}

pub type GuardLocked<T> = Locked<T, GuardedMutex>;
pub type FastLocked<T> = Locked<T, FastMutex>;
pub type ResourceLocked<T> = Locked<T, ResourceMutex>;
pub type SpinLocked<T> = Locked<T, SpinMutex>;
pub type InStackQueueLocked<T> = StackQueueLocked<T, QueuedSpinMutex>;
