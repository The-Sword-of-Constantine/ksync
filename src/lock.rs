//! this mod provide wrappers for c++ like std::unique_lock and std::shared_lock
//! the Mutex is atomically unlocked with RAII
//! NOTE:
//! this mod only implements the `unique lock` and `shared lock` primitives
//! modern rust users should use `Mutex` instead

use crate::mutex::Mutex;

/// a c++ like unique_lock wrapper for standalone usage
/// # Example
/// ```
/// // define some struct
/// struct Data {
///     a: u8,
///     b: u16,
///     c: u32,
///     d: u64,
///     // this lock is only used to protect member `c` and `d`
///     lock: FastMutex
/// }
///
/// let data = Data{ a: 0, b: 0, c: 0, d: 0, lock: FastMutex::new() }
///
/// // create a lock guard(using if let statement here is cheap)
/// // the UniqueLock::new() is designed to return Ok() always
/// if let Ok(_) = UniqueLock::new(&data.lock) {
///     data.c += 1;
///     data.d += 1;
/// } // the unique lock is released just after `guard` is out of its scope
///
/// ```
pub struct UniqueLock<'a, T: Mutex> {
    inner: &'a T,
}

impl<'a, T: Mutex> UniqueLock<'a, T> {
    pub fn new(locker: &'a T) -> Result<Self, ()> {
        locker.lock();
        Ok(Self { inner: locker })
    }
}

impl<T: Mutex> Drop for UniqueLock<'_, T> {
    fn drop(&mut self) {
        self.inner.unlock();
    }
}

/// a c++ like shared_lock wrapper for standalone usage
/// # Example
/// ```
/// // define some struct
/// struct Data {
///     a: u8,
///     b: u16,
///     c: u32,
///     d: u64,
///     // this lock is only used to protect member `c` and `d`
///     lock: ResourceMutex
/// }
///
/// let data = Data{ a: 0, b: 0, c: 0, d: 0, lock: ResourceLock::new() }
///
/// // create a lock guard(using if let statement here is cheap)
/// // the SharedLock::new() is designed to return Ok() always
/// if let Ok(_) = SharedLock::new(&data.lock) {
///     data.c += 1;
///     data.d += 1;
/// } // the unique lock is released just after `guard` is out of its scope
///
/// ```
pub struct SharedLock<'a, T: Mutex> {
    inner: &'a T,
}

impl<'a, T: Mutex> SharedLock<'a, T> {
    pub fn new(locker: &'a T) -> Result<Self, ()> {
        locker.lock_shared();
        Ok(Self { inner: locker })
    }
}

impl<T: Mutex> Drop for SharedLock<'_, T> {
    fn drop(&mut self) {
        self.inner.unlock_shared();
    }
}
