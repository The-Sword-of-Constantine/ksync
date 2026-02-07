//! this module provides OnceCell, OnceLock, LazyCell, LazyLock implementations
//! each has its own respective use cases, and they are different from the std one but acts mostly the same function as it
//!
//! `OnceCell`, `OnceLock` can all be used in where the initialization must be delayed out of object construction
//! while `LazyCell` and `LazyLock` can not
//!
//! they are all implemented with an associate `drop` method can be used to drop only once
//!
//! - `OnceCell`</br>
//! delayed initiazation out of construction
//! can be initialized only once in single thread</br>
//! can be safely used in multi-thread by get a shared reference to it if inner `T` is `Sync`</br>
//!
//! - `OnceLock`</br>
//! initialized when first accessed
//! can be safely initialized only once in multi-thread</br>
//! can be safely used in multi-thread by get a shared reference to it if inner `T` is `Sync`</br>
//!
//! - `LazyCell`</br>
//! delayed initiazation out of construction
//! can be initialized only once in single thread</br>
//! can be safely used in multi-thread by get a shared reference to it if inner `T` is `Sync`<</br>
//!
//! - `lazyLock`</br>
//! initialized when first accessed
//! can be safely initialized only once in multi-thread</br>
//! can be safely used in multi-thread by get a shared reference to it if inner `T` is `Sync`<</br>
//!
//! # Noteworthy
//! As we notice that `OnceCell` and `LazyCell` implement `Sync` if `T` implement `Sync` by default, this only applies to one case:</br>
//! we have a data piece that we exactly know it need to be delayly initialized only once and will not cause data race(it maintains its own interior mutability)
//! when used in multi-thread therefore it can be shared referenced in multi-threads, see following example:</br>
//! ```
//! // LazyLock/lazyCell may not be suitable for these cases
//! // but OnceCell is more efficient than OnceLock
//! struct DriverObject(PDRIVER_OBJECT);
//! unsafe impl Sync for DriverObject {}
//!
//! struct GlobalDriverData {
//!     // fields that initialized only once
//!     // ...
//! }
//!
//! unsafe impl Sync for GlobalDriverData {}
//!
//! // use OnceLock is also ok here
//! // but we prefer OnceCell since we exactly do not need the "lock" overhead here
//! static DRIVER: OnceCell<DriverObject> = OnceCell::new();
//! static GLOBAL_READONLY_DATA: OnceCell<GlobalDriverData> = OnceCell::new();
//!
//! fn initialize_global_data() -> GlobalDriverData {
//!     // ... do something
//! }
//! fn driver_entry(driver: PDRIVER_OBJECT, ...) {
//!     let driver_object = DRIVER.get_or_init(|| driver);
//!     // ... do something
//!     
//!     GLOBAL_READONLY_DATA.set(initialize_global_data());
//! }
//!
//! fn driver_unload(...) {
//!     OnceCell::drop(&DRIVER);
//!     OnceCell::drop(&GLOBAL_READONLY_DATA)
//! }
//! ```
use core::{
    cell::UnsafeCell,
    mem::{self, ManuallyDrop, MaybeUninit},
    ops::Deref,
    ptr::{self, drop_in_place},
    sync::atomic::{self, AtomicU32, Ordering},
};

use crate::once::{CallState, Once};

union Data<T, F> {
    value: ManuallyDrop<T>,
    f: ManuallyDrop<F>,
}

/// A value which is initialized on the first access and ensure thread safe during initialization
///
/// # Safety
/// - the value is initialized on its accessed
/// - ensure only one thread can only initialize `T` once, other thread must wait until the initialization completed
/// thus no data race occurred during initialization
/// - ensure only shared refs of `T` can be gained from a `LazyLock` behind a shared reference
///
/// # Example
/// ```
/// // typical usage
/// // declare a `LazyLock` somewhere
/// static GLOBAL_INSTANCE: LazyLock<0u32> = LazyLock::new(|| 0);
///
/// fn use_global_instance() {
///     println!("value = {}", *GLOBAL_INSTANCE);
/// }
///
/// // destroy instance in DriverUnload
/// fn driver_unload(driver_object: PDRIVER_OBJECT) {
///     // the caller must ensure NOT use it again after it dropped
///     LazyLock::drop(&GLOBAL_INSTANCE);
/// }
/// ```
///
/// # Note
/// since only shared refs can be gained through a `LazyLock`,
/// so if one want to changed the value of `T` inside a `LazyLock` concurrently,
/// consider wrap `T` within a `Locked` instead.
///
/// see `Locked<T>` for details
/// ```
pub struct LazyLock<T, F = fn() -> T> {
    once: UnsafeCell<Once<T>>,
    data: UnsafeCell<Data<T, F>>,
}

impl<T, F: FnOnce() -> T> LazyLock<T, F> {
    pub const fn new(f: F) -> Self {
        Self {
            once: UnsafeCell::new(Once::new()),
            data: UnsafeCell::new(Data {
                f: ManuallyDrop::new(f),
            }),
        }
    }

    #[inline]
    fn get_once(&self) -> &Once<T> {
        unsafe { &*self.once.get() }
    }

    #[inline]
    fn get_once_mut(&self) -> &mut Once<T> {
        unsafe { &mut *self.once.get() }
    }

    #[inline]
    pub fn is_initialized(&self) -> bool {
        self.get_once().get_state() == CallState::Completed
    }

    #[inline]
    fn get_unchecked(&self) -> &T {
        unsafe { &(*self.data.get()).value }
    }

    #[inline]
    fn get_unchecked_mut(&self) -> &mut T {
        unsafe { &mut (*self.data.get()).value }
    }

    #[inline]
    pub fn get(&self) -> Option<&T> {
        if self.is_initialized() {
            Some(self.get_unchecked())
        } else {
            None
        }
    }

    #[inline]
    pub fn get_mut(&mut self) -> Option<&mut T> {
        if self.is_initialized() {
            Some(self.get_unchecked_mut())
        } else {
            None
        }
    }

    pub fn force(this: &LazyLock<T, F>) -> &T {
        let state = this.get_once().get_state();

        match state {
            CallState::Initial => LazyLock::really_init(this),
            CallState::InProgress => this.force_wait(),
            CallState::Completed => this.get_unchecked(),
            _ => panic!("LazyLock is Poisoned"),
        }
    }

    fn really_init(this: &LazyLock<T, F>) -> &T {
        let data = unsafe { &mut *this.data.get() };
        let f = unsafe { ManuallyDrop::take(&mut data.f) };

        if let Some(mut value) = this.get_once().call_once(f) {
            unsafe { &mut *this.data.get() }.value = ManuallyDrop::new(value.take());
            this.get_unchecked()
        } else {
            this.force_wait()
        }
    }

    /// wait until the state becomes State::Initialized and return a valid `&T`
    pub fn force_wait(&self) -> &T {
        self.wait();
        self.get_unchecked()
    }

    /// wait until the state becomes State::Initialized
    #[inline]
    pub fn wait(&self) {
        self.get_once().wait();
    }

    /// # Synopsis
    /// use this method to drop `T` inside a `LazyLock`</br>
    /// a static `LazyLock` will not be automatically dropped in kernel programming since kernel leaks something like CRT runtime code</br>
    /// NOR do we can use the `into_inner()` semantics here since rust forbidden move out of static `LazyLock`
    ///
    /// # Safety
    /// - the caller must call this method at most once
    /// - access the wrapped `T` after dropped can cause undefined behavior
    /// - call `drop()` more than once can cause undefined behavior
    /// - use this method only for the global static initialized `LazyLock`
    ///
    /// # Examples
    /// ```
    /// // declares LazyLock in somewhere
    /// static GLOBAL_INSTANCE: LazyLock<u32> = LazyLock::new(|| 0);
    ///
    /// void driver_unload(driver_object: PDRIVER_OBJECT) {
    ///     // the inner T will be dropped here
    ///     LazyLock::drop(&GLOBAL_INSTANCE);
    ///     // ... do some other stuff
    /// }
    /// ```
    pub fn drop(this: &LazyLock<T, F>) {
        let state = this.get_once().get_state();

        let data = unsafe { &mut *this.data.get() };

        match state {
            CallState::Initial => unsafe { ManuallyDrop::drop(&mut data.f) },
            CallState::Completed => unsafe { ManuallyDrop::drop(&mut data.value) },
            _ => panic!("LazyLock in poisoned state"),
        }

        // Safety
        // we must ensure all the members be dropped in manually drop operation to prevent memory leaks
        unsafe { drop_in_place(this.get_once_mut()) };
    }
}

impl<T, F: FnOnce() -> T> Deref for LazyLock<T, F> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        Self::force(self)
    }
}

impl<T, F> Drop for LazyLock<T, F> {
    fn drop(&mut self) {
        match unsafe { &*self.once.get() }.get_state() {
            CallState::Initial => {
                unsafe { ManuallyDrop::drop(&mut self.data.get_mut().f) };
            }
            CallState::Completed => {
                unsafe { ManuallyDrop::drop(&mut self.data.get_mut().value) };
            }
            _ => {}
        }
    }
}

unsafe impl<T: Sync, F: FnOnce() -> T> Sync for LazyLock<T, F> {}

enum State<T, F> {
    Uninit(F),
    Init(T),
    Poisoned,
}

/// # Synopsis
/// A value which is initialized on the first access.
/// it behave mostly like `LazyLock` but is not thread safe during initialization
///
/// # fetures
/// - naturally no data race during initialization(caller must follow the safety rules below)
/// - a `LazyCell` is memory efficient than a `LazyLock`, it only require size_of(T) for memory storage
///
/// ## Safety
/// - caller must ensure it to be initialized only once, for example: intialize it in DriverEntry by calling `LazyCell::force`
/// - can be shared between multi-threads
/// - can not obtain a mutable reference through a `LazyCell` unless using `unsafe` block
/// - no interior mutability once it has been initialized
///
/// # Note
/// - `LazyCell` does not allocate memory in kernel heap, consider using `Box<T>` if `T` must be allocated dynamically
/// - if the caller want to read-write the wrapped `T` concurrently, consider wrap `T` into a `Locked<T>`
/// - once a `LazyCell` is initialized in static contex(typically a static instance), it is in pinned memory
///
/// # Example
/// ```
/// type FnAPI = extern "system" fn ();
///
/// pub static KERNEL_API: LazyCell<Option<FnAPI>> = LazyCell::new(|| get_kernel_api());
///
/// // use it somewhere as follows:
/// fn driver_entry(...) {
///     if let Some(func) = *KERNEL_API {
///         // ...
///     }
/// }
/// ```
#[repr(transparent)]
pub struct LazyCell<T, F = fn() -> T> {
    state: UnsafeCell<State<T, F>>,
}

impl<T, F: FnOnce() -> T> LazyCell<T, F> {
    pub const fn new(f: F) -> Self {
        Self {
            state: UnsafeCell::new(State::Uninit(f)),
        }
    }

    pub fn into_inner(this: LazyCell<T, F>) -> Result<T, F> {
        match this.state.into_inner() {
            State::Init(data) => Ok(data),
            State::Uninit(f) => Err(f),
            State::Poisoned => panic!("LazyStatic is not initialized"),
        }
    }

    pub fn get(&self) -> Option<&T> {
        let state = unsafe { &*self.state.get() };

        match state {
            State::Init(data) => Some(data),
            _ => None,
        }
    }

    /// be careful to use this method since it expose a mutable reference to the caller
    ///
    /// but it is convenient to transfer address of inside `T` to other native fucntions
    pub fn get_mut(&mut self) -> Option<&mut T> {
        let state = unsafe { &mut *self.state.get() };

        match state {
            State::Init(data) => Some(data),
            _ => None,
        }
    }

    /// Safety:
    ///
    /// it is the caller's responsibility to call force() in signle-thread mode to avoid data race
    pub fn force(this: &LazyCell<T, F>) -> &T {
        let state = unsafe { &*this.state.get() };

        match state {
            State::Init(data) => data,
            State::Uninit(_) => unsafe { LazyCell::really_init(this) },
            State::Poisoned => {
                panic!("LazyStatic is in poisoned state, maybe it has been used incorrectly")
            }
        }
    }

    pub fn drop(this: &LazyCell<T, F>) {
        let state = unsafe { &mut *this.state.get() };

        match state {
            State::Uninit(_) | State::Init(_) => unsafe {
                drop_in_place(state);
                ptr::write(state, State::Poisoned);
            },
            _ => panic!(),
        }
    }

    #[cfg(feature = "enable_mut_lazystatic")]
    pub unsafe fn force_mut(this: &LazyCell<T, F>) -> &mut T {
        let state = unsafe { &mut *this.state.get() };

        match state {
            State::Init(data) => data,
            State::Uninit(_) => unsafe { LazyCell::really_init_mut(this) },
            State::Poisoned => {
                panic!("LazyStatic is in poisoned state, maybe it has been used incorrectly")
            }
        }
    }

    unsafe fn really_init(this: &LazyCell<T, F>) -> &T {
        let state = unsafe { &mut *this.state.get() };

        let State::Uninit(f) = mem::replace(state, State::Poisoned) else {
            unreachable!()
        };

        let data = f();

        unsafe { this.state.get().write(State::Init(data)) };

        let state = unsafe { &*this.state.get() };

        let State::Init(data) = state else {
            unreachable!()
        };

        data
    }

    #[cfg(feature = "enable_mut_lazystatic")]
    unsafe fn really_init_mut(this: &LazyCell<T, F>) -> &mut T {
        let state = unsafe { &mut *this.state.get() };

        let State::Uninit(f) = mem::replace(state, State::Poisoned) else {
            unreachable!()
        };

        let data = f();

        unsafe { this.state.get().write(State::Init(data)) };

        let state = unsafe { &mut *this.state.get() };

        let State::Init(data) = state else {
            unreachable!()
        };

        data
    }
}

impl<T, F: FnOnce() -> T> Deref for LazyCell<T, F> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        LazyCell::force(self)
    }
}

unsafe impl<T: Sync, F: FnOnce() -> T> Sync for LazyCell<T, F> {}

/// A cell which can nominally be written to only once.
#[repr(transparent)]
pub struct OnceCell<T> {
    inner: UnsafeCell<Option<T>>,
}

impl<T> OnceCell<T> {
    pub const fn new() -> Self {
        Self {
            inner: UnsafeCell::new(None),
        }
    }

    #[inline]
    pub fn get(&self) -> Option<&T> {
        unsafe { &*self.inner.get() }.as_ref()
    }

    #[inline]
    pub fn get_mut(&mut self) -> Option<&mut T> {
        unsafe { &mut *self.inner.get() }.as_mut()
    }

    #[inline]
    pub fn set(&self, value: T) -> Result<(), T> {
        match self.get() {
            Some(_) => Err(value),
            _ => {
                unsafe { *self.inner.get() = Some(value) };

                Ok(())
            }
        }
    }

    #[inline]
    pub fn get_or_init<F: FnOnce() -> T>(&self, f: F) -> Option<&T> {
        match self.get() {
            None => {
                let value = f();

                if let Ok(_) = self.set(value) {
                    return self.get();
                }

                None
            }
            _ => return None,
        }
    }

    #[inline]
    pub fn take(&self) -> Option<T> {
        mem::take(unsafe { &mut *self.inner.get() })
    }

    #[inline]
    pub fn into_inner(self) -> Option<T> {
        self.inner.into_inner()
    }

    #[inline]
    pub fn drop(this: &OnceCell<T>) {
        unsafe { *this.inner.get() = None };
    }
}

// Safety
// user must initilize only once, shared between multi-thread through only shared reference
unsafe impl<T: Sync> Sync for OnceCell<T> {}

/// A synchronization primitive which can nominally be written to only once.
pub struct OnceLock<T> {
    // state: AtomicU32,
    once: UnsafeCell<Once<T>>,
    value: UnsafeCell<MaybeUninit<T>>,
}

impl<T> OnceLock<T> {
    pub const fn new() -> Self {
        Self {
            once: UnsafeCell::new(Once::new()),
            value: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    #[inline]
    pub fn is_initialized(&self) -> bool {
        self.get_once().get_state() == CallState::Completed
    }

    #[inline]
    pub fn get(&self) -> Option<&T> {
        if self.is_initialized() {
            Some(self.get_unchecked())
        } else {
            None
        }
    }

    #[inline]
    fn get_unchecked(&self) -> &T {
        unsafe { (&*self.value.get()).assume_init_ref() }
    }

    #[inline]
    fn get_unchecked_mut(&self) -> &mut T {
        unsafe { (&mut *self.value.get()).assume_init_mut() }
    }

    #[inline]
    pub fn get_mut(&mut self) -> Option<&mut T> {
        if self.is_initialized() {
            Some(self.get_unchecked_mut())
        } else {
            None
        }
    }

    /// set a value into underlying data
    ///
    /// initalize underlying `T` with `value` and return Ok(()) if `OnceLock` is not initialized yet
    /// Otherwise return an Err(value)
    #[inline]
    pub fn set(&self, value: T) -> Result<(), T> {
        if let Some(_) = self.get() {
            return Err(value);
        }

        self.init_once(move || value);

        Ok(())
    }

    #[inline]
    fn get_once(&self) -> &Once<T> {
        unsafe { &*self.once.get() }
    }

    #[inline]
    fn get_once_mut(&self) -> &mut Once<T> {
        unsafe { &mut *self.once.get() }
    }

    /// get or initialize the underlying `T`
    ///
    /// return a reference to underlying `T` if it is already initialized, otherwise `None`
    #[inline]
    pub fn get_or_init<F: FnOnce() -> T>(&self, f: F) -> Option<&T> {
        if let Some(value) = self.get() {
            return Some(value);
        }

        Some(self.init_once(f))
    }

    /// take the ownership of inside value
    ///
    /// # Safety
    /// - the user must not use it again after calling `take`
    /// - use this object again after `take` can cause undefined behavior
    #[inline]
    pub fn take(&mut self) -> Option<T> {
        if self.is_initialized() {
            // change the state of once into `Poisoned`
            self.once = UnsafeCell::new(Once::poisoned());

            unsafe { Some((&*self.value.get()).assume_init_read()) }
        } else {
            None
        }
    }

    #[inline]
    /// ensure the inside `T` is initialized only once
    fn init_once<F: FnOnce() -> T>(&self, f: F) -> &T {
        if let Some(mut value) = self.get_once().call_once(f) {
            unsafe { *self.value.get() = MaybeUninit::new(value.take()) };
            self.get_unchecked()
        } else {
            self.wait()
        }
    }

    /// wait until the state becomes INITIALIZED and return an valid `&T`
    #[inline]
    pub fn wait(&self) -> &T {
        self.get_once().wait();

        self.get_unchecked()
    }

    /// associate method that can be used to drop a static `OnceLock` by just hold a immutable reference
    ///
    /// # Safety
    /// - user must call this method only once
    /// - user must ensure it can never be used after `drop`
    ///
    /// # Example
    ///
    /// ```
    /// static GLOBAL_DATA: OnceLock<u32> = OnceLock::new();
    ///
    /// fn driver_entry(driver: DRIVER_OBJECT) {
    ///     GLOBAL_DATA.get_or_init(|| 1);
    /// }
    ///
    /// fn driver_unload(...) {
    ///     // GLOBAL_DATA drops here
    ///     OnceLock::drop(&GLOBAL_DATA);
    ///     // do not use it again
    /// }
    /// ```
    ///
    #[inline]
    pub fn drop(this: &OnceLock<T>) {
        if this.is_initialized() {
            // drop the underlying `T`
            unsafe {
                (&mut *this.value.get()).assume_init_drop();
            }
        }

        unsafe { ptr::drop_in_place(this.get_once_mut()) };
    }
}

impl<T> Drop for OnceLock<T> {
    fn drop(&mut self) {
        if self.is_initialized() {
            unsafe { (&mut *self.value.get()).assume_init_drop() };
        }
    }
}

unsafe impl<T: Sync> Sync for OnceLock<T> {}
