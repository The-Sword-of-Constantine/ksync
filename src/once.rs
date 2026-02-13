use core::{
    marker::PhantomData,
    mem::ManuallyDrop,
    sync::atomic::{AtomicU32, Ordering},
};

// internal states
const INITIAL: u32 = 0;
const INPROGRESS: u32 = 1;
const COPMLETED: u32 = 2;
const POISONED: u32 = 3;

#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub enum CallState {
    /// initail state indicates that nothing has done
    Initial,

    /// indicates the call is in progress, other components should wait until they
    /// can get a result
    InProgress,

    /// the call has completed, other components can do what they cam
    Completed,

    // indicates poisoned state
    Poisoned,
}

#[repr(transparent)]
pub struct Once<T> {
    state: AtomicU32,
    _phantom: PhantomData<T>,
}

impl<T> Once<T> {
    pub const fn new() -> Self {
        Self {
            state: AtomicU32::new(INITIAL),
            _phantom: PhantomData,
        }
    }

    pub const fn poisoned() -> Self {
        Self {
            state: AtomicU32::new(POISONED),
            _phantom: PhantomData,
        }
    }

    /// get the call state
    pub fn get_state(&self) -> CallState {
        match self.state.load(Ordering::Relaxed) {
            INITIAL => CallState::Initial,
            INPROGRESS => CallState::InProgress,
            COPMLETED => CallState::Completed,
            _ => CallState::Poisoned,
        }
    }

    /// call the `init_once` only once
    ///
    /// return a `OnceGuard` temporarily hold the value of `T` if the `init_once` is successfully executed
    pub fn call_once<F: FnOnce() -> T>(&'_ self, init_once: F) -> Option<OnceGuard<'_, T>> {
        if let Ok(_) =
            self.state
                .compare_exchange(INITIAL, INPROGRESS, Ordering::SeqCst, Ordering::Relaxed)
        {
            Some(OnceGuard {
                once: self,
                data: ManuallyDrop::new(init_once()),
            })
        } else {
            None
        }
    }

    /// wait until the state change to `Completed` state
    pub fn wait(&self) {
        use core::arch::x86_64::_mm_pause;

        while self.get_state() != CallState::Completed {
            _mm_pause();
        }
    }
}

/// A guard type that temporarily hold value of `T`
///
/// it does not actually take ownership of `data`
///
/// it will finally change the call state to `COPMLETED` upon it is dropped.
/// doing this to ensure that any other further result of initializing operations after `init_once` can be seen by other
/// threads without any re-order problems
pub struct OnceGuard<'a, T> {
    once: &'a Once<T>,
    data: ManuallyDrop<T>,
}

impl<'a, T> OnceGuard<'a, T> {
    /// take the inner `data` out
    ///
    /// # Safety
    /// since data is wrapped in a `ManuallyDrop`, it can be safely transfer out of scope without double-free problems
    pub fn take(&mut self) -> T {
        unsafe { ManuallyDrop::take(&mut self.data) }
    }
}

impl<'a, T> Drop for OnceGuard<'a, T> {
    fn drop(&mut self) {
        let _ = self.once.state.compare_exchange(
            INPROGRESS,
            COPMLETED,
            Ordering::SeqCst,
            Ordering::Relaxed,
        );
    }
}
