use core::{mem, ptr, time::Duration};

use alloc::boxed::Box;
use wdk_sys::{
    _EX_TIMER, _KDPC, _KTIMER,
    _POOL_TYPE::NonPagedPoolNx,
    _TIMER_TYPE::{NotificationTimer, SynchronizationTimer},
    EX_TIMER_HIGH_RESOLUTION, EX_TIMER_NOTIFICATION, EXT_DELETE_PARAMETERS, KTIMER, LARGE_INTEGER,
    PEX_TIMER, PEXT_CALLBACK, PKTIMER, PVOID, STATUS_INSUFFICIENT_RESOURCES,
    ntddk::{
        ExAllocateTimer, ExCancelTimer, ExDeleteTimer, ExFreePoolWithTag, ExSetTimer,
        ExSetTimerResolution, KeCancelTimer, KeInitializeDpc, KeInitializeTimerEx,
        KeReadStateTimer, KeSetTimerEx,
    },
};

use crate::{
    dpc::Dpc,
    kobject::Dispatchable,
    ntstatus::{NtError, Result},
    raw::AsRawObject,
    utils::ex_allocate_pool_zero,
};

const TIMER_TAG: u32 = u32::from_ne_bytes(*b"rimt");

/// run a task only once after some duration
///
/// run and "forget", manage memory automatically, usefull when using a one-shot-forget timer as a delayed task
/// # Parameter
/// - after: task will be run after amount of time specified, a `Duraton::ZERO` indicate the task will be started it immediately
/// # Note
/// depends on the implement context, the `f` will be dispatched on different IRQL
pub trait DelayRun {
    fn delay_run<F: Fn() + 'static>(f: F, after: Duration) -> Result<()>;
}

pub struct Timer {
    inner: PKTIMER,
    dpc: Dpc,
}

impl Timer {
    /// create a new `Timer`
    ///
    /// # Parameters
    /// - f: routine will be called when timer expired
    /// - is_synch: specify the type of timer, NotificationTimer or SynchronizationTimer will be created
    pub fn new<F: Fn() + 'static>(f: F, is_synch: bool) -> Result<Self> {
        let layout =
            ex_allocate_pool_zero(NonPagedPoolNx, mem::size_of::<KTIMER>() as _, TIMER_TAG);

        if layout.is_null() {
            return Err(NtError::new(STATUS_INSUFFICIENT_RESOURCES));
        }

        unsafe {
            KeInitializeTimerEx(
                layout.cast(),
                if is_synch {
                    SynchronizationTimer
                } else {
                    NotificationTimer
                },
            );
        }

        Ok(Self {
            inner: layout.cast(),
            dpc: Dpc::new(f)?,
        })
    }

    pub fn get_state(&self) -> bool {
        unsafe { KeReadStateTimer(self.inner) != 0 }
    }

    /// start this timer
    /// # Parameters
    /// - after: start this timer after amount of time, the timer will expired immdediately if a `Duration::ZERO` specified
    /// - period: timer expire period, the timer will not expire periodically if sepcify `Duration::ZERO` which means a one-shot timer
    pub fn start(&self, after: Duration, period: Duration) {
        let due_time = LARGE_INTEGER {
            QuadPart: -1 * after.as_millis() as i64 * 1_0000,
        };

        unsafe {
            KeSetTimerEx(
                self.inner,
                due_time,
                period.as_millis() as _,
                self.dpc.get(),
            );
        }
    }

    /// stop this timer
    pub fn stop(&self) {
        unsafe {
            KeCancelTimer(self.inner);
        }
    }
}

impl AsRawObject for Timer {
    type Target = _KTIMER;
    fn as_raw(&self) -> *mut Self::Target {
        self.inner
    }
}

impl Dispatchable for Timer {}

struct OneShotContex<F> {
    callback: Box<F>,
    timer: Box<_KTIMER>,
}

extern "C" fn oneshot_dpc_routine<F: Fn()>(
    pDpc: *mut _KDPC,
    DeferredContext: PVOID,
    SystemArgument1: PVOID,
    SystemArgument2: PVOID,
) {
    let context = unsafe { Box::from_raw(DeferredContext as *mut OneShotContex<F>) };

    (context.callback)();

    // free the DPC
    let _ = unsafe { Box::from_raw(pDpc) };

    // free all items in context
}

impl DelayRun for Timer {
    fn delay_run<F: Fn() + 'static>(f: F, after: Duration) -> Result<()> {
        let mut dpc = Box::new(_KDPC::default());

        // allocate DPC context
        let mut context = Box::new(OneShotContex {
            callback: Box::new(f),
            timer: Box::new(_KTIMER::default()),
        });

        unsafe {
            KeInitializeDpc(
                dpc.as_mut(),
                Some(oneshot_dpc_routine::<F>),
                context.as_mut() as *mut _ as _,
            );

            KeInitializeTimerEx(context.timer.as_mut(), NotificationTimer);
        }

        let due_time = LARGE_INTEGER {
            QuadPart: -1 * after.as_millis() as i64 * 1_0000,
        };

        unsafe {
            KeSetTimerEx(context.timer.as_mut(), due_time, 0, dpc.as_mut());
        }

        let _ = Box::leak(dpc);
        let _ = Box::leak(context);

        Ok(())
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        unsafe {
            ExFreePoolWithTag(self.inner.cast(), TIMER_TAG);
        }
    }
}

unsafe impl Send for Timer {}
unsafe impl Sync for Timer {}

/// A High Resolution Timer
///
/// # Note
/// before create timer that expired in 1ms, please adjust the system time tick resolutio first by calling `set_timer_resolution`
///
/// # Refer
/// see https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exsettimer for details
pub struct HRTimer(PEX_TIMER);

impl HRTimer {
    /// create a high resolution timer with or without a callback
    ///
    /// if a timer is created without callback, it will also satisfy the thread who waits on it to be signaled
    pub fn new<F: Fn() + 'static>(f: Option<F>) -> Result<Self> {
        let mut callback_stub: PEXT_CALLBACK = None;
        let mut callback: *mut F = ptr::null_mut();

        if f.is_some() {
            callback = Box::into_raw(Box::new(f.unwrap()));
            callback_stub = Some(hr_timer_routine_stub::<F>);
        }

        let timer =
            unsafe { ExAllocateTimer(callback_stub, callback as _, EX_TIMER_HIGH_RESOLUTION) };

        Ok(Self(timer))
    }

    /// start this timer
    /// # Parameter
    /// All the same as `Timer::start`
    pub fn start(&self, after: Duration, period: Duration) {
        unsafe {
            ExSetTimer(
                self.0,
                -1 * after.as_millis() as i64 * 1_0000,
                (period.as_micros() * 10) as _,
                ptr::null_mut(),
            );
        }
    }

    /// stop this timer
    pub fn stop(&self) {
        unsafe {
            ExCancelTimer(self.0, ptr::null_mut());
        };
    }
}

impl AsRawObject for HRTimer {
    type Target = _EX_TIMER;
    fn as_raw(&self) -> *mut Self::Target {
        self.0
    }
}

impl Dispatchable for HRTimer {}

/// callback run only once on DISPATCH_LEVEL
extern "C" fn hr_timer_routine_once_stub<F: FnOnce()>(timer: PEX_TIMER, context: PVOID) {
    let callback = unsafe { Box::from_raw(mem::transmute::<_, *mut F>(context)) };

    callback();

    let mut param = EXT_DELETE_PARAMETERS::default();

    unsafe { ExDeleteTimer(timer.cast(), 0, 0, &mut param) };
}

impl DelayRun for HRTimer {
    fn delay_run<F: FnOnce() + 'static>(f: F, after: Duration) -> Result<()> {
        let callback = Box::into_raw(Box::new(f));

        let timer = unsafe {
            ExAllocateTimer(
                Some(hr_timer_routine_once_stub::<F>),
                callback as _,
                EX_TIMER_HIGH_RESOLUTION,
            )
        };

        unsafe {
            ExSetTimer(
                timer,
                -1 * after.as_millis() as i64 * 1_0000,
                0,
                ptr::null_mut(),
            );
        }

        Ok(())
    }
}

impl Drop for HRTimer {
    fn drop(&mut self) {
        unsafe {
            // stop and delete the timer
            let mut param = EXT_DELETE_PARAMETERS::default();

            ExDeleteTimer(self.0, 1, 1, &mut param);
        }
    }
}

/// callback run periodically on DISPATCH_LEVEL
extern "C" fn hr_timer_routine_stub<F: Fn()>(timer: PEX_TIMER, context: PVOID) {
    let callback = unsafe { Box::from_raw(mem::transmute::<_, *mut F>(context)) };

    callback();
}

/// adjust the system wide time tick resolution
/// # Note
///
/// the system tiemr resolution must be restored after call `set_resolution`
///
/// see https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exsettimerresolution for details
#[inline]
pub fn set_timer_resolution(res: Duration) -> Duration {
    Duration::from_nanos(
        (unsafe { ExSetTimerResolution(res.as_nanos() as u32 / 100, 1) } * 100) as u64,
    )
}

/// restore the system wide time tick resolution to default value
#[inline]
pub fn resotre_timer_resolution() {
    unsafe {
        ExSetTimerResolution(0, 0);
    }
}

/// A "threaded timer" that can be used in thread running on IRQL <= DISPATCH_LEVEL
///
/// # Example
/// These examples is also suitable for `ThreadHRTimer`
///
/// - A Synchronization Timer
/// ```
/// let timer = Arc::new(ThreadTimer::new(true));
/// let ticker = timer.clone();
/// let thread = thread::spawn(|| {
///     loop {
///         ticker.wait();
///         // timer expired, do something
///     }
/// });
/// ```
/// - A Notification Timer
/// ```
/// let timer = Arc::new(ThreadTimer::new(false));
/// let broadcaster = tiemr.clone();
///
/// for _ in 0..4 {
///     let _ = thread::spawn(|| loop {
///         broadcaster.wait();
///         // timer expired, do something
///     })
/// }
/// ```
#[repr(transparent)]
pub struct ThreadTimer(PKTIMER);

impl ThreadTimer {
    pub fn new(is_synch: bool) -> Result<Self> {
        let layout =
            ex_allocate_pool_zero(NonPagedPoolNx, mem::size_of::<KTIMER>() as _, TIMER_TAG);

        if layout.is_null() {
            return Err(NtError::new(STATUS_INSUFFICIENT_RESOURCES));
        }

        unsafe {
            KeInitializeTimerEx(
                layout.cast(),
                if is_synch {
                    SynchronizationTimer
                } else {
                    NotificationTimer
                },
            );
        }

        Ok(Self(layout.cast()))
    }
}

impl AsRawObject for ThreadTimer {
    type Target = _KTIMER;
    fn as_raw(&self) -> *mut Self::Target {
        self.0
    }
}

impl Dispatchable for ThreadTimer {}

unsafe impl Sync for ThreadTimer {}

impl Drop for ThreadTimer {
    fn drop(&mut self) {
        unsafe {
            ExFreePoolWithTag(self.0.cast(), TIMER_TAG);
        }
    }
}

/// A "Threaded High Resolution Timer" can be used in thread that running on IRQL <= DISPATCH_LEVEL
///
/// # Example
/// See examples of `ThreadTimer`*
pub struct ThreadHRTimer(PEX_TIMER);

impl ThreadHRTimer {
    /// # Parameters
    /// - is_sync: specified whether this timer is a synchronization timer or a notification timer
    ///
    /// # Note
    /// A timer can be a notification timer or a synchronization timer.
    /// When a notification timer is signaled, all waiting threads have their wait satisfied.
    /// The state of this timer remains signaled until it is explicitly reset. When a synchronization timer expires,
    /// its state is set to signaled until a single waiting thread is released. Then, the timer is reset to the not-signaled state.
    ///
    /// # Refer
    /// see https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exallocatetimer for details
    pub fn new(is_sync: bool) -> Result<Self> {
        let mut attr: u32 = EX_TIMER_HIGH_RESOLUTION;

        if !is_sync {
            attr |= EX_TIMER_NOTIFICATION;
        }

        let timer = unsafe { ExAllocateTimer(None, ptr::null_mut(), attr) };

        if timer.is_null() {
            return Err(NtError::new(STATUS_INSUFFICIENT_RESOURCES));
        }

        Ok(Self(timer))
    }
}

impl AsRawObject for ThreadHRTimer {
    type Target = _EX_TIMER;
    fn as_raw(&self) -> *mut Self::Target {
        self.0
    }
}

impl Dispatchable for ThreadHRTimer {}

unsafe impl Sync for ThreadHRTimer {}

impl Drop for ThreadHRTimer {
    fn drop(&mut self) {
        unsafe {
            ExFreePoolWithTag(self.0.cast(), TIMER_TAG);
        }
    }
}
