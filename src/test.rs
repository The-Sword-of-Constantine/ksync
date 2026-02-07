// call it in another driver to do the testing
use core::ptr;
use core::time::Duration;

use alloc::sync::Arc;
use wdk::println;
use wdk_sys::ntddk::{IoCreateDevice, IoDeleteDevice, KeGetCurrentProcessorNumberEx};
use wdk_sys::{FILE_DEVICE_SECURE_OPEN, FILE_DEVICE_UNKNOWN, PDEVICE_OBJECT, PDRIVER_OBJECT};

use crate::lazy::{LazyCell, OnceCell};
use crate::ntstatus::{NtError, Result, cvt};
use crate::workitem::WorkItem;
use crate::{lock, thread, ulong_to_handle};

use super::dpc::{self};
use super::event::*;
use super::kobject::*;
use super::mutex::*;
use super::sema::*;
use super::thread::*;
use super::timer::*;

extern crate alloc;

pub fn test_kobject() {
    if let Ok(process) = ProcessObject::from_process_id(ulong_to_handle!(4368)) {
        println!("get process: {:p}", process.as_ptr());
    }

    if let Ok(thread) = ThreadObject::from_thread_id(ulong_to_handle!(4372)) {
        println!("get thread: {:p}", thread.as_ptr());
    }
}

pub fn test_thread() {
    let handle = spawn(|| {
        for i in 0..10 {
            println!("thread {:x} is running", this_thread::id());
            this_thread::sleep(Duration::from_millis(200));
        }
        println!("thread {:x} exited", this_thread::id());
    })
    .unwrap();

    let exit_status = handle.join().expect("join tread failed");

    println!("thread exit status: {:x}", exit_status);
}

use alloc::vec::Vec;

pub fn test_guard_mutex() {
    let mut handles: Vec<JoinHandle> = Vec::new();

    let shared_counter = Arc::new(GuardLocked::new(0u32).unwrap());

    for _ in 0..4 {
        let counter = shared_counter.clone();

        handles.push(
            spawn(move || {
                for i in 0..100 {
                    if let Ok(mut guard) = counter.lock() {
                        *guard += 1;
                        // this_thread::sleep(Duration::from_millis(i));
                    }
                }
            })
            .unwrap(),
        );
    }

    // wait for all threads to exit
    for h in handles {
        h.join().expect("join thread failed");
    }

    // check the shared counter
    println!(
        "the final value of shared counter is: {:?}",
        **shared_counter
    );
}

pub fn test_fast_mutex() {
    let mut handles: Vec<JoinHandle> = Vec::new();

    let shared_counter = Arc::new(FastLocked::new(0u32).unwrap());

    for _ in 0..4 {
        let counter = shared_counter.clone();

        handles.push(
            spawn(move || {
                for i in 0..100 {
                    if let Ok(mut guard) = counter.lock() {
                        *guard += 1;
                    }
                }
            })
            .unwrap(),
        );
    }

    // wait for all threads to exit
    for h in handles {
        h.join().expect("join thread failed");
    }

    // check the shared counter
    println!(
        "the final value of shared counter is: {:?}",
        **shared_counter
    );
}

pub fn test_spinlock() {
    let mut handles: Vec<JoinHandle> = Vec::new();

    let shared_counter = Arc::new(SpinLocked::new(0u32).unwrap());

    for _ in 0..4 {
        let counter = shared_counter.clone();

        handles.push(
            spawn(move || {
                for i in 0..100 {
                    if let Ok(mut guard) = counter.lock() {
                        *guard += 1;
                    }
                }
            })
            .unwrap(),
        );
    }

    // wait for all threads to exit
    for h in handles {
        h.join().expect("join thread failed");
    }

    // check the shared counter
    println!(
        "the final value of shared counter is: {:?}",
        **shared_counter
    );
}

pub fn test_resouce_lock() {
    let mut handles: Vec<JoinHandle> = Vec::new();

    let shared_counter = Arc::new(ResourceLocked::new(0u32).unwrap());

    for _ in 0..4 {
        let counter = shared_counter.clone();

        handles.push(
            spawn(move || {
                for i in 0..100 {
                    if let Ok(mut guard) = counter.lock() {
                        *guard += 1;
                    }
                }
            })
            .unwrap(),
        );
    }

    // wait for all threads to exit
    for h in handles {
        h.join().expect("join thread failed");
    }

    // check the shared counter
    println!(
        "the final value of shared counter is: {:?}",
        **shared_counter
    );
}

pub fn test_queued_spin_lock() {
    let mut handles: Vec<JoinHandle> = Vec::new();

    let shared_counter = Arc::new(InStackQueueLocked::new(0u32).unwrap());

    for _ in 0..4 {
        let counter = shared_counter.clone();

        handles.push(
            spawn(move || {
                for _ in 0..1000 {
                    let mut handle = LockedQuueHandle::new();

                    if let Ok(mut guard) = counter.lock(&mut handle) {
                        *guard += 1;
                    }
                }
            })
            .unwrap(),
        );
    }

    // wait for all threads to exit
    for h in handles {
        h.join().expect("join thread failed");
    }

    // check the shared counter
    println!(
        "the final value of shared counter is: {:?}",
        **shared_counter
    );
}

pub fn test_event() {
    // create a auto-reset event(also called SynchronizationEvent)
    let event = Arc::new(
        EventProperty::new()
            .auto_reset(true)
            .initial_state(false)
            .new_event()
            .unwrap(),
    );

    // start main thread
    {
        let event = event.clone();

        let _ = spawn(move || {
            for i in 0..4 {
                this_thread::sleep(Duration::from_secs(10));
                event.set();
            }
        });
    }

    // observer thread
    {
        let event = event.clone();
        let _ = spawn(move || {
            if event.wait_for(Duration::from_secs(5), false).timed_out() {
                println!("wait timed out, thread {} exited", this_thread::id());
            }

            println!("observer thread {} exited", this_thread::id());
        });
    }

    // worker thread
    {
        for _ in 0..4 {
            let event = event.clone();
            let _ = spawn(move || {
                if event.wait(false).success() {
                    println!("worker thread {} waked up", this_thread::id());
                }

                println!("worker thread {} exited", this_thread::id());
            });
        }
    }
}

pub fn test_semaphore() {
    let limit = available_parallelism().get();

    let semaphore = Arc::new(Semaphore::new(0, limit as _).unwrap());

    // producer thread
    {
        let repo = semaphore.clone();

        let _ = spawn(move || {
            for _ in 0..4 {
                this_thread::sleep(Duration::from_secs(5));
                repo.release(1);
            }

            println!("producer thread {} exited", this_thread::id());
        });
    }

    // consumer thread
    {
        for _ in 0..limit {
            let repo = semaphore.clone();

            let _ = spawn(move || {
                if repo.wait(false).success() {
                    println!("consumerthread {} wake up", this_thread::id());
                }

                println!("consumer thread {} exited", this_thread::id());
            });
        }
    }
}

pub fn test_timer() {
    // this timer will use a DPC
    let timer = Arc::new(
        Timer::new(
            || {
                println!("timer expired");
            },
            false,
        )
        .unwrap(),
    );

    {
        let timer = timer.clone();

        let _ = spawn(move || {
            this_thread::sleep(Duration::from_secs(30));
            timer.stop();

            println!("timer stopped");
        });
    }

    timer.start(Duration::ZERO, Duration::from_secs(5));
}

pub fn test_dpc() {
    dpc::run_once_per_core(|| {
        let core = unsafe { KeGetCurrentProcessorNumberEx(ptr::null_mut()) };

        println!("running on core#{}", core);
    });
}

fn test_delay_task() {
    for _ in 0..10 {
        let _ = Timer::delay_run(
            || {
                println!("mission completed in normal timer");
            },
            Duration::from_secs(3),
        );
    }

    for _ in 0..6 {
        let _ = HRTimer::delay_run(
            || {
                println!("mission completed in high resolution timer");
            },
            Duration::from_secs(8),
        );
    }
}

fn test_hr_timer() {
    let timer = Arc::new(
        Timer::new(
            || {
                println!("timer expired");
            },
            false,
        )
        .unwrap(),
    );

    // start a thread to stop the timer after 20 seconds
    {
        let timer = timer.clone();

        let _ = thread::spawn(move || {
            this_thread::sleep(Duration::from_secs(20));
            timer.stop();

            println!("timer stopped");
        });
    }

    timer.start(Duration::from_secs(3), Duration::from_secs(1));
}

#[repr(transparent)]
struct Device(PDEVICE_OBJECT);

impl Device {
    fn new() -> Result<Self> {
        let mut device: PDEVICE_OBJECT = ptr::null_mut();

        let status = unsafe {
            IoCreateDevice(
                DRIVER.get().unwrap().as_raw(),
                0,
                ptr::null_mut(),
                FILE_DEVICE_UNKNOWN,
                FILE_DEVICE_SECURE_OPEN,
                0,
                &mut device,
            )
        };

        cvt(status)?;

        Ok(Self(device))
    }

    fn get(&self) -> PDEVICE_OBJECT {
        self.0
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        unsafe {
            IoDeleteDevice(self.0);
        }
    }
}

unsafe impl Sync for Device {}

// [!!!] re-write it in your own driver
struct WdmDriver(PDRIVER_OBJECT);
impl WdmDriver {
    fn as_raw(&self) -> PDRIVER_OBJECT {
        self.0
    }
}

unsafe impl Sync for WdmDriver {}

/// [!!!] re-write it in your own driver
static DRIVER: OnceCell<WdmDriver> = OnceCell::new();

// [!!!] re-write it in your own driver
static DEVICE: LazyCell<Device> = LazyCell::new(|| Device::new().unwrap());

// [!!!] re-write it in your own driver
fn test_workitem() {
    // create a device first, it must has static lifetime
    LazyCell::force(&DEVICE);

    let event = Arc::new(EventProperty::new().new_event().unwrap());

    let device = DEVICE.get().unwrap().get();

    {
        let value = 3;

        let event = event.clone();

        let workitem = WorkItem::new(
            move || {
                println!("it worked: {}", value);
                event.set();
            },
            device,
        )
        .unwrap();

        workitem.activate();
    }

    // wait for workitem complete its execution
    event.wait(false);

    for i in 0..10 {
        let _ = WorkItem::post(
            move || {
                println!("workeitem#{} executed", i);
            },
            device,
        );
    }
}
