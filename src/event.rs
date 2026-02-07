use core::mem;
use wdk_sys::{
    _EVENT_TYPE::{NotificationEvent, SynchronizationEvent},
    _KEVENT,
    _POOL_TYPE::NonPagedPoolNx,
    IO_NO_INCREMENT, PKEVENT, STATUS_INSUFFICIENT_RESOURCES,
    ntddk::{
        ExFreePoolWithTag, KeClearEvent, KeInitializeEvent, KeReadStateEvent, KeResetEvent,
        KeSetEvent,
    },
};

use crate::{
    kobject::Dispatchable,
    ntstatus::{NtError, Result},
    raw::AsRawObject,
    utils::ex_allocate_pool_zero,
};

/// A kernel mode synchronous Event
#[repr(transparent)]
pub struct Event(PKEVENT);

const EVENT_TAG: u32 = u32::from_ne_bytes(*b"tvek");

pub struct EventProperty {
    /// true - SynchronizationEvent
    /// false - NotificationEvent
    auto_reset: bool,

    /// initial state after creation
    initial_state: bool,
}

impl EventProperty {
    /// create a type of `NotificationEvent` by default
    pub fn new() -> Self {
        Self {
            auto_reset: false,
            initial_state: false,
        }
    }

    pub fn auto_reset(mut self, value: bool) -> Self {
        self.auto_reset = value;

        self
    }

    pub fn initial_state(mut self, value: bool) -> Self {
        self.initial_state = value;

        self
    }

    pub fn new_event(self) -> Result<Event> {
        Event::new(self)
    }
}

impl Event {
    /// allocate a new event object on the kernel heap
    pub fn new(prop: EventProperty) -> Result<Self> {
        let layout =
            ex_allocate_pool_zero(NonPagedPoolNx, mem::size_of::<_KEVENT>() as _, EVENT_TAG);

        if layout.is_null() {
            return Err(NtError::new(STATUS_INSUFFICIENT_RESOURCES));
        }

        let r#type = if prop.auto_reset {
            SynchronizationEvent
        } else {
            NotificationEvent
        };

        unsafe { KeInitializeEvent(layout.cast(), r#type, prop.initial_state as u8) };

        Ok(Self(layout.cast()))
    }

    /// trun the event into signaled state
    #[inline]
    pub fn set(&self) {
        unsafe {
            KeSetEvent(self.0, IO_NO_INCREMENT as _, 0);
        }
    }

    /// trun the event into not-signaled state
    #[inline]
    pub fn clear(&self) {
        unsafe {
            KeClearEvent(self.0);
        }
    }

    /// set the event to not-signaled state and return the previous state
    /// # Return value
    /// - true, previous state is in signaled state
    /// - false, previous state is in not-signaled state
    #[inline]
    pub fn reset(&self) -> bool {
        unsafe { KeResetEvent(self.0) != 0 }
    }

    /// get the current state of this event
    /// # Return Value
    /// - true, event is in signaled state
    /// - false, event is in not-signaled state
    pub fn get_state(&self) -> bool {
        unsafe { KeReadStateEvent(self.0) != 0 }
    }
}

impl AsRawObject for Event {
    type Target = _KEVENT;
    fn as_raw(&self) -> *mut Self::Target {
        self.0
    }
}

impl Dispatchable for Event {}

impl Drop for Event {
    fn drop(&mut self) {
        unsafe {
            ExFreePoolWithTag(self.0.cast(), EVENT_TAG);
        }
    }
}

unsafe impl Send for Event {}
unsafe impl Sync for Event {}
