use wdk_sys::HANDLE;

pub trait AsRawObject {
    type Target;

    fn as_raw(&self) -> *mut Self::Target;
}

pub trait AsRawHandle {
    fn as_raw(&self) -> HANDLE;
}

pub trait FromRawHandle {
    fn from_raw(h: HANDLE) -> Self;
}
