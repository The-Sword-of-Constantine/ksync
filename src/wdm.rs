use core::{
    mem::{self},
    ops::{Deref, DerefMut},
    ptr::{self, NonNull},
};

use crate::{
    kobject::KernelObject,
    ntstatus::{NtError, cvt},
    utils,
};
use alloc::{borrow::ToOwned, boxed::Box, vec::Vec};

use wdk::nt_success;
use wdk_sys::{
    _DEVICE_OBJECT, _DRIVER_OBJECT, _UNICODE_STRING, DEVICE_OBJECT, DRIVER_OBJECT,
    FILE_DEVICE_SECURE_OPEN, FILE_DEVICE_UNKNOWN, FILE_READ_DATA, IO_NO_INCREMENT,
    IRP_MJ_MAXIMUM_FUNCTION, LIST_ENTRY, NTSTATUS, PDEVICE_OBJECT, PDRIVER_OBJECT, PFILE_OBJECT,
    PIRP, PUNICODE_STRING, STATUS_DEVICE_ALREADY_ATTACHED, STATUS_INSUFFICIENT_RESOURCES,
    STATUS_INVALID_PARAMETER_2, STATUS_NOT_FOUND, STATUS_NOT_IMPLEMENTED, STATUS_PENDING,
    STATUS_SUCCESS, UNICODE_STRING,
    ntddk::{
        IoAttachDeviceToDeviceStackSafe, IoCreateDevice, IoCreateSymbolicLink, IoDeleteDevice,
        IoDeleteSymbolicLink, IoDetachDevice, IoGetAttachedDeviceReference,
        IoGetDeviceObjectPointer, IoGetRelatedDeviceObject, IofCompleteRequest,
    },
};

use crate::utils::IoMarkIrpPending;

#[allow(non_snake_case, non_camel_case_types)]
#[repr(C)]
pub struct KLDR_DATA_TABLE_ENTRY {
    pub InLoadOrderLinks: LIST_ENTRY,
    pub ExceptionTable: *mut core::ffi::c_void,
    pub ExceptionTableSize: u32,
    pub GpValue: *mut core::ffi::c_void,
    pub NonPagedDebugInfo: *mut core::ffi::c_void,
    pub DllBase: *mut core::ffi::c_void,
    pub EntryPoint: *mut core::ffi::c_void,
    pub SizeOfImage: u32,
    pub FullDllName: UNICODE_STRING,
    pub BaseDllName: UNICODE_STRING,
    pub Flags: u32,
    pub LoadCount: u16,
    pub __Unused5: u16,
    pub SectionPointer: *mut core::ffi::c_void,
    pub CheckSum: u32,
    pub LoadedImports: *mut core::ffi::c_void,
    pub PatchInformation: *mut core::ffi::c_void,
}

#[allow(non_camel_case_types)]
pub type PKLDR_DATA_TABLE_ENTRY = *mut KLDR_DATA_TABLE_ENTRY;

pub struct DeviceProperty<'a> {
    dev_type: u32,
    dev_characteristics: u32,
    dev_name: Option<&'a str>,
    dev_symbol_name: Option<&'a str>,
}

impl<'a> DeviceProperty<'a> {
    pub const fn new() -> Self {
        Self {
            dev_type: FILE_DEVICE_UNKNOWN,
            dev_characteristics: FILE_DEVICE_SECURE_OPEN,
            dev_name: None,
            dev_symbol_name: None,
        }
    }

    #[inline(always)]
    pub fn get_type(&self) -> u32 {
        self.dev_type
    }

    #[inline(always)]
    pub fn get_characteristics(&self) -> u32 {
        self.dev_type
    }

    #[inline(always)]
    pub fn get_dev_name(&self) -> Option<&'a str> {
        self.dev_name
    }

    #[inline(always)]
    pub fn get_dev_symbol_name(&self) -> Option<&'a str> {
        self.dev_symbol_name
    }

    #[inline(always)]
    pub fn set_type(mut self, r#type: u32) -> Self {
        self.dev_type = r#type;
        self
    }

    #[inline(always)]
    pub fn set_characteristics(mut self, characteristics: u32) -> Self {
        self.dev_characteristics = characteristics;
        self
    }

    #[inline(always)]
    pub fn set_name(mut self, name: &'a str) -> Self {
        self.dev_name = Some(name);
        self
    }

    #[inline(always)]
    pub fn set_symbol_name(mut self, symbol_name: &'a str) -> Self {
        self.dev_symbol_name = Some(symbol_name);
        self
    }

    #[inline(always)]
    pub fn new_device(
        self,
        driver: &mut Driver,
        dispatch_handler: Option<Box<dyn IrpDispatch>>,
    ) -> Result<&mut OwnedDevice, NtError> {
        driver.create_device(self, dispatch_handler)
    }
}

/// A type act as IRP Dispatch handler that handle IRP request in device's own "Device Stack Frame"
///
/// at mostly time, it can also be used as `DeviceExtension` but no only a `IrpDispatch`
pub trait IrpDispatch {
    /// the `irp_dispatch_stub` will call `IoCompeleteIrp` mostly time during the end of dispatch
    /// so NEVER call `IoCompeleteIrp` in `dispatch`
    ///
    /// # Responsibility of an IRP Dispatch Handler:
    /// - handling the device's own stuff and return a `Result<u64, NtError>`
    /// - a Ok(value) with value >= 0 embeded indicates the IRP can be complete successfully, and the value will be set to the `Irp.IoStatus.Information` field</br>
    /// while the `Irp.IoStatus.Status` field will be set to STATUS_SUCCESS
    /// - an Err(e) indicates the IRP can not be compleete successfully, there is two cases</br>
    /// 1). if `e.code()` != STATUS_PENDING, the `Irp.IoStatus.Status` will be set to `e.code()` and the IRP will be completed immediately</br>
    /// 2). if `e.code()` == is STATUS_PENDINGthe, the `Irp.IoStatus.Status` will be set to `e.code()` and the IRP will be marked as pending, IRP is not completed </br>
    fn dispatch(&self, device: PDEVICE_OBJECT, irp: PIRP) -> Result<u64, NtError>;
}

/// just a helper structure for IRP dispatch handler and device stack manipulation
struct DispatchContext<'a> {
    irp_handler: &'a mut dyn IrpDispatch,
    attach_to: PDEVICE_OBJECT,
}

/// A Driver Wrapper for WDM device model, Not Owned
///
/// it maintain ownership of all devices it created, is is typically used as a global static variable
///
/// # Exmaple
/// ```
/// // declare as a global static variable
/// pub static DRIVER: OnceLock<WdmDriver> = OnceLock::new();
///
/// fn driver_entry(driver: PDRIVER_OBJECT, ...) -> NTSTATUS {
///     // initialize the it
///     let _ = DRIVER.get_or_init(driver);
/// }
///
/// fn driver_unload(driver: PDRIVER_OBJECT) {
///     // finialize, free all the resources used by `DRIVER`
///     OnceLock::drop(&DRIVER);
/// }
/// ```
pub struct Driver {
    object: NonNull<DRIVER_OBJECT>,
    devices: Vec<OwnedDevice>,
}

impl Driver {
    pub fn new(driver: PDRIVER_OBJECT) -> Self {
        let mut driver = NonNull::new(driver).unwrap();

        Self::setup_dispatch_routines(unsafe { driver.as_mut() });

        Self {
            object: driver,
            devices: Vec::new(),
        }
    }

    pub fn as_raw(&self) -> PDRIVER_OBJECT {
        self.object.as_ptr()
    }

    /// helper method for debugging
    pub fn disable_integrity_check(&self) {
        unsafe {
            let ldr_data = &mut *(self.DriverSection as PKLDR_DATA_TABLE_ENTRY);

            ldr_data.Flags |= 0x20;
        }
    }

    fn setup_dispatch_routines(driver: &mut DRIVER_OBJECT) {
        #[allow(unpredictable_function_pointer_comparisons)]
        if driver.MajorFunction[0] == Some(irp_dispatch_stub) {
            return;
        }

        for i in 0..(IRP_MJ_MAXIMUM_FUNCTION as usize) {
            driver.MajorFunction[i] = Some(irp_dispatch_stub);
        }
    }

    pub fn create_device(
        &mut self,
        property: DeviceProperty,
        dispatch_handler: Option<Box<dyn IrpDispatch>>,
    ) -> Result<&mut OwnedDevice, NtError> {
        let dev = OwnedDevice::new(self, property, dispatch_handler)?;

        self.devices.push(dev);

        self.devices
            .last_mut()
            .ok_or(NtError::new(STATUS_NOT_FOUND))
    }

    #[deprecated(since = "0.1.4", note = "please use `Driver::create_device` instead")]
    pub fn create_device_with_name(
        &mut self,
        name: &str,
        symbol_name: Option<&str>,
        dispatch_handler: Option<Box<dyn IrpDispatch>>,
    ) -> Result<&mut OwnedDevice, NtError> {
        let dev = OwnedDevice::with_name(self, name, symbol_name, dispatch_handler)?;

        self.devices.push(dev);

        self.devices
            .last_mut()
            .ok_or(NtError::new(STATUS_NOT_FOUND))
    }
}

impl Deref for Driver {
    type Target = _DRIVER_OBJECT;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.object.as_ptr() }
    }
}

impl DerefMut for Driver {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.object.as_ptr() }
    }
}

pub struct EmptyDispatch(());

impl IrpDispatch for EmptyDispatch {
    fn dispatch(&self, device: PDEVICE_OBJECT, irp: PIRP) -> Result<u64, NtError> {
        Err(NtError::new(STATUS_NOT_IMPLEMENTED))
    }
}

/// A WDM Device object wrapper(Owned)
///
/// it maintain ownership of `name`, `symbol_name` and the unerlying device object and dispatch object(if any)
pub struct OwnedDevice {
    name: Option<Box<UNICODE_STRING>>,
    symbol_name: Option<Box<UNICODE_STRING>>,
    object: NonNull<_DEVICE_OBJECT>,
    /// keep the `dispatcher object` resident in memory
    #[allow(dead_code)]
    dispatch_object: Option<Box<dyn IrpDispatch>>,
}

impl OwnedDevice {
    /// create a default device with `DeviceProperty`
    ///
    /// Device Extension is created when `dispatch_object` is specified
    pub fn new(
        driver: &Driver,
        property: DeviceProperty,
        dispatch_handler: Option<Box<dyn IrpDispatch>>,
    ) -> Result<Self, NtError> {
        let mut device: PDEVICE_OBJECT = ptr::null_mut();
        let mut ext_size = 0u32;
        let mut dev_name: Option<Box<_UNICODE_STRING>> = None;

        if dispatch_handler.is_some() {
            ext_size = mem::size_of::<DispatchContext>() as _;
        }

        if let Some(name) = property.get_dev_name() {
            dev_name = Some(
                utils::utf16_from_str(("\\Device\\".to_owned() + name).as_str())
                    .ok_or(NtError::new(STATUS_INSUFFICIENT_RESOURCES))?,
            );
        }

        let mut status = unsafe {
            IoCreateDevice(
                driver.as_raw(),
                ext_size,
                if dev_name.is_some() {
                    dev_name.as_mut().unwrap().as_mut()
                } else {
                    ptr::null_mut()
                },
                property.get_type(),
                property.get_characteristics(),
                0,
                &mut device,
            )
        };

        cvt(status)?;

        let mut device_dos_name: Option<Box<UNICODE_STRING>> = None;

        if let Some(name) = property.get_dev_symbol_name() {
            if let Some(ref mut name2) = dev_name {
                let mut sym_name: Box<_UNICODE_STRING> =
                    utils::utf16_from_str(("\\DosDevices\\".to_owned() + name).as_str())
                        .ok_or(NtError::new(STATUS_INSUFFICIENT_RESOURCES))?;

                status = unsafe { IoCreateSymbolicLink(sym_name.as_mut(), name2.as_mut()) };

                if !nt_success(status) {
                    unsafe {
                        IoDeleteDevice(device);
                    }
                    return Err(NtError::new(status));
                }

                device_dos_name = Some(sym_name);
            }
        }

        let mut dispatch_object: Option<Box<dyn IrpDispatch>> = None;

        // A `dyn` type in Rust is a DST type for dynamic dispatch
        // a `dyn xxx` is essentially different from a `&dyn xxx`, they are just explained as `T` and `&T`
        // but a `&dyn` type has a fixed size of 16 bytes long, it is a "fat pointer" consist of two parts:
        // 1)the high part is a pointer point to the object that allocated in the heap
        // 2)the low part if a pointer  point to the `vtable` of the object in the 'rdata' section of image
        // both is guaranteed residence in memory by `Box`, so we could safely use it for dynamic dispatch
        // and that's why the `&dyn xxx` is not "compatible" with native raw pointers, but we can store a '&dyn xxx' into memory of a raw pointer
        //
        // when we initialize a Box<dyn xxx> by calling Box<dyn xxx>::new(T), the following two things will happen:
        // 1) the Box will allocate `T` from heap and store its address(8 bytes on x64) in high part of "fat pointer"
        // 2) the Box will store the `vtable` of `T` in low part of "fat pointer"
        //
        // here we perform to copy a `&dyn IrpDispatch` into `DeviceExtension` and then take the ownership of the dispatch handler
        // the dispatch handler lives as long as this device object, the user must ensure this device object lives longer than the `irp_dispatch_stub`
        // upon we get a `&dyn IrpDispatch` from a Box, it extract the address of "fat pointer" directly for us which is 8 bytes on x64(sizeof(void*))
        // thus we can safely transfer it to native API for dynamic dispatch
        if let Some(mut value) = dispatch_handler {
            // copy the "fat pointer" from Box into device extension
            // `Box::as_mut()` will return a "fat pointer" separated by [rax:rdx] which will be efficiently stored on the stack
            // and then copied into device extension by us, as u may guessed, `ptr::write` here will use three registers(rcx, rdx, r8) as its arguments
            // since the return value of `value.as_mut()` take 16 bytes(passed in as [rdx, r8])
            unsafe {
                ptr::write(
                    (*device).DeviceExtension.cast(),
                    DispatchContext {
                        irp_handler: value.as_mut(),
                        attach_to: ptr::null_mut(),
                    },
                );
            }
            dispatch_object = Some(value);
        }

        Ok(Self {
            name: dev_name,
            symbol_name: device_dos_name,
            object: NonNull::new(device).unwrap(),
            dispatch_object,
        })
    }

    /// create a named device in namespace `\Device\`
    #[deprecated(since = "0.1.4", note = "please use `OwnedDevice::new` instead")]
    pub fn with_name(
        driver: &Driver,
        name: &str,
        symbol_name: Option<&str>,
        dispatch_handler: Option<Box<dyn IrpDispatch>>,
    ) -> Result<Self, NtError> {
        let mut device: PDEVICE_OBJECT = ptr::null_mut();

        let mut ext_size = 0u32;

        if dispatch_handler.is_some() {
            ext_size = mem::size_of::<DispatchContext>() as _;
        }

        if name.is_empty() {
            return Err(NtError::new(STATUS_INVALID_PARAMETER_2));
        }

        let mut device_name = utils::utf16_from_str(("\\Device\\".to_owned() + name).as_str())
            .ok_or(NtError::new(STATUS_INSUFFICIENT_RESOURCES))?;

        let mut status = unsafe {
            IoCreateDevice(
                driver.as_raw(),
                ext_size,
                device_name.as_mut(),
                FILE_DEVICE_UNKNOWN,
                FILE_DEVICE_SECURE_OPEN,
                0,
                &mut device,
            )
        };

        cvt(status)?;

        let mut dispatch_object: Option<Box<dyn IrpDispatch>> = None;

        // destroy the `dispatch_object` here
        // write the `dyn IrpDispatch` into `DeviceExtension`
        if let Some(mut value) = dispatch_handler {
            unsafe {
                ptr::write(
                    (*device).DeviceExtension.cast(),
                    DispatchContext {
                        irp_handler: value.as_mut(),
                        attach_to: ptr::null_mut(),
                    },
                );
            }
            dispatch_object = Some(value);
        }

        let mut device_dos_name: Option<Box<UNICODE_STRING>> = None;

        if let Some(name) = symbol_name {
            let mut sym_name = utils::utf16_from_str(("\\DosDevices\\".to_owned() + name).as_str())
                .ok_or(NtError::new(STATUS_INSUFFICIENT_RESOURCES))?;

            status = unsafe { IoCreateSymbolicLink(sym_name.as_mut(), device_name.as_mut()) };

            if !nt_success(status) {
                unsafe {
                    IoDeleteDevice(device);
                }
                return Err(NtError::new(status));
            }

            device_dos_name = Some(sym_name);
        }

        Ok(Self {
            name: Some(device_name),
            symbol_name: device_dos_name,
            object: NonNull::new(device).unwrap(),
            dispatch_object,
        })
    }

    /// attach to a existing device `target`
    pub fn attach(&mut self, target: PDEVICE_OBJECT) -> Result<(), NtError> {
        let device = self.object.as_ptr();
        let dev_ext = self.get_ext_mut();

        if dev_ext.attach_to.is_null() {
            cvt(unsafe { IoAttachDeviceToDeviceStackSafe(target, device, &mut dev_ext.attach_to) })
        } else {
            Err(NtError::new(STATUS_DEVICE_ALREADY_ATTACHED))
        }
    }

    pub fn dettach(&mut self) {
        let target = self.get_attached_device();

        if !target.is_null() {
            unsafe {
                IoDetachDevice(target);
            }
        }
    }

    pub fn get_attached_device(&self) -> PDEVICE_OBJECT {
        let dev_ext = unsafe { &*(self.object.as_ref().DeviceExtension as *mut DispatchContext) };

        dev_ext.attach_to
    }

    // fn get_ext(&self) -> &DispatchContext {
    //     unsafe { &*(self.object.as_ref().DeviceExtension as *const DispatchContext) }
    // }

    fn get_ext_mut(&mut self) -> &mut DispatchContext {
        unsafe { &mut *(self.object.as_ref().DeviceExtension as *mut DispatchContext) }
    }

    pub fn as_raw(&self) -> PDEVICE_OBJECT {
        self.object.as_ptr()
    }

    pub fn as_ref(&self) -> &DEVICE_OBJECT {
        unsafe { self.object.as_ref() }
    }

    pub fn as_ref_mut(&mut self) -> &mut DEVICE_OBJECT {
        unsafe { self.object.as_mut() }
    }

    pub fn device_name(&self) -> Option<&Box<UNICODE_STRING>> {
        self.name.as_ref()
    }

    pub fn symbolic_name(&self) -> Option<&Box<UNICODE_STRING>> {
        self.symbol_name.as_ref()
    }
}

impl Deref for OwnedDevice {
    type Target = _DEVICE_OBJECT;
    fn deref(&self) -> &Self::Target {
        unsafe { self.object.as_ref() }
    }
}

impl DerefMut for OwnedDevice {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { self.object.as_mut() }
    }
}

impl Drop for OwnedDevice {
    fn drop(&mut self) {
        // delte symbolic link
        if let Some(value) = &mut self.symbol_name {
            let _ = unsafe { IoDeleteSymbolicLink(value.as_mut()) };
        }

        // it is time for destroy the `dyn IrpDispatch`
        // dropped by Rust

        let dev_ext = unsafe { &*(self.object.as_ref().DeviceExtension as *const DispatchContext) };

        if !dev_ext.attach_to.is_null() {
            unsafe { IoDetachDevice(dev_ext.attach_to) };
        }

        // delete the device
        unsafe { IoDeleteDevice(self.object.as_ptr()) };
    }
}

extern "C" fn irp_dispatch_stub(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    let mut status = STATUS_SUCCESS;
    let ext = unsafe { (*device).DeviceExtension };

    // complete the IRP as STATUS_NOT_IMPLEMENTED when not extension found
    // this field must be non-null if user specified `dispatch_handler` in device creation
    if ext.is_null() {
        status = STATUS_NOT_IMPLEMENTED;

        unsafe {
            (*irp).IoStatus.__bindgen_anon_1.Status = status;
            IofCompleteRequest(irp, IO_NO_INCREMENT as _);
        }

        return status;
    }

    // this code maybe consfused to c/c++ programmer
    // read the dynamic handler out from device extension
    let dispatch_context = unsafe { ptr::read(ext as *mut DispatchContext) };

    // there is an alternative:
    // read a &dyn IrpDispatch(size of 16 bytes) from a *const &dyn IrpDispatch(size of 8 bytes)
    // let dispatch_context: &dyn IrpDispatch = unsafe { ptr::read(ext as _) };
    match dispatch_context.irp_handler.dispatch(device, irp) {
        Ok(length) => {
            status = STATUS_SUCCESS;
            unsafe { (*irp).IoStatus.Information = length }
        }
        Err(e) => status = e.code(),
    }

    // always set the Status field
    unsafe { (*irp).IoStatus.__bindgen_anon_1.Status = status };

    match status {
        STATUS_PENDING => IoMarkIrpPending(irp),
        _ => unsafe { IofCompleteRequest(irp, IO_NO_INCREMENT as _) },
    }

    return status;
}

unsafe impl Sync for Driver {}

/// A Referenced DeviceObject wrapper
#[repr(transparent)]
pub struct DeviceObject(KernelObject<_DEVICE_OBJECT>);

impl DeviceObject {
    pub fn from_name(name: &str) -> Result<Self, NtError> {
        let mut raw_dev: PDEVICE_OBJECT = ptr::null_mut();
        let mut file_obj: PFILE_OBJECT = ptr::null_mut();

        let mut uname: Box<wdk_sys::_UNICODE_STRING> =
            utils::utf16_from_str(name).ok_or(NtError::new(STATUS_INSUFFICIENT_RESOURCES))?;

        cvt(unsafe {
            // forget this file object here, since we will dereference device object in `drop`
            // see https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iogetdeviceobjectpointer for details
            IoGetDeviceObjectPointer(uname.as_mut(), FILE_READ_DATA, &mut file_obj, &mut raw_dev)
        })?;

        Ok(Self(KernelObject::new(raw_dev).unwrap()))
    }

    /// this will return the topmost device in the device stack
    pub fn from_attached(device: PDEVICE_OBJECT) -> Self {
        let device = unsafe { IoGetAttachedDeviceReference(device) };

        Self(KernelObject::new(device).unwrap())
    }

    /// get device object from a file object
    pub fn from_file(file_object: PFILE_OBJECT) -> Self {
        let device = unsafe { IoGetRelatedDeviceObject(file_object) };

        Self(KernelObject::new(device).unwrap())
    }
}

impl Deref for DeviceObject {
    type Target = KernelObject<_DEVICE_OBJECT>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
