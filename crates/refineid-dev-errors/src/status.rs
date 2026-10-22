// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

//! Windows status values by the names `winerror.h` and `scarderr.h` give
//! them.

/// A Windows status value: a `u32` such as a Card Module `DWORD` or a
/// Win32 error, or an `i32` `HRESULT`.
pub trait StatusCode {
    /// The status as its 32 bits.
    fn bits(self) -> u32;
}

impl StatusCode for u32 {
    fn bits(self) -> u32 {
        self
    }
}

impl StatusCode for i32 {
    fn bits(self) -> u32 {
        self.cast_unsigned()
    }
}

impl StatusCode for &u32 {
    fn bits(self) -> u32 {
        *self
    }
}

impl StatusCode for &i32 {
    fn bits(self) -> u32 {
        self.cast_unsigned()
    }
}

/// The severity bit of a failure `HRESULT` (`winerror.h`, `SEVERITY_ERROR`
/// shifted into place).
const SEVERITY_ERROR_BIT: u32 = 1 << 31;

/// The facility of an `HRESULT` that carries a Win32 error
/// (`winerror.h` `FACILITY_WIN32`).
const FACILITY_WIN32: u32 = 7;

/// Where the facility sits in an `HRESULT` (`winerror.h`
/// `HRESULT_FACILITY`).
const FACILITY_SHIFT: u32 = 16;

/// The code bits of an `HRESULT` (`winerror.h` `HRESULT_CODE`).
const CODE_MASK: u32 = 0xFFFF;

/// The bits `HRESULT_FROM_WIN32` sets above a Win32 error.
const WIN32_HRESULT_PREFIX: u32 = SEVERITY_ERROR_BIT | (FACILITY_WIN32 << FACILITY_SHIFT);

/// `bits` by its name, `HRESULT_FROM_WIN32(name)` for a wrapped Win32
/// error, or in hexadecimal when it has no name here.
pub fn describe(bits: u32) -> String {
    if let Some(name) = names::named(bits) {
        return name.to_owned();
    }
    if bits & !CODE_MASK == WIN32_HRESULT_PREFIX
        && let Some(name) = names::named(bits & CODE_MASK)
    {
        return format!("HRESULT_FROM_WIN32({name})");
    }
    format!("{bits:#010X}")
}

#[cfg(windows)]
mod names {
    //! The names, from the Windows SDK constants `windows-sys` carries.

    /// `(value, name)` for each listed `HRESULT`.
    macro_rules! hresults {
        ($($name:ident),* $(,)?) => {
            &[$((windows_sys::Win32::Foundation::$name.cast_unsigned(), stringify!($name))),*]
        };
    }

    /// `(value, name)` for each listed Win32 error.
    macro_rules! win32_errors {
        ($($name:ident),* $(,)?) => {
            &[$((windows_sys::Win32::Foundation::$name, stringify!($name))),*]
        };
    }

    /// The `HRESULT`s `RefineID` meets: every smart card status, the
    /// key storage provider's `NTE_` statuses, the common COM failures, and
    /// the Bluetooth ATT errors.
    const HRESULTS: &[(u32, &str)] = hresults![
        SCARD_E_BAD_SEEK,
        SCARD_E_CANCELLED,
        SCARD_E_CANT_DISPOSE,
        SCARD_E_CARD_UNSUPPORTED,
        SCARD_E_CERTIFICATE_UNAVAILABLE,
        SCARD_E_COMM_DATA_LOST,
        SCARD_E_DIR_NOT_FOUND,
        SCARD_E_DUPLICATE_READER,
        SCARD_E_FILE_NOT_FOUND,
        SCARD_E_ICC_CREATEORDER,
        SCARD_E_ICC_INSTALLATION,
        SCARD_E_INSUFFICIENT_BUFFER,
        SCARD_E_INVALID_ATR,
        SCARD_E_INVALID_CHV,
        SCARD_E_INVALID_HANDLE,
        SCARD_E_INVALID_PARAMETER,
        SCARD_E_INVALID_TARGET,
        SCARD_E_INVALID_VALUE,
        SCARD_E_NOT_READY,
        SCARD_E_NOT_TRANSACTED,
        SCARD_E_NO_ACCESS,
        SCARD_E_NO_DIR,
        SCARD_E_NO_FILE,
        SCARD_E_NO_KEY_CONTAINER,
        SCARD_E_NO_MEMORY,
        SCARD_E_NO_PIN_CACHE,
        SCARD_E_NO_READERS_AVAILABLE,
        SCARD_E_NO_SERVICE,
        SCARD_E_NO_SMARTCARD,
        SCARD_E_NO_SUCH_CERTIFICATE,
        SCARD_E_PCI_TOO_SMALL,
        SCARD_E_PIN_CACHE_EXPIRED,
        SCARD_E_PROTO_MISMATCH,
        SCARD_E_READER_UNAVAILABLE,
        SCARD_E_READER_UNSUPPORTED,
        SCARD_E_READ_ONLY_CARD,
        SCARD_E_SERVER_TOO_BUSY,
        SCARD_E_SERVICE_STOPPED,
        SCARD_E_SHARING_VIOLATION,
        SCARD_E_SYSTEM_CANCELLED,
        SCARD_E_TIMEOUT,
        SCARD_E_UNEXPECTED,
        SCARD_E_UNKNOWN_CARD,
        SCARD_E_UNKNOWN_READER,
        SCARD_E_UNKNOWN_RES_MNG,
        SCARD_E_UNSUPPORTED_FEATURE,
        SCARD_E_WRITE_TOO_MANY,
        SCARD_F_COMM_ERROR,
        SCARD_F_INTERNAL_ERROR,
        SCARD_F_UNKNOWN_ERROR,
        SCARD_F_WAITED_TOO_LONG,
        SCARD_P_SHUTDOWN,
        SCARD_W_CACHE_ITEM_NOT_FOUND,
        SCARD_W_CACHE_ITEM_STALE,
        SCARD_W_CACHE_ITEM_TOO_BIG,
        SCARD_W_CANCELLED_BY_USER,
        SCARD_W_CARD_NOT_AUTHENTICATED,
        SCARD_W_CHV_BLOCKED,
        SCARD_W_EOF,
        SCARD_W_REMOVED_CARD,
        SCARD_W_RESET_CARD,
        SCARD_W_SECURITY_VIOLATION,
        SCARD_W_UNPOWERED_CARD,
        SCARD_W_UNRESPONSIVE_CARD,
        SCARD_W_UNSUPPORTED_CARD,
        SCARD_W_WRONG_CHV,
        NTE_BAD_ALGID,
        NTE_BAD_DATA,
        NTE_BAD_FLAGS,
        NTE_BAD_HASH,
        NTE_BAD_KEY,
        NTE_BAD_KEYSET,
        NTE_BAD_LEN,
        NTE_BAD_SIGNATURE,
        NTE_BAD_TYPE,
        NTE_BUFFER_TOO_SMALL,
        NTE_DEVICE_NOT_READY,
        NTE_EXISTS,
        NTE_FAIL,
        NTE_INVALID_HANDLE,
        NTE_INVALID_PARAMETER,
        NTE_KEYSET_NOT_DEF,
        NTE_NO_KEY,
        NTE_NO_MEMORY,
        NTE_NOT_FOUND,
        NTE_NOT_SUPPORTED,
        NTE_PERM,
        NTE_PROVIDER_DLL_FAIL,
        NTE_SILENT_CONTEXT,
        NTE_USER_CANCELLED,
        E_ABORT,
        E_ACCESSDENIED,
        E_BOUNDS,
        E_FAIL,
        E_HANDLE,
        E_ILLEGAL_METHOD_CALL,
        E_INVALIDARG,
        E_NOTIMPL,
        E_OUTOFMEMORY,
        E_POINTER,
        E_UNEXPECTED,
        RO_E_CLOSED,
        E_BLUETOOTH_ATT_ATTRIBUTE_NOT_FOUND,
        E_BLUETOOTH_ATT_ATTRIBUTE_NOT_LONG,
        E_BLUETOOTH_ATT_INSUFFICIENT_AUTHENTICATION,
        E_BLUETOOTH_ATT_INSUFFICIENT_AUTHORIZATION,
        E_BLUETOOTH_ATT_INSUFFICIENT_ENCRYPTION,
        E_BLUETOOTH_ATT_INSUFFICIENT_ENCRYPTION_KEY_SIZE,
        E_BLUETOOTH_ATT_INSUFFICIENT_RESOURCES,
        E_BLUETOOTH_ATT_INVALID_ATTRIBUTE_VALUE_LENGTH,
        E_BLUETOOTH_ATT_INVALID_HANDLE,
        E_BLUETOOTH_ATT_INVALID_OFFSET,
        E_BLUETOOTH_ATT_INVALID_PDU,
        E_BLUETOOTH_ATT_PREPARE_QUEUE_FULL,
        E_BLUETOOTH_ATT_READ_NOT_PERMITTED,
        E_BLUETOOTH_ATT_REQUEST_NOT_SUPPORTED,
        E_BLUETOOTH_ATT_UNKNOWN_ERROR,
        E_BLUETOOTH_ATT_UNLIKELY,
        E_BLUETOOTH_ATT_UNSUPPORTED_GROUP_TYPE,
        E_BLUETOOTH_ATT_WRITE_NOT_PERMITTED,
    ];

    /// The Win32 errors `RefineID` meets: file, pipe, device and wait
    /// failures.
    const WIN32_ERRORS: &[(u32, &str)] = win32_errors![
        ERROR_INVALID_FUNCTION,
        ERROR_FILE_NOT_FOUND,
        ERROR_PATH_NOT_FOUND,
        ERROR_ACCESS_DENIED,
        ERROR_INVALID_HANDLE,
        ERROR_NOT_ENOUGH_MEMORY,
        ERROR_INVALID_DATA,
        ERROR_NOT_READY,
        ERROR_BAD_LENGTH,
        ERROR_GEN_FAILURE,
        ERROR_SHARING_VIOLATION,
        ERROR_LOCK_VIOLATION,
        ERROR_NOT_SUPPORTED,
        ERROR_FILE_EXISTS,
        ERROR_INVALID_PARAMETER,
        ERROR_BROKEN_PIPE,
        ERROR_SEM_TIMEOUT,
        ERROR_INSUFFICIENT_BUFFER,
        ERROR_ALREADY_EXISTS,
        ERROR_BAD_FORMAT,
        ERROR_BAD_PIPE,
        ERROR_PIPE_BUSY,
        ERROR_NO_DATA,
        ERROR_PIPE_NOT_CONNECTED,
        ERROR_MORE_DATA,
        ERROR_PIPE_CONNECTED,
        ERROR_NOACCESS,
        ERROR_OPERATION_ABORTED,
        ERROR_IO_PENDING,
        ERROR_INVALID_FLAGS,
        ERROR_SERVICE_NOT_ACTIVE,
        ERROR_NOT_FOUND,
        ERROR_NO_SUCH_DEVICE,
        ERROR_CANCELLED,
        ERROR_TIMEOUT,
        ERROR_INSTALL_FAILURE,
        ERROR_DEVICE_NOT_CONNECTED,
        ERROR_DEVICE_NOT_AVAILABLE,
    ];

    /// The name of `bits`, an `HRESULT` or a Win32 error.
    pub(super) fn named(bits: u32) -> Option<&'static str> {
        HRESULTS
            .iter()
            .chain(WIN32_ERRORS)
            .find(|(value, _)| *value == bits)
            .map(|(_, name)| *name)
    }
}

#[cfg(not(windows))]
mod names {
    //! No names off Windows, where no Windows status arises.

    /// No status has a name here.
    pub(super) const fn named(_bits: u32) -> Option<&'static str> {
        None
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::describe;
    use crate::status::StatusCode;
    use windows_sys::Win32::Foundation::{
        E_ACCESSDENIED, ERROR_BROKEN_PIPE, ERROR_DEVICE_NOT_AVAILABLE, SCARD_E_NO_SERVICE,
    };

    #[test]
    fn a_smart_card_status_is_named() {
        assert_eq!(describe(SCARD_E_NO_SERVICE.bits()), "SCARD_E_NO_SERVICE");
    }

    #[test]
    fn a_win32_error_is_named() {
        assert_eq!(describe(ERROR_BROKEN_PIPE), "ERROR_BROKEN_PIPE");
    }

    #[test]
    fn an_hresult_is_named_before_its_win32_form() {
        assert_eq!(describe(E_ACCESSDENIED.bits()), "E_ACCESSDENIED");
    }

    #[test]
    fn a_wrapped_win32_error_is_named_inside_its_wrapper() {
        let wrapped = super::WIN32_HRESULT_PREFIX | ERROR_DEVICE_NOT_AVAILABLE;
        assert_eq!(
            describe(wrapped),
            "HRESULT_FROM_WIN32(ERROR_DEVICE_NOT_AVAILABLE)"
        );
    }
}

#[cfg(test)]
mod portable_tests {
    use super::describe;

    /// A status no table names: the reserved top of the `HRESULT` space.
    const UNNAMED: u32 = u32::MAX;

    #[test]
    fn an_unnamed_status_is_written_in_hexadecimal() {
        assert_eq!(describe(UNNAMED), "0xFFFFFFFF");
    }
}
