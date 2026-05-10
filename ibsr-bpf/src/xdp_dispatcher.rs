//! libxdp chained-program dispatcher attach for IBSR's XDP counter.
//!
//! Mirror of nr-guard's xdp_loader.rs. Lets IBSR coexist with nr-guard
//! (or any other libxdp-aware XDP program) on the same interface —
//! libxdp's dispatcher fans out to each chained program in priority
//! order, all returning XDP_PASS in IBSR's case.
//!
//! libbpf-rs still owns the BPF object load + map operations; we only
//! swap the kernel attach call.

use std::ffi::{CStr, CString};
use std::os::fd::{AsFd, AsRawFd};

use libxdp_sys::{
    libxdp_strerror, xdp_attach_mode_XDP_MODE_NATIVE, xdp_attach_mode_XDP_MODE_SKB,
    xdp_program, xdp_program__attach, xdp_program__detach, xdp_program__from_fd,
    xdp_program__id,
};

#[derive(Debug, thiserror::Error)]
pub enum DispatcherError {
    #[error("if_nametoindex({iface}) failed: {source}")]
    NoSuchInterface {
        iface: String,
        source: std::io::Error,
    },
    #[error("xdp_program__from_fd returned NULL — invalid program FD?")]
    InvalidProgramFd,
    #[error("libxdp attach to {iface} failed in both native and skb modes (err={code}): {msg}")]
    AttachFailed {
        iface: String,
        code: i32,
        msg: String,
    },
}

/// Owned handle to the dispatcher attach. Detaches on Drop.
pub struct XdpDispatcherHandle {
    prog: *mut xdp_program,
    ifindex: i32,
    mode: u32,
    iface: String,
}

unsafe impl Send for XdpDispatcherHandle {}

impl XdpDispatcherHandle {
    pub fn dispatcher_id(&self) -> u32 {
        if self.prog.is_null() {
            return 0;
        }
        unsafe { xdp_program__id(self.prog) }
    }

    pub fn summary(&self) -> String {
        let mode = match self.mode {
            m if m == xdp_attach_mode_XDP_MODE_NATIVE => "native",
            m if m == xdp_attach_mode_XDP_MODE_SKB => "skb",
            _ => "?",
        };
        format!(
            "iface={} mode={} dispatcher_prog_id={}",
            self.iface,
            mode,
            self.dispatcher_id(),
        )
    }
}

impl Drop for XdpDispatcherHandle {
    fn drop(&mut self) {
        if self.prog.is_null() {
            return;
        }
        let _ = unsafe { xdp_program__detach(self.prog, self.ifindex, self.mode, 0) };
        // libbpf-rs owns the underlying BPF object; don't xdp_program__close
        // here — that would free libbpf state libbpf-rs still holds.
        self.prog = std::ptr::null_mut();
    }
}

fn strerror(err: i32) -> String {
    let mut buf = [0u8; 256];
    let written = unsafe {
        libxdp_strerror(err, buf.as_mut_ptr() as *mut std::os::raw::c_char, buf.len())
    };
    if written < 0 {
        return format!("errno {}", err);
    }
    let cstr = CStr::from_bytes_until_nul(&buf).unwrap_or(c"<unknown>");
    cstr.to_string_lossy().into_owned()
}

fn ifindex_for(iface: &str) -> Result<i32, DispatcherError> {
    let cname = CString::new(iface).map_err(|_| DispatcherError::NoSuchInterface {
        iface: iface.to_string(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidInput, "iface name has NUL"),
    })?;
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        return Err(DispatcherError::NoSuchInterface {
            iface: iface.to_string(),
            source: std::io::Error::last_os_error(),
        });
    }
    Ok(idx as i32)
}

/// Attach `prog_fd` (a libbpf-rs-loaded XDP program FD) to `iface` via
/// libxdp's dispatcher. Tries native mode first, falls back to SKB.
pub fn attach<F: AsFd>(iface: &str, prog_fd: F) -> Result<XdpDispatcherHandle, DispatcherError> {
    let raw_fd = prog_fd.as_fd().as_raw_fd();
    let ifindex = ifindex_for(iface)?;

    let xprog = unsafe { xdp_program__from_fd(raw_fd) };
    if xprog.is_null() {
        return Err(DispatcherError::InvalidProgramFd);
    }

    let err =
        unsafe { xdp_program__attach(xprog, ifindex, xdp_attach_mode_XDP_MODE_NATIVE, 0) };
    if err == 0 {
        return Ok(XdpDispatcherHandle {
            prog: xprog,
            ifindex,
            mode: xdp_attach_mode_XDP_MODE_NATIVE,
            iface: iface.to_string(),
        });
    }
    // Try SKB.
    let err =
        unsafe { xdp_program__attach(xprog, ifindex, xdp_attach_mode_XDP_MODE_SKB, 0) };
    if err == 0 {
        return Ok(XdpDispatcherHandle {
            prog: xprog,
            ifindex,
            mode: xdp_attach_mode_XDP_MODE_SKB,
            iface: iface.to_string(),
        });
    }
    Err(DispatcherError::AttachFailed {
        iface: iface.to_string(),
        code: err,
        msg: strerror(err),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ifindex_lo_is_one() {
        assert_eq!(ifindex_for("lo").unwrap(), 1);
    }

    #[test]
    fn test_ifindex_garbage_errors() {
        assert!(ifindex_for("definitely-not-an-iface-asdfqwerty").is_err());
    }

    #[test]
    fn test_strerror_non_empty() {
        assert!(!strerror(-22).is_empty());
    }
}
