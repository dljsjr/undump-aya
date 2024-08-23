#![no_std]

/// Duped from the aya_ebpf crate. Userspace doesn't depend on that crate, and this lib
/// is used by both kspace and uspace.
pub const COMMAND_NAME_LEN: usize = 16;

// With alignment, 8172 bytes. This works.
pub const MAX_SAMPLE_DATA_BUFFER_SIZE: usize = 8148;

// With alignment, 8176 bytes. This *doesn't* work.
// pub const MAX_SAMPLE_DATA_BUFFER_SIZE: usize = 8152;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UdsSocketCapture<const N: usize> {
    pub len: u32,
    pub pid: u32,
    pub command: [u8; COMMAND_NAME_LEN],
    pub buff: [u8; N],
}

impl<const N: usize> Default for UdsSocketCapture<N> {
    fn default() -> Self {
        Self {
            len: Default::default(),
            pid: Default::default(),
            command: Default::default(),
            buff: [0u8; N],
        }
    }
}

#[cfg(feature = "aya")]
unsafe impl<const N: usize> aya::Pod for UdsSocketCapture<N> {}
