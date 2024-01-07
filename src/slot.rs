use std::{
    ffi::c_void,
    num::NonZeroUsize,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    ptr::{copy_nonoverlapping, NonNull},
};

use anyhow::{Context, Result};
use nix::sys::mman::{mmap, munmap, MapFlags, ProtFlags};
use x86_64::structures::paging::PhysFrame;

use crate::kvm::{KvmGuestMemFdFlags, Page, VmHandle};

pub struct Slot {
    gpa: PhysFrame,
    shared_mapping: AnonymousPrivateMapping,
    restricted_fd: OwnedFd,
}

impl Slot {
    pub fn for_launch_update(vm: &VmHandle, gpa: PhysFrame, pages: &[Page]) -> Result<Self> {
        let shared_mapping = AnonymousPrivateMapping::for_private_mapping(pages)?;

        let len = u64::try_from(pages.len() * 0x1000)?;
        let restricted_fd = vm
            .create_guest_memfd(len, KvmGuestMemFdFlags::empty())
            .context("failed to create guest memfd")?;

        Ok(Self {
            gpa,
            shared_mapping,
            restricted_fd,
        })
    }

    pub fn gpa(&self) -> PhysFrame {
        self.gpa
    }

    pub fn shared_mapping(&self) -> &AnonymousPrivateMapping {
        &self.shared_mapping
    }

    pub fn restricted_fd(&self) -> BorrowedFd {
        self.restricted_fd.as_fd()
    }
}

pub struct AnonymousPrivateMapping {
    ptr: NonNull<c_void>,
    len: NonZeroUsize,
}

impl AnonymousPrivateMapping {
    pub fn for_private_mapping(pages: &[Page]) -> Result<Self> {
        let this = Self::new(pages.len() * 0x1000)?;

        unsafe {
            copy_nonoverlapping(pages.as_ptr(), this.ptr.as_ptr().cast(), pages.len());
        }

        Ok(this)
    }

    pub fn new(len: usize) -> Result<Self> {
        let len = NonZeroUsize::new(len).context("cannot create empty mmap")?;

        let res = unsafe {
            mmap(
                None,
                len,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE,
                0,
                0,
            )
        };
        let ptr = res.context("failed to mmap memory")?;
        let ptr = NonNull::new(ptr).unwrap();

        Ok(Self { ptr, len })
    }

    pub fn as_ptr(&self) -> NonNull<c_void> {
        self.ptr
    }

    pub fn len(&self) -> NonZeroUsize {
        self.len
    }
}

unsafe impl Send for AnonymousPrivateMapping {}
unsafe impl Sync for AnonymousPrivateMapping {}

impl Drop for AnonymousPrivateMapping {
    fn drop(&mut self) {
        let res = unsafe { munmap(self.ptr.as_ptr(), self.len.get()) };
        res.unwrap();
    }
}
