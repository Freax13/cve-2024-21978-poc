use std::{
    fs::OpenOptions,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
        unix::prelude::OpenOptionsExt,
    },
};

use anyhow::{ensure, Context, Result};
use bitflags::bitflags;
use bytemuck::{Pod, Zeroable};
use nix::{ioctl_readwrite, ioctl_write_int_bad, ioctl_write_ptr, libc::O_SYNC, request_code_none};
use tracing::debug;

use crate::{
    slot::Slot,
    snp_types::{GuestPolicy, PageType, VmplPermissions},
};

const KVMIO: u8 = 0xAE;

pub struct KvmHandle {
    fd: OwnedFd,
}

impl KvmHandle {
    pub fn new() -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(O_SYNC)
            .open("/dev/kvm")
            .context("failed to open /dev/kvm")?;
        let fd = OwnedFd::from(file);

        ioctl_write_int_bad!(kvm_get_api_version, request_code_none!(KVMIO, 0x00));
        let res = unsafe { kvm_get_api_version(fd.as_raw_fd(), 0) };
        let version = res.context("failed to execute get_api_version")?;
        debug!(version, "determined kvm version");
        ensure!(version >= 12, "unsupported kvm api version ({version})");

        Ok(Self { fd })
    }

    pub fn create_snp_vm(&self) -> Result<VmHandle> {
        debug!("creating vm");

        ioctl_write_int_bad!(kvm_create_vm, request_code_none!(KVMIO, 0x01));
        let res = unsafe { kvm_create_vm(self.fd.as_raw_fd(), 3) };
        let raw_fd = res.context("failed to create vm")?;
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        Ok(VmHandle { fd })
    }
}

pub struct VmHandle {
    fd: OwnedFd,
}

impl VmHandle {
    unsafe fn map_private_memory(
        &self,
        slot: u16,
        guest_phys_addr: u64,
        memory_size: u64,
        userspace_addr: u64,
        restricted_fd: BorrowedFd,
        restricted_offset: u64,
    ) -> Result<()> {
        debug!("mapping private memory");

        let region = KvmUserspaceMemoryRegion2 {
            region: KvmUserspaceMemoryRegion {
                slot: u32::from(slot),
                flags: KvmUserspaceMemoryRegionFlags::KVM_MEM_PRIVATE,
                guest_phys_addr,
                memory_size,
                userspace_addr,
            },
            restricted_offset,
            restricted_fd: Some(restricted_fd),
            _pad1: 0,
            _pad2: [0; 14],
        };

        ioctl_write_ptr!(
            kvm_set_user_memory_region2,
            KVMIO,
            0x49,
            KvmUserspaceMemoryRegion2
        );
        let res = unsafe { kvm_set_user_memory_region2(self.fd.as_raw_fd(), &region) };
        res.context("failed to map private memory")?;

        Ok(())
    }

    pub unsafe fn map_encrypted_memory(&self, id: u16, slot: &Slot) -> Result<()> {
        debug!(id, guest_phys_addr = %format_args!("{:x?}", slot.gpa()), "mapping private memory");

        let shared_mapping = slot.shared_mapping();
        let restricted_fd = slot.restricted_fd();

        unsafe {
            self.map_private_memory(
                id,
                slot.gpa().start_address().as_u64(),
                u64::try_from(shared_mapping.len().get())?,
                u64::try_from(shared_mapping.as_ptr().as_ptr() as usize)?,
                restricted_fd,
                0,
            )?;
        }

        Ok(())
    }

    unsafe fn memory_encrypt_op<'a>(
        &self,
        payload: KvmSevCmdPayload<'a>,
        sev_handle: Option<&SevHandle>,
    ) -> Result<KvmSevCmdPayload<'a>> {
        debug!("executing memory encryption operation");

        let mut cmd = KvmSevCmd {
            payload,
            error: 0,
            sev_fd: sev_handle.map(|sev_handle| sev_handle.fd.as_fd()),
        };

        ioctl_readwrite!(kvm_memory_encrypt_op, KVMIO, 0xba, u64);
        let res =
            kvm_memory_encrypt_op(self.fd.as_raw_fd(), &mut cmd as *mut KvmSevCmd as *mut u64);
        ensure!(cmd.error == 0);
        res.context("failed to execute memory encryption operation")?;

        Ok(cmd.payload)
    }

    pub fn sev_snp_init(&self) -> Result<()> {
        let mut data = KvmSnpInit {
            flags: KvmSnpInitFlags::empty(),
        };
        let payload = KvmSevCmdPayload::KvmSevSnpInit { data: &mut data };
        let res = unsafe { self.memory_encrypt_op(payload, None) };
        res.context("failed to initialize sev snp")?;
        Ok(())
    }

    pub fn sev_snp_launch_start(&self, policy: GuestPolicy, sev_handle: &SevHandle) -> Result<()> {
        debug!("starting snp launch");
        let mut data = KvmSevSnpLaunchStart {
            policy,
            ma_uaddr: 0,
            ma_en: 0,
            imi_en: 0,
            gosvw: [0; 16],
            _pad: [0; 6],
        };
        let payload = KvmSevCmdPayload::KvmSevSnpLaunchStart { data: &mut data };
        let res = unsafe { self.memory_encrypt_op(payload, Some(sev_handle)) };
        res.context("failed to start sev snp launch")?;
        Ok(())
    }

    pub fn sev_snp_launch_update(
        &self,
        start_addr: u64,
        uaddr: u64,
        len: u32,
        page_type: PageType,
        vmpl1_perms: VmplPermissions,
        // FIXME: figure out if we need a sev handle for this operation
        sev_handle: &SevHandle,
    ) -> Result<()> {
        debug!("updating snp launch");

        ensure!(
            start_addr & 0xfff == 0,
            "start address is not properly aligned"
        );
        let start_gfn = start_addr >> 12;

        let mut data = KvmSevSnpLaunchUpdate {
            start_gfn,
            uaddr,
            len,
            imi_page: 0,
            page_type: page_type as u8,
            vmpl3_perms: VmplPermissions::empty(),
            vmpl2_perms: VmplPermissions::empty(),
            vmpl1_perms,
        };
        let payload = KvmSevCmdPayload::KvmSevSnpLaunchUpdate { data: &mut data };
        let res = unsafe { self.memory_encrypt_op(payload, Some(sev_handle)) };
        res.context("failed to update sev snp launch")?;
        Ok(())
    }

    pub fn sev_snp_launch_finish(
        &self,
        // FIXME: figure out if we need a sev handle for this operation
        sev_handle: &SevHandle,
        host_data: [u8; 32],
    ) -> Result<()> {
        debug!("finishing snp launch");

        let mut data = KvmSevSnpLaunchFinish {
            id_block_uaddr: 0,
            id_auth_uaddr: 0,
            id_block_en: 0,
            auth_key_en: 0,
            host_data,
            _pad: [0; 6],
        };
        let payload = KvmSevCmdPayload::KvmSevSnpLaunchFinish { data: &mut data };
        let res = unsafe { self.memory_encrypt_op(payload, Some(sev_handle)) };
        res.context("failed to finish sev snp launch")?;
        Ok(())
    }

    pub fn sev_snp_guest_status(&self) -> Result<SnpGuestStatusBuffer> {
        let mut data = SnpGuestStatusBuffer {
            policy: 0,
            asid: 0,
            state: 0,
            reserved: 0,
            reserved2: [0; 2],
            vcek_dis: 0,
            reserved3: 0,
            reserved4: 0,
        };
        let payload = KvmSevCmdPayload::KvmSevSnpGuestStatus { data: &mut data };
        let res = unsafe { self.memory_encrypt_op(payload, None) };
        res.context("failed to query guest status")?;
        Ok(data)
    }

    pub fn create_guest_memfd(&self, size: u64, flags: KvmGuestMemFdFlags) -> Result<OwnedFd> {
        debug!(size, ?flags, "creating guest memfd");

        #[repr(C)]
        struct KvmCreateGuestMemfd {
            size: u64,
            flags: KvmGuestMemFdFlags,
            reserved: [u64; 6],
        }

        let mut data = KvmCreateGuestMemfd {
            size,
            flags,
            reserved: [0; 6],
        };

        ioctl_readwrite!(kvm_create_guest_memfd, KVMIO, 0xd4, KvmCreateGuestMemfd);

        let res = unsafe { kvm_create_guest_memfd(self.fd.as_raw_fd(), &mut data) };
        let num = res.context("failed to create guest memory")?;
        Ok(unsafe { OwnedFd::from_raw_fd(num) })
    }

    pub fn sev_snp_dbg_decrypt_pfn(&self) -> Result<[u8; 4096]> {
        debug!("debug decrypting victim page");

        let mut page = [0xcc; 4096];

        let mut data = KvmSevSnpDbg {
            src_gfn: 0,
            dst_uaddr: &mut page as *const [u8; 4096] as u64,
        };
        let payload = KvmSevCmdPayload::KvmSevSnpDbgDecryptPfn { data: &mut data };
        let res = unsafe { self.memory_encrypt_op(payload, None) };
        res.context("failed to debug decrypt")?;
        Ok(page)
    }
}

#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C, align(4096))]
pub struct Page {
    bytes: [u8; 4096],
}

impl Page {
    pub const ZERO: Page = Page { bytes: [0; 4096] };
}

impl Default for Page {
    fn default() -> Self {
        Self::ZERO
    }
}

#[repr(C)]
struct KvmUserspaceMemoryRegion {
    slot: u32,
    flags: KvmUserspaceMemoryRegionFlags,
    guest_phys_addr: u64,
    /// bytes
    memory_size: u64,
    /// start of the userspace allocated memory
    userspace_addr: u64,
}

bitflags! {
    #[repr(transparent)]
    struct KvmUserspaceMemoryRegionFlags: u32 {
        const KVM_MEM_LOG_DIRTY_PAGES = 1 << 0;
        const KVM_MEM_READONLY = 1 << 1;
        const KVM_MEM_PRIVATE = 1 << 2;
    }
}

#[repr(C)]
struct KvmUserspaceMemoryRegion2<'a> {
    region: KvmUserspaceMemoryRegion,
    restricted_offset: u64,
    restricted_fd: Option<BorrowedFd<'a>>,
    _pad1: u32,
    _pad2: [u64; 14],
}

pub struct SevHandle {
    fd: OwnedFd,
}

impl SevHandle {
    pub fn new() -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(O_SYNC)
            .open("/dev/sev")
            .context("failed to open /dev/sev")?;
        let fd = OwnedFd::from(file);
        Ok(Self { fd })
    }

    pub fn sev_pdh_gen(&self) -> Result<()> {
        #[repr(C, packed)]
        struct SevIssueCmd {
            cmd: u32,   /* In */
            data: u64,  /* In */
            error: u32, /* Out */
        }

        ioctl_readwrite!(sev_issue_cmd, b'S', 0, SevIssueCmd);

        let mut payload = SevIssueCmd {
            cmd: 4,
            data: &mut () as *mut () as u64,
            error: 0,
        };
        let res = unsafe { sev_issue_cmd(self.fd.as_raw_fd(), &mut payload) };
        res.context("failed to generate pdh")?;
        Ok(())
    }
}

#[repr(C)]
struct KvmSevCmd<'a, 'b> {
    payload: KvmSevCmdPayload<'a>,
    error: u32,
    sev_fd: Option<BorrowedFd<'b>>,
}

#[allow(clippy::enum_variant_names)]
#[repr(C, u32)]
// FIXME: Figure out which ones need `&mut T` and which ones need `&T`
#[allow(dead_code)]
enum KvmSevCmdPayload<'a> {
    KvmSevSnpInit { data: &'a mut KvmSnpInit } = 22,
    KvmSevSnpLaunchStart { data: &'a mut KvmSevSnpLaunchStart } = 23,
    KvmSevSnpLaunchUpdate { data: &'a mut KvmSevSnpLaunchUpdate } = 24,
    KvmSevSnpLaunchFinish { data: &'a mut KvmSevSnpLaunchFinish } = 25,
    KvmSevSnpGuestStatus { data: &'a mut SnpGuestStatusBuffer } = 28,
    KvmSevSnpDbgDecryptPfn { data: &'a mut KvmSevSnpDbg } = 29,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct SnpGuestStatusBuffer {
    pub policy: u64,
    pub asid: u32,
    state: u8,
    reserved: u8,
    reserved2: [u8; 2],
    vcek_dis: u32,
    reserved3: u32,
    reserved4: u64,
}

#[repr(C)]
struct KvmSnpInit {
    flags: KvmSnpInitFlags,
}

bitflags! {
    #[repr(transparent)]
    struct KvmSnpInitFlags: u64 {}
}

#[repr(C)]
struct KvmSevSnpLaunchStart {
    /// Guest policy to use.
    policy: GuestPolicy,
    /// userspace address of migration agent
    ma_uaddr: u64,
    /// 1 if the migtation agent is enabled
    ma_en: u8,
    /// set IMI to 1.
    imi_en: u8,
    /// guest OS visible workarounds
    gosvw: [u8; 16],
    _pad: [u8; 6],
}

#[repr(C)]
struct KvmSevSnpLaunchUpdate {
    /// Guest page number to start from.
    start_gfn: u64,
    /// userspace address need to be encrypted
    uaddr: u64,
    /// length of memory region
    len: u32,
    /// 1 if memory is part of the IMI
    imi_page: u8,
    /// page type
    page_type: u8,
    /// VMPL3 permission mask
    vmpl3_perms: VmplPermissions,
    /// VMPL2 permission mask
    vmpl2_perms: VmplPermissions,
    /// VMPL1 permission mask
    vmpl1_perms: VmplPermissions,
}

#[repr(C)]
struct KvmSevSnpLaunchFinish {
    id_block_uaddr: u64,
    id_auth_uaddr: u64,
    id_block_en: u8,
    auth_key_en: u8,
    host_data: [u8; 32],
    _pad: [u8; 6],
}

#[repr(C)]
struct KvmSevSnpDbg {
    src_gfn: u64,
    dst_uaddr: u64,
}

bitflags! {
    #[repr(transparent)]
    pub struct KvmGuestMemFdFlags: u64 {
        const HUGE_PMD = 1 << 0;
    }
}
