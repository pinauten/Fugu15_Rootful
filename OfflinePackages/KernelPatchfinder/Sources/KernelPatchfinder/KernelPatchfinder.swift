//
//  KernelPatchfinder.swift
//  KernelPatchfinder
//
//  Created by Linus Henze.
//  Copyright © 2022 Pinauten GmbH. All rights reserved.
//

import Foundation
import SwiftMachO
import PatchfinderUtils
import Darwin

open class KernelPatchfinder {
    public let kernel: MachO!
    
    public let cachedResults: [String: UInt64]?
    
    /// Virtual base address of the kernel image
    public let baseAddress: UInt64
    
    /// Kernel entry point
    public let entryPoint: UInt64
    
    /**
     * Whether or not the kernel is running under Piranha
     *
     * - Warning: Patchfinder results might be wrong when running under Piranha - You should dump the kernel from RAM in this case
     */
    public let runningUnderPiranha: Bool
    
    /// `__TEXT_EXEC,__text` section
    public let textExec: PatchfinderSegment!
    
    /// `__TEXT,__cstring` section
    public let cStrSect: PatchfinderSegment!
    
    /// `__DATA,__data` section
    public let dataSect: PatchfinderSegment!
    
    /// `__DATA_CONST,__const` section
    public let constSect: PatchfinderSegment!
    
    /// `__PPLTEXT,__text` section
    public let pplText: PatchfinderSegment!
    
    /// Address of allproc
    public lazy var allproc: UInt64? = {
        if cachedResults != nil {
            return cachedResults.unsafelyUnwrapped["allproc"]
        }
        
        // First find ref to string "shutdownwait"
        guard let shutdownwait = cStrSect.addrOf("shutdownwait") else {
            return nil
        }
        
        // Get an xref to shutdownwait
        guard let reboot_kernel = textExec.findNextXref(to: shutdownwait, optimization: .noBranches) else {
            return nil
        }
        
        // allproc should be first adrp ldr
        for i in 1..<20 {
            let pc = reboot_kernel + UInt64(i * 4)
            let adrp = textExec.instruction(at: pc) ?? 0
            let ldr  = textExec.instruction(at: pc + 4) ?? 0
            if let target = AArch64Instr.Emulate.adrpLdr(adrp: adrp, ldr: ldr, pc: pc) {
                return target
            }
        }
        
        return nil
    }()
    
    /// Address of the kernel's root translation table
    public lazy var cpu_ttep: UInt64? = {
        if cachedResults != nil {
            return cachedResults.unsafelyUnwrapped["cpu_ttep"]
        }
        
        // First follow the jump in start
        guard let start_first_cpu = AArch64Instr.Emulate.b(textExec.instruction(at: entryPoint) ?? 0, pc: entryPoint) else {
            return nil
        }
        
        // Find cbz x21, something
        guard let cpu_ttep_pre = textExec.addrOf([0xB40000B5], startAt: start_first_cpu) else {
            return nil
        }
        
        let adrp = textExec.instruction(at: cpu_ttep_pre + 4)
        let add  = textExec.instruction(at: cpu_ttep_pre + 8)
        
        return AArch64Instr.Emulate.adrpAdd(adrp: adrp ?? 0, add: add ?? 0, pc: cpu_ttep_pre + 4)
    }()
    
    /// Address of the `ppl_bootstrap_dispatch` function
    public lazy var ppl_bootstrap_dispatch: UInt64? = {
        if cachedResults != nil {
            return cachedResults.unsafelyUnwrapped["ppl_bootstrap_dispatch"]
        }
        
        guard let ppl_dispatch_failed = dataSect.addrOf("ppl_dispatch: failed") else {
            return nil
        }
        
        var ppl_bootstrap_dispatch: UInt64!
        var pc: UInt64! = nil
        while true {
            guard let found = textExec.findNextXref(to: ppl_dispatch_failed, startAt: pc, optimization: .noBranches) else {
                return nil
            }
            
            if AArch64Instr.isAutibsp(textExec.instruction(at: found - 4) ?? 0) {
                ppl_bootstrap_dispatch = found
                break
            }
            
            pc = found + 4
        }
        
        // Find the start of ppl_bootstrap_dispatch
        // Search up to 20 instructions
        var ppl_bootstrap_dispatch_start: UInt64?
        for i in 1..<50 {
            let pc = ppl_bootstrap_dispatch - UInt64(i * 4)
            let instr = textExec.instruction(at: pc) ?? 0
            if let args = AArch64Instr.Args.cmp(instr) {
                if args.regA == 15 {
                    ppl_bootstrap_dispatch_start = pc
                    break
                }
            }
        }
        
        return ppl_bootstrap_dispatch_start
    }()
    
    /// Address of the `gxf_ppl_enter` function
    public lazy var gxf_ppl_enter: UInt64? = {
        if cachedResults != nil {
            return cachedResults.unsafelyUnwrapped["gxf_ppl_enter"]
        }
        
        guard let ppl_bootstrap_dispatch = ppl_bootstrap_dispatch else {
            return nil
        }
        
        // Find gxf_ppl_enter
        guard let gxf_ppl_enter = textExec.findNextXref(to: ppl_bootstrap_dispatch, optimization: .onlyBranches) else {
            return nil
        }
        
        // Find start of gxf_ppl_enter
        // Search up to 20 instructions
        var gxf_ppl_enter_start: UInt64?
        for i in 1..<20 {
            let pc = gxf_ppl_enter - UInt64(i * 4)
            if AArch64Instr.isPacibsp(textExec.instruction(at: pc) ?? 0) {
                gxf_ppl_enter_start = pc
                break
            }
        }
        
        return gxf_ppl_enter_start
    }()
    
    /// Address of the `pmap_enter_options_addr` function
    public lazy var pmap_enter_options_addr: UInt64? = {
        if cachedResults != nil {
            return cachedResults.unsafelyUnwrapped["pmap_enter_options_addr"]
        }
        
        guard let pmap_enter_options_ppl = pplDispatchFunc(forOperation: 0xA) else {
            return nil
        }
        
        // Now the hard part: xref pmap_enter_options_ppl and find out which one is pmap_enter_options_addr
        // pmap_enter_options does an 'or' and an 'and' before the call, but no left shift
        var candidate = textExec.findNextXref(to: pmap_enter_options_ppl, optimization: .onlyBranches)
        var pmap_enter_options_addr: UInt64!
        while candidate != nil {
            // Check 20 instructions before
            var foundOr  = false
            var foundAnd = false
            for i in 1..<20 {
                let inst = textExec.instruction(at: candidate! - UInt64(i * 4)) ?? 0
                if inst & 0x7F800000 == 0x12000000 {
                    foundAnd = true
                } else if inst & 0x7F800000 == 0x32000000 {
                    foundOr  = true
                } else if inst & 0x7F800000 == 0x53000000 {
                    // Nope, that's a lsl
                    foundAnd = false
                    foundOr  = false
                    break
                }
            }
            
            if foundOr && foundAnd {
                // Should be it
                pmap_enter_options_addr = candidate
                break
            }
            
            candidate = textExec.findNextXref(to: pmap_enter_options_ppl, startAt: candidate! + 4, optimization: .onlyBranches)
        }
        
        guard pmap_enter_options_addr != nil else {
            return nil
        }
        
        // Find the start of pmap_enter_options_addr
        while !AArch64Instr.isPacibsp(textExec.instruction(at: pmap_enter_options_addr.unsafelyUnwrapped) ?? 0) {
            pmap_enter_options_addr -= 4
        }
        
        return pmap_enter_options_addr
    }()
    
    /// Address of the signed part of the `hw_lck_ticket_reserve_orig_allow_invalid` function
    public lazy var hw_lck_ticket_reserve_orig_allow_invalid_signed: UInt64? = {
        if cachedResults != nil {
            return cachedResults.unsafelyUnwrapped["hw_lck_ticket_reserve_orig_allow_invalid_signed"]
        }
        
        var pc: UInt64?
        while true {
            guard let candidate = textExec.addrOf([0x52800000, 0xD65F03C0], startAt: pc) else {
                return nil
            }
            
            if let args = AArch64Instr.Args.str(textExec.instruction(at: candidate - 4) ?? 0) {
                if args.regSrc == 10 && args.regDst == 16 {
                    if textExec.instruction(at: candidate - 8) != 0xD503205F {
                        return candidate - 4
                    }
                }
            }
            
            pc = candidate + 4
        }
    }()
    
    /// Address of the `hw_lck_ticket_reserve_orig_allow_invalid` function
    public lazy var hw_lck_ticket_reserve_orig_allow_invalid: UInt64? = {
        if cachedResults != nil {
            return cachedResults.unsafelyUnwrapped["hw_lck_ticket_reserve_orig_allow_invalid"]
        }
        
        guard let signed = hw_lck_ticket_reserve_orig_allow_invalid_signed else {
            return nil
        }
        
        for i in 0..<50 {
            let pc = signed - UInt64(i * 4)
            if AArch64Instr.Emulate.adr(textExec.instruction(at: pc) ?? 0, pc: pc) != nil {
                return pc
            }
        }
        
        return nil
    }()
    
    /// Address of a `br x22` gadget (first signs, then branches)
    public lazy var br_x22_gadget: UInt64? = {
        if cachedResults != nil {
            return cachedResults.unsafelyUnwrapped["br_x22_gadget"]
        }
        
        var pc: UInt64?
        while true {
            guard let candidate = textExec.addrOf([0xD71F0ADF], startAt: pc) else {
                return nil
            }
            
            for i in 0..<50 {
                let pc = candidate - UInt64(i * 4)
                if textExec.instruction(at: pc) == 0xDAC103F6 {
                    return pc
                }
            }
            
            pc = candidate + 4
        }
    }()
    
    /// Address of `thread_exception_return`
    public lazy var exception_return: UInt64? = {
        if cachedResults != nil {
            return cachedResults.unsafelyUnwrapped["exception_return"]
        }
        
        return textExec.addrOf([0xD5034FDF, 0xD538D083, 0x910002BF])
    }()
    
    /// Address of `thread_exception_return` after checking the signed state
    public lazy var exception_return_after_check: UInt64? = {
        if cachedResults != nil {
            return cachedResults.unsafelyUnwrapped["exception_return_after_check"]
        }
        
        guard let exception_return = exception_return else {
            return nil
        }
        
        return textExec.addrOf([0xAA0303FE, 0xAA1603E3, 0xAA1703E4, 0xAA1803E5], startAt: exception_return)
    }()
    
    /// Address of `thread_exception_return` after checking the signed state, without restoring lr and others
    public lazy var exception_return_after_check_no_restore: UInt64? = {
        if cachedResults != nil {
            return cachedResults.unsafelyUnwrapped["exception_return_after_check_no_restore"]
        }
        
        guard let exception_return_after_check = exception_return_after_check else {
            return nil
        }
        
        return textExec.addrOf([0xD5184021], startAt: exception_return_after_check)
    }()
    
    /// Address of a `ldp x0, x1, [x8]` gadget
    public lazy var ldp_x0_x1_x8_gadget: UInt64? = {
        if cachedResults != nil {
            return cachedResults.unsafelyUnwrapped["ldp_x0_x1_x8_gadget"]
        }
        
        return textExec.addrOf([0xA9400500, 0xD65F03C0])
    }()
    
    /// Address of a `str x8, [x9]` gadget
    public lazy var str_x8_x9_gadget: UInt64? = {
        if cachedResults != nil {
            return cachedResults.unsafelyUnwrapped["str_x8_x9_gadget"]
        }
        
        return textExec.addrOf([0xF9000128, 0xD65F03C0])
    }()
    
    /// Address of a `str x0, [x19]; ldr x?, [x20, #?]` gadget
    public lazy var str_x0_x19_ldr_x20: UInt64? = {
        if cachedResults != nil {
            return cachedResults.unsafelyUnwrapped["str_x0_x19_ldr_x20"]
        }
        
        var pc: UInt64?
        while true {
            guard let candidate = textExec.addrOf([0xF9000260], startAt: pc) else {
                return nil
            }
            
            if let vals = AArch64Instr.Args.ldr(textExec.instruction(at: candidate + 4) ?? 0) {
                if vals.regSrc == 20 {
                    return candidate
                }
            }
            
            pc = candidate + 4
        }
    }()
    
    /// Address of the `pmap_set_nested` function
    public lazy var pmap_set_nested: UInt64? = {
        if cachedResults != nil {
            return cachedResults.unsafelyUnwrapped["pmap_set_nested"]
        }
        
        return pplDispatchFunc(forOperation: 0x1A)
    }()
    
    /// Address of the `pmap_nest` function
    public lazy var pmap_nest: UInt64? = {
        if cachedResults != nil {
            return cachedResults.unsafelyUnwrapped["pmap_nest"]
        }
        
        guard let pmap_nest_ppl = pplDispatchFunc(forOperation: 0x11) else {
            return nil
        }
        
        guard var pmap_nest = textExec.findNextXref(to: pmap_nest_ppl, optimization: .onlyBranches) else {
            return nil
        }
        
        while !AArch64Instr.isPacibsp(textExec.instruction(at: pmap_nest) ?? 0) {
            pmap_nest -= 4
        }
        
        return pmap_nest
    }()
    
    /// Address of the `pmap_remove_options` function
    public lazy var pmap_remove_options: UInt64? = {
        if cachedResults != nil {
            return cachedResults.unsafelyUnwrapped["pmap_remove_options"]
        }
        
        guard let pmap_remove_ppl = pplDispatchFunc(forOperation: 0x17) else {
            return nil
        }
        
        var pc: UInt64?
        while true {
            guard var candidate = textExec.findNextXref(to: pmap_remove_ppl, startAt: pc, optimization: .onlyBranches) else {
                return nil
            }
            
            if textExec.instruction(at: candidate - 4) != 0x52802003 {
                while !AArch64Instr.isPacibsp(textExec.instruction(at: candidate) ?? 0) {
                    candidate -= 4
                }
                
                return candidate
            }
            
            pc = candidate + 4
        }
    }()
    
    /// Address of the `pmap_mark_page_as_ppl_page` function
    public lazy var pmap_mark_page_as_ppl_page: UInt64? = {
        if cachedResults != nil {
            return cachedResults.unsafelyUnwrapped["pmap_mark_page_as_ppl_page"]
        }
        
        return pplDispatchFunc(forOperation: 0x10)
    }()
    
    /// Address of the `pmap_create_options` function
    public lazy var pmap_create_options: UInt64? = {
        if cachedResults != nil {
            return cachedResults.unsafelyUnwrapped["pmap_create_options"]
        }
        
        guard let pmap_create_options_ppl = pplDispatchFunc(forOperation: 0x8) else {
            return nil
        }
        
        var pc: UInt64?
        while true {
            guard var candidate = textExec.findNextXref(to: pmap_create_options_ppl, startAt: pc, optimization: .onlyBranches) else {
                return nil
            }
            
            if textExec.instruction(at: candidate - 4) != 0x52800002 {
                if textExec.instruction(at: candidate - 4) != 0x52800102 {
                    while !AArch64Instr.isPacibsp(textExec.instruction(at: candidate) ?? 0) {
                        candidate -= 4
                    }
                    
                    return candidate
                }
            }
            
            pc = candidate + 4
        }
    }()
    
    /// Address of the `gIOCatalogue` object
    public lazy var gIOCatalogue: UInt64? = {
        if cachedResults != nil {
            return cachedResults.unsafelyUnwrapped["gIOCatalogue"]
        }
        
        guard let kConfigTablesStr = cStrSect.addrOf("KernelConfigTables syntax error: %s") else {
            return nil
        }
        
        // Xref that to find IOCatalogue::initialize
        guard let ioCatalogueInitialize = textExec.findNextXref(to: kConfigTablesStr, optimization: .noBranches) else {
            return nil
        }
        
        // Find the end of that function
        guard let ioCatalogueInitializeEnd = textExec.addrOf([0xD65F0FFF], startAt: ioCatalogueInitialize) else {
            return nil
        }
        
        // Go back to the first adrp ldr
        var gIOCatalogue: UInt64!
        for i in 1..<100 {
            let pos = ioCatalogueInitializeEnd - UInt64(i * 4)
            let instr1 = textExec.instruction(at: pos) ?? 0
            let instr2 = textExec.instruction(at: pos + 4) ?? 0
            let val = AArch64Instr.Emulate.adrpLdr(adrp: instr1, ldr: instr2, pc: pos)
            if val != nil {
                gIOCatalogue = val
                break
            }
        }
        
        return gIOCatalogue
    }()
    
    /// Address of the `IOCatalogue::terminateDriversForModule(const char * moduleName, bool unload)` function
    public lazy var terminateDriversForModule: UInt64? = {
        if cachedResults != nil {
            return cachedResults.unsafelyUnwrapped["terminateDriversForModule"]
        }
        
        guard let cantRemoveKextStr = cStrSect.addrOf("Can't remove kext %s - not found.") else {
            return nil
        }
        
        // Xref str to find OSKext::removeKextWithIdentifier
        guard let removeKextWithIdentifier = textExec.findNextXref(to: cantRemoveKextStr, optimization: .noBranches) else {
            return nil
        }
        
        // Find the start of removeKextWithIdentifier
        var removeKextWithIdentifierStart: UInt64!
        for i in 1..<100 {
            let pos = removeKextWithIdentifier - UInt64(i * 4)
            if AArch64Instr.isPacibsp(textExec.instruction(at: pos) ?? 0) {
                removeKextWithIdentifierStart = pos
                break
            }
        }
        
        guard removeKextWithIdentifierStart != nil else {
            return nil
        }
        
        // Xref to find the function that does a bl
        var terminateOSString: UInt64! = textExec.findNextXref(to: removeKextWithIdentifierStart, optimization: .onlyBranches)
        while let pc = terminateOSString,
              AArch64Instr.Emulate.bl(textExec.instruction(at: pc) ?? 0, pc: pc) == nil {
            terminateOSString = textExec.findNextXref(to: removeKextWithIdentifierStart, startAt: pc + 4, optimization: .onlyBranches)
        }
        
        guard terminateOSString != nil else {
            return nil
        }
        
        // Now we just find the start of this...
        var terminateOSStringStart: UInt64!
        for i in 1..<300 {
            let pos = terminateOSString - UInt64(i * 4)
            if AArch64Instr.isPacibsp(textExec.instruction(at: pos) ?? 0, alsoAllowNop: false) {
                terminateOSStringStart = pos
                break
            }
        }
        
        guard terminateOSStringStart != nil else {
            return nil
        }
        
        // ...xref it...
        guard let terminateDriversForModuleBL = textExec.findNextXref(to: terminateOSStringStart, optimization: .onlyBranches) else {
            return nil
        }
        
        // ...and find start
        var terminateDriversForModule: UInt64!
        for i in 1..<300 {
            let pos = terminateDriversForModuleBL - UInt64(i * 4)
            if AArch64Instr.isPacibsp(textExec.instruction(at: pos) ?? 0) {
                terminateDriversForModule = pos
                break
            }
        }
        
        return terminateDriversForModule
    }()
    
    /// Address of the `kalloc_data_external` function
    public lazy var kalloc_data_external: UInt64? = {
        if cachedResults != nil {
            return cachedResults.unsafelyUnwrapped["kalloc_data_external"]
        }
        
        // For kalloc, find "AMFI: %s: Failed to allocate memory for fatal error message, cannot produce a crash reason."
        // The first bl in the function will be to kalloc_data_external
        guard let amfi_fatal_err_str = cStrSect.addrOf("AMFI: %s: Failed to allocate memory for fatal error message, cannot produce a crash reason.") else {
            return nil
        }
        
        guard var amfi_fatal_err_func = textExec.findNextXref(to: amfi_fatal_err_str, optimization: .noBranches) else {
            return nil
        }
        
        var amfi_fatal_err_func_start: UInt64!
        for i in 1..<300 {
            let pos = amfi_fatal_err_func - UInt64(i * 4)
            if AArch64Instr.isPacibsp(textExec.instruction(at: pos) ?? 0) {
                amfi_fatal_err_func_start = pos
                break
            }
        }
        
        guard amfi_fatal_err_func_start != nil else {
            return nil
        }
        
        var kalloc_external: UInt64!
        for i in 1..<20 {
            let pc = amfi_fatal_err_func_start + UInt64(i * 4)
            let target = AArch64Instr.Emulate.bl(textExec.instruction(at: pc) ?? 0, pc: pc)
            if target != nil {
                kalloc_external = target
                break
            }
        }
        
        return kalloc_external
    }()
    
    /// Address of the `ml_sign_thread_state` function
    public lazy var ml_sign_thread_state: UInt64? = {
        if cachedResults != nil {
            return cachedResults.unsafelyUnwrapped["ml_sign_thread_state"]
        }
        
        return textExec.addrOf([0x9AC03021, 0x9262F842, 0x9AC13041, 0x9AC13061, 0x9AC13081, 0x9AC130A1, 0xF9009401, 0xD65F03C0])
    }()
    
    /// Address of the ppl handler table
    public lazy var ppl_handler_table: UInt64? = {
        if cachedResults != nil {
            return cachedResults.unsafelyUnwrapped["ppl_handler_table"]
        }
        
        guard let ppl_bootstrap_dispatch = ppl_bootstrap_dispatch else {
            return nil
        }
        
        var ppl_handler_table: UInt64?
        for i in 1..<20 {
            let pc = ppl_bootstrap_dispatch + UInt64(i * 4)
            let adrp = textExec.instruction(at: pc) ?? 0
            let ldr  = textExec.instruction(at: pc + 4) ?? 0
            let tbl = AArch64Instr.Emulate.adrpAdd(adrp: adrp, add: ldr, pc: pc)
            if tbl != nil {
                ppl_handler_table = tbl
                break
            }
        }
        
        return ppl_handler_table
    }()
    
    /// Address of `pmap_image4_trust_caches`
    public lazy var pmap_image4_trust_caches: UInt64? = {
        if cachedResults != nil {
            return cachedResults.unsafelyUnwrapped["pmap_image4_trust_caches"]
        }
        
        guard let ppl_handler_table = ppl_handler_table else {
            return nil
        }
        
        guard var pmap_lookup_in_loaded_trust_caches_internal = constSect.r64(at: ppl_handler_table + 0x148) else {
            return nil
        }
        
        if (pmap_lookup_in_loaded_trust_caches_internal >> 48) == 0x8011 {
            // Relocation, on-disk kernel
            pmap_lookup_in_loaded_trust_caches_internal &= 0xFFFFFFFFFFFF
            pmap_lookup_in_loaded_trust_caches_internal += 0xFFFFFFF007004000
        } else {
            // Probably live kernel
            // Strip pointer authentication code
            pmap_lookup_in_loaded_trust_caches_internal |= 0xFFFFFF8000000000
        }
        
        var pmap_image4_trust_caches: UInt64?
        for i in 1..<20 {
            let pc = pmap_lookup_in_loaded_trust_caches_internal + UInt64(i * 4)
            let emu = AArch64Instr.Emulate.ldr(pplText.instruction(at: pc) ?? 0, pc: pc)
            if emu != nil {
                pmap_image4_trust_caches = emu
                break
            }
        }
        
        return pmap_image4_trust_caches
    }()
    
    /// Get the EL level the kernel runs at
    public lazy var kernel_el: UInt64? = {
        if cachedResults != nil {
            return cachedResults.unsafelyUnwrapped["kernel_el"]
        }
        
        // Get start
        guard let realStart = AArch64Instr.Emulate.b(textExec.instruction(at: entryPoint) ?? 0, pc: entryPoint) else {
            return nil
        }
        
        let targetInstructionAddr = realStart + 0x10
        let instr = textExec.instruction(at: targetInstructionAddr) ?? 0
        if instr == 0xD5384240 {
            return 2
        } else if AArch64Instr.Emulate.adrp(instr, pc: targetInstructionAddr) != nil {
            return 1
        } else {
            return nil
        }
    }()
    
    /// Offset of `TH_RECOVER` in thread struct
    public lazy var TH_RECOVER: UInt64? = {
        if cachedResults != nil {
            return cachedResults.unsafelyUnwrapped["TH_RECOVER"]
        }
        
        guard let lckFunc = hw_lck_ticket_reserve_orig_allow_invalid_signed else {
            return nil
        }
        
        guard let args = AArch64Instr.Args.str(textExec.instruction(at: lckFunc) ?? 0) else {
            return nil
        }
        
        return UInt64(args.imm)
    }()
    
    /// Offset of `TH_KSTACKPTR` in thread struct
    public lazy var TH_KSTACKPTR: UInt64? = {
        if cachedResults != nil {
            return cachedResults.unsafelyUnwrapped["TH_KSTACKPTR"]
        }
        
        var pc: UInt64?
        while true {
            guard let candidate = textExec.addrOf([0xD538D08A], startAt: pc) else {
                return nil
            }
            
            if let args = AArch64Instr.Args.ldr(textExec.instruction(at: candidate + 4) ?? 0) {
                if (textExec.instruction(at: candidate + 8) ?? 0) == 0xD503233F {
                    return UInt64(args.imm)
                }
            }
            
            pc = candidate + 4
        }
    }()
    
    /// Offset of `ACT_CONTEXT` in thread struct
    public lazy var ACT_CONTEXT: UInt64? = {
        if cachedResults != nil {
            return cachedResults.unsafelyUnwrapped["ACT_CONTEXT"]
        }
        
        var pc: UInt64?
        while true {
            guard let candidate = textExec.addrOf([0xD5184100, 0xA8C107E0, 0xD50040BF], startAt: pc) else {
                return nil
            }
            
            if let args = AArch64Instr.Args.addImm(textExec.instruction(at: candidate - 12) ?? 0) {
                return UInt64(args.imm)
            }
            
            pc = candidate + 4
        }
    }()
    
    /// Offset of `ACT_CPUDATAP` in thread struct
    public lazy var ACT_CPUDATAP: UInt64? = {
        if cachedResults != nil {
            return cachedResults.unsafelyUnwrapped["ACT_CPUDATAP"]
        }
        
        var pc: UInt64?
        while true {
            guard let candidate = textExec.addrOf([0xD50343DF], startAt: pc) else {
                return nil
            }
            
            if let args = AArch64Instr.Args.ldr(textExec.instruction(at: candidate + 4) ?? 0) {
                if args.regDst == 11 && args.regSrc == 10 {
                    return UInt64(args.imm)
                }
            }
            
            pc = candidate + 4
        }
    }()
    
    /// Offset of `ITK_SPACE` in task struct
    public lazy var ITK_SPACE: UInt64? = {
        if cachedResults != nil {
            return cachedResults.unsafelyUnwrapped["ITK_SPACE"]
        }
        
        guard let task_dealloc_str = cStrSect.addrOf("task_deallocate(%p): volatile_objects=%d nonvolatile_objects=%d") else {
            return nil
        }
        
        guard var task_deallocate_internal = textExec.findNextXref(to: task_dealloc_str, optimization: .noBranches) else {
            return nil
        }
        
        var pc = task_deallocate_internal
        while true {
            guard let candidate = textExec.findNextXref(to: pc, optimization: .onlyBranches) else {
                pc = pc - 4
                continue
            }
            
            // Scan downward for a bl
            pc = candidate
            while true {
                pc += 4
                if let args = AArch64Instr.Emulate.bl(textExec.instruction(at: pc) ?? 0, pc: pc) {
                    break
                }
            }
            
            // Scan for our ldr
            while true {
                pc += 4
                if let args = AArch64Instr.Args.ldr(textExec.instruction(at: pc) ?? 0) {
                    return UInt64(args.imm)
                }
            }
        }
    }()
    
    /// Offset of `PMAP` in vm\_map struct
    public lazy var VM_MAP_PMAP: UInt64? = {
        if cachedResults != nil {
            return cachedResults.unsafelyUnwrapped["VM_MAP_PMAP"]
        }
        
        guard let control_access_str = cStrSect.addrOf("userspace has control access to a kernel") else {
            return nil
        }
        
        guard var task_check_func = textExec.findNextXref(to: control_access_str, optimization: .noBranches) else {
            return nil
        }
        
        var pc = task_check_func
        while true {
            pc = pc - 4
            
            if let args = AArch64Instr.Args.ldr(textExec.instruction(at: pc) ?? 0) {
                if AArch64Instr.Emulate.compareBranch(textExec.instruction(at: pc + 4) ?? 0, pc: pc + 4) != nil {
                    if AArch64Instr.Emulate.adrp(textExec.instruction(at: pc - 4) ?? 0, pc: pc - 4) == nil {
                        return UInt64(args.imm)
                    }
                }
            }
        }
    }()
    
    /// Offset of `LABEL` in mach\_port struct
    public lazy var PORT_LABEL: UInt64? = {
        if cachedResults != nil {
            return cachedResults.unsafelyUnwrapped["PORT_LABEL"]
        }
        
        guard let label_check_str = cStrSect.addrOf("ipc_kobject_label_check: attempted receive right copyout for labeled kobject") else {
            return nil
        }
        
        guard var label_check_func = textExec.findNextXref(to: label_check_str, optimization: .noBranches) else {
            return nil
        }
        
        var pc = label_check_func
        while true {
            pc = pc - 4
            
            guard let br = textExec.findNextXref(to: pc, optimization: .onlyBranches) else {
                continue
            }
            
            pc = br
            
            while true {
                pc += 4
                if let args = AArch64Instr.Args.ldr(textExec.instruction(at: pc) ?? 0) {
                    return UInt64(args.imm)
                }
            }
        }
    }()
    
    /// Find `ptov_table`, `gPhysBase` and `gVirtBase` for phys-to-virt translation
    public lazy var ptov_data: (table: UInt64, physBase: UInt64?, virtBase: UInt64?)? = {
        if cachedResults != nil {
            guard let table = cachedResults.unsafelyUnwrapped["ptov_data_table"] else {
                return nil
            }
            
            return (table: table, physBase: cachedResults.unsafelyUnwrapped["ptov_data_physBase"], virtBase: cachedResults.unsafelyUnwrapped["ptov_data_virtBase"])
        }
        
        guard let panic_str = cStrSect.addrOf("%s: illegal PA: 0x%llx; phys base 0x%llx, size 0x%llx @%s:%d") else {
            return nil
        }
        
        guard var pc = textExec.findNextXref(to: panic_str, optimization: .noBranches) else {
            return nil
        }
        
        var virtBase: UInt64?
        var physBase: UInt64?
        
        while true {
            if AArch64Instr.isPacibsp(textExec.instruction(at: pc) ?? 0) {
                // Found start!
                var firstLoadLoc: UInt64?
                while true {
                    if let dst = AArch64Instr.Emulate.adrpLdr(adrp: textExec.instruction(at: pc) ?? 0, ldr: textExec.instruction(at: pc + 4) ?? 0, pc: pc) {
                        if let firstLoadLoc = firstLoadLoc {
                            return (table: min(firstLoadLoc, dst), physBase: physBase, virtBase: virtBase)
                        }
                        
                        firstLoadLoc = dst
                        pc += 4
                    }
                    
                    pc += 4
                }
            } else if physBase == nil && AArch64Instr.Args.subs(textExec.instruction(at: pc) ?? 0) != nil {
                if let pb = AArch64Instr.Emulate.adrpLdr(adrp: textExec.instruction(at: pc - 8) ?? 0, ldr: textExec.instruction(at: pc - 4) ?? 0, pc: pc - 8) {
                    physBase = pb
                    var foundFirst = false
                    var tpc = pc
                    while true {
                        if let dst = AArch64Instr.Emulate.adrpLdr(adrp: textExec.instruction(at: tpc) ?? 0, ldr: textExec.instruction(at: tpc + 4) ?? 0, pc: tpc) {
                            if !foundFirst {
                                foundFirst = true
                            } else {
                                virtBase = dst
                                break
                            }
                        }
                        
                        tpc += 4
                    }
                }
            }
            
            pc -= 4
        }
    }()
    
    /// `pmap_alloc_page_for_kern` function
    public lazy var pmap_alloc_page_for_kern: UInt64? = {
        if cachedResults != nil {
            return cachedResults.unsafelyUnwrapped["pmap_alloc_page_for_kern"]
        }
        
        guard let func_str = cStrSect.addrOf("pmap_alloc_page_for_kern") else {
            return nil
        }
        
        guard var pc = textExec.findNextXref(to: func_str, optimization: .noBranches) else {
            return nil
        }
        
        while true {
            if AArch64Instr.isPacibsp(textExec.instruction(at: pc) ?? 0) {
                return pc
            }
            
            pc -= 4
        }
    }()
    
    public lazy var pivot_root: UInt64? = {
        if cachedResults != nil {
            return cachedResults.unsafelyUnwrapped["pivot_root"]
        }
        
        guard let preboot_str = cStrSect.addrOf("System/Volumes/iSCPreboot") else {
            return nil
        }
        
        guard var pc = textExec.findNextXref(to: preboot_str, optimization: .noBranches) else {
            return nil
        }
        
        while true {
            if AArch64Instr.isPacibsp(textExec.instruction(at: pc) ?? 0, alsoAllowNop: false) {
                return pc
            }
            
            pc -= 4
        }
    }()
    
    public lazy var pacda_gadget: UInt64? = {
        if cachedResults != nil {
            return cachedResults.unsafelyUnwrapped["pacda_gadget"]
        }
        
        return textExec.addrOf([0xF100003F, 0xDAC10921, 0x9A8103E9, 0xF9000109, 0xD65F03C0])
    }()
    
    public func exportResults() -> Data? {
        let results_opt = [
            "baseAddress": baseAddress,
            "entryPoint": entryPoint,
            "allproc": allproc,
            "cpu_ttep": cpu_ttep,
            "ppl_bootstrap_dispatch": ppl_bootstrap_dispatch,
            "gxf_ppl_enter": gxf_ppl_enter,
            "pmap_enter_options_addr": pmap_enter_options_addr,
            "hw_lck_ticket_reserve_orig_allow_invalid_signed": hw_lck_ticket_reserve_orig_allow_invalid_signed,
            "hw_lck_ticket_reserve_orig_allow_invalid": hw_lck_ticket_reserve_orig_allow_invalid,
            "br_x22_gadget": br_x22_gadget,
            "exception_return": exception_return,
            "exception_return_after_check": exception_return_after_check,
            "exception_return_after_check_no_restore": exception_return_after_check_no_restore,
            "ldp_x0_x1_x8_gadget": ldp_x0_x1_x8_gadget,
            "str_x8_x9_gadget": str_x8_x9_gadget,
            "str_x0_x19_ldr_x20": str_x0_x19_ldr_x20,
            "pmap_set_nested": pmap_set_nested,
            "pmap_nest": pmap_nest,
            "pmap_remove_options": pmap_remove_options,
            "pmap_mark_page_as_ppl_page": pmap_mark_page_as_ppl_page,
            "pmap_create_options": pmap_create_options,
            "gIOCatalogue": gIOCatalogue,
            "terminateDriversForModule": terminateDriversForModule,
            "kalloc_data_external": kalloc_data_external,
            "ml_sign_thread_state": ml_sign_thread_state,
            "ppl_handler_table": ppl_handler_table,
            "pmap_image4_trust_caches": pmap_image4_trust_caches,
            "kernel_el": kernel_el,
            "TH_RECOVER": TH_RECOVER,
            "TH_KSTACKPTR": TH_KSTACKPTR,
            "ACT_CONTEXT": ACT_CONTEXT,
            "ACT_CPUDATAP": ACT_CPUDATAP,
            "ITK_SPACE": ITK_SPACE,
            "VM_MAP_PMAP": VM_MAP_PMAP,
            "PORT_LABEL": PORT_LABEL,
            "ptov_data_table": ptov_data?.table,
            "ptov_data_physBase": ptov_data?.physBase,
            "ptov_data_virtBase": ptov_data?.virtBase,
            "pmap_alloc_page_for_kern": pmap_alloc_page_for_kern,
            "pivot_root": pivot_root,
            "pacda_gadget": pacda_gadget
        ]
        
        let results = results_opt.filter { (k, v) in
            v != nil
        }
        
        return try? PropertyListSerialization.data(fromPropertyList: results, format: .xml, options: 0)
    }

    /// Return patchfinder for the currently running kernel.
    public static var running: KernelPatchfinder? = {
        if let krnl = MachO.runningKernel {
            return KernelPatchfinder(kernel: krnl)
        }
        
        // Try libgrabkernel (if available)
        typealias grabKernelType = @convention(c) (_ path: UnsafePointer<CChar>?, _ isResearchDevice: Int32) -> Int32
        guard let grabKernelRaw = dlsym(dlopen(nil, 0), "grabkernel") else {
            return nil
        }
        
        let grabkernel = unsafeBitCast(grabKernelRaw, to: grabKernelType.self)
        
        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0].path
        let kernel = documents + "/kernel.img4"
        if !FileManager.default.fileExists(atPath: kernel) {
            let status = grabkernel(kernel, 0)
            guard status == 0 else {
                return nil
            }
        }
        
        guard let k = loadImg4Kernel(path: kernel) else {
            return nil
        }
        
        guard let machO = try? MachO(fromData: k, okToLoadFAT: false) else {
            return nil
        }
        
        return KernelPatchfinder(kernel: machO)
    }()
    
    /// Initialize patchfinder for the given kernel.
    public required init?(kernel: MachO) {
        self.kernel        = kernel
        self.cachedResults = nil
        
        guard let textExec = kernel.pfSection(segment: "__TEXT_EXEC", section: "__text") else {
            return nil
        }
        
        guard let cStrSect = kernel.pfSection(segment: "__TEXT", section: "__cstring") else {
            return nil
        }
        
        guard let dataSect = kernel.pfSection(segment: "__DATA", section: "__data") else {
            return nil
        }
        
        guard let constSect = kernel.pfSection(segment: "__DATA_CONST", section: "__const") else {
            return nil
        }
        
        guard let pplText = kernel.pfSection(segment: "__PPLTEXT", section: "__text") else {
            return nil
        }
        
        self.textExec  = textExec
        self.cStrSect  = cStrSect
        self.dataSect  = dataSect
        self.constSect = constSect
        self.pplText   = pplText
        
        var baseAddress: UInt64 = UInt64.max
        var entryPoint: UInt64?
        var runningUnderPiranha = false
        for lc in kernel.cmds {
            if let seg = lc as? Segment64LoadCommand {
                if seg.vmAddr < baseAddress && seg.vmAddr > 0 {
                    baseAddress = seg.vmAddr
                }
            } else if let uCmd = lc as? UnixThreadLoadCommand {
                /*guard let state = uCmd.threadStates[0].state.tryGetGeneric(type: arm_thread_state64_t.self) else {
                    return nil
                }
                
                #if arch(arm64) && __DARWIN_OPAQUE_ARM_THREAD_STATE64
                let s = UInt64(UInt(bitPattern: state.__opaque_pc))
                #else
                let s = state.__pc
                #endif*/
                
                let state = uCmd.threadStates[0].state
                guard let s = state.tryGetGeneric(type: UInt64.self, offset: UInt(state.count - 0x10)) else {
                    return nil
                }
                
                entryPoint = s
                
                // Check the start instruction
                if AArch64Instr.Emulate.b(textExec.instruction(at: s) ?? 0, pc: s) == nil {
                    // Not a branch?
                    // Either a bad kernel or we're running under Piranha
                    // Piranha always adds three instructions
                    guard AArch64Instr.Emulate.b(textExec.instruction(at: s + 12) ?? 0, pc: s + 12) != nil else {
                        // Nope, bad kernel
                        return nil
                    }
                    
                    // Running under Piranha
                    // Kernel is probably patched, patchfinder results might be wrong
                    entryPoint = s + 12
                    runningUnderPiranha = true
                }
            }
        }
        
        guard baseAddress != UInt64.max else {
            return nil
        }
        
        guard let entryPoint = entryPoint else {
            return nil
        }
        
        self.baseAddress = baseAddress
        self.entryPoint = entryPoint
        self.runningUnderPiranha = runningUnderPiranha
    }
    
    public init?(fromCachedResults cr: Data) {
        guard let results = try? PropertyListSerialization.propertyList(from: cr, format: nil) as? [String: UInt64] else {
            return nil
        }
        
        guard let baseAddress = results["baseAddress"] else {
            return nil
        }
        
        guard let entryPoint = results["entryPoint"] else {
            return nil
        }
        
        self.baseAddress         = baseAddress
        self.entryPoint          = entryPoint
        self.cachedResults       = results
        self.kernel              = nil
        self.runningUnderPiranha = false
        self.textExec            = nil
        self.cStrSect            = nil
        self.dataSect            = nil
        self.constSect           = nil
        self.pplText             = nil
    }
    
    public func pplDispatchFunc(forOperation op: UInt16) -> UInt64? {
        guard let gxf_ppl_enter = gxf_ppl_enter else {
            return nil
        }
        
        var pc: UInt64! = nil
        while true {
            guard let ref = textExec.findNextXref(to: gxf_ppl_enter, startAt: pc, optimization: .onlyBranches) else {
                return nil
            }
            
            if let args = AArch64Instr.Args.movz(textExec.instruction(at: ref - 4) ?? 0) {
                if args.regDst == 15 && args.imm == op {
                    return ref - 4
                }
            }
            
            pc = ref + 4
        }
    }
}
