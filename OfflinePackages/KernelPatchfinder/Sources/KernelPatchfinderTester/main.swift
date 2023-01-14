//
//  KernelPatchfinderTests.swift
//  KernelPatchfinder
//
//  Created by Linus Henze.
//  Copyright © 2022 Pinauten GmbH. All rights reserved.
//

import Foundation
@testable import KernelPatchfinder
import SwiftMachO

guard CommandLine.arguments.count == 2 else {
    print("Usage: KernelPatchfinderTester <kernel file>")
    exit(-1)
}

guard let pf = KernelPatchfinder(kernel: try MachO(fromFile: CommandLine.arguments[1], okToLoadFAT: false)) else {
    print("Failed to create KernelPatchfinder instance!")
    exit(-1)
}

if pf.allproc == nil {
    print("Failed: pf.allproc")
}

if pf.cpu_ttep == nil {
    print("Failed: pf.cpu_ttep")
}

if pf.pmap_enter_options_addr == nil {
    print("Failed: pf.pmap_enter_options_addr")
}

if pf.hw_lck_ticket_reserve_orig_allow_invalid_signed == nil {
    print("Failed: pf.hw_lck_ticket_reserve_orig_allow_invalid_signed")
}

if pf.hw_lck_ticket_reserve_orig_allow_invalid == nil {
    print("Failed: pf.hw_lck_ticket_reserve_orig_allow_invalid")
}

if pf.br_x22_gadget == nil {
    print("Failed: pf.br_x22_gadget")
}

if pf.exception_return == nil {
    print("Failed: pf.exception_return")
}

if pf.ldp_x0_x1_x8_gadget == nil {
    print("Failed: pf.ldp_x0_x1_x8_gadget")
}

if pf.exception_return_after_check == nil {
    print("Failed: pf.exception_return_after_check")
}

if pf.exception_return_after_check_no_restore == nil {
    print("Failed: pf.exception_return_after_check_no_restore")
}

if pf.str_x8_x9_gadget == nil {
    print("Failed: pf.str_x8_x9_gadget")
}

if pf.str_x0_x19_ldr_x20 == nil {
    print("Failed: pf.str_x0_x19_ldr_x20")
}

if pf.pmap_set_nested == nil {
    print("Failed: pf.pmap_set_nested")
}

if pf.pmap_nest == nil {
    print("Failed: pf.pmap_nest")
}

if pf.pmap_remove_options == nil {
    print("Failed: pf.pmap_remove_options")
}

if pf.pmap_mark_page_as_ppl_page == nil {
    print("Failed: pf.pmap_mark_page_as_ppl_page")
}

if pf.pmap_create_options == nil {
    print("Failed: pf.pmap_create_options")
}

if pf.ml_sign_thread_state == nil {
    print("Failed: pf.ml_sign_thread_state")
}

if pf.kernel_el == nil {
    print("Failed to find out if kernel runs at EL1 or EL2!")
}

if pf.TH_RECOVER == nil {
    print("Failed: pf.TH_RECOVER")
}

if pf.TH_KSTACKPTR == nil {
    print("Failed: pf.TH_KSTACKPTR")
}

if pf.ACT_CONTEXT == nil {
    print("Failed: pf.ACT_CONTEXT")
}

if pf.ACT_CPUDATAP == nil {
    print("Failed: pf.ACT_CPUDATAP")
}

if pf.ITK_SPACE == nil {
    print("Failed: pf.ITK_SPACE")
}

if pf.VM_MAP_PMAP == nil {
    print("Failed: pf.VM_MAP_PMAP")
}

if pf.PORT_LABEL == nil {
    print("Failed: pf.PORT_LABEL")
}
