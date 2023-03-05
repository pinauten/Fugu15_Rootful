//
//  KernelPatchfinderTests.swift
//  KernelPatchfinder
//
//  Created by Linus Henze.
//  Copyright © 2022 Pinauten GmbH. All rights reserved.
//

import XCTest
@testable import KernelPatchfinder
import SwiftMachO
import PatchfinderUtils

final class KernelPatchfinderTests: XCTestCase {
    func test(pf: KernelPatchfinder) throws {
        XCTAssertNotNil(pf.allproc)
        XCTAssertNotNil(pf.cpu_ttep)
        XCTAssertNotNil(pf.pmap_enter_options_addr)
        XCTAssertNotNil(pf.hw_lck_ticket_reserve_orig_allow_invalid_signed)
        XCTAssertNotNil(pf.hw_lck_ticket_reserve_orig_allow_invalid)
        XCTAssertNotNil(pf.br_x22_gadget)
        XCTAssertNotNil(pf.exception_return)
        XCTAssertNotNil(pf.ldp_x0_x1_x8_gadget)
        XCTAssertNotNil(pf.exception_return_after_check)
        XCTAssertNotNil(pf.exception_return_after_check_no_restore)
        XCTAssertNotNil(pf.str_x8_x9_gadget)
        XCTAssertNotNil(pf.str_x0_x19_ldr_x20)
        XCTAssertNotNil(pf.pmap_set_nested)
        XCTAssertNotNil(pf.pmap_nest)
        XCTAssertNotNil(pf.pmap_remove_options)
        XCTAssertNotNil(pf.pmap_mark_page_as_ppl_page)
        XCTAssertNotNil(pf.pmap_create_options)
        XCTAssertNotNil(pf.gIOCatalogue)
        XCTAssertNotNil(pf.terminateDriversForModule)
        XCTAssertNotNil(pf.kalloc_data_external)
        XCTAssertNotNil(pf.ml_sign_thread_state)
        XCTAssertNotNil(pf.ppl_handler_table)
        XCTAssertNotNil(pf.pmap_image4_trust_caches)
        XCTAssertNotNil(pf.kernel_el)
        XCTAssertNotNil(pf.TH_RECOVER)
        XCTAssertNotNil(pf.TH_KSTACKPTR)
        XCTAssertNotNil(pf.ACT_CONTEXT)
        XCTAssertNotNil(pf.ACT_CPUDATAP)
        XCTAssertNotNil(pf.ITK_SPACE)
        XCTAssertNotNil(pf.VM_MAP_PMAP)
        XCTAssertNotNil(pf.PORT_LABEL)
    }
    
    func testPatchfinder() throws {
        /*guard let pf = KernelPatchfinder.running else {
            XCTFail("KernelPatchfinder.running == nil!")
            return
        }*/
        
        // /Users/linus/kernelcache.release.iphone11.raw
        // /Users/linus/Desktop/Fugu15_OBTS/Server/kernelcache.release.iphone14.raw
        guard let pf = KernelPatchfinder(kernel: try! MachO(fromFile: "/Users/linus/kernelcache.release.iphone11.raw", okToLoadFAT: false)) else {
            XCTFail("KernelPatchfinder.running == nil!")
            return
        }
        
        try test(pf: pf)
        
        guard let data = pf.exportResults() else {
            XCTFail("pf.exportResults() == nil!")
            return
        }
        
        guard let pfRes = KernelPatchfinder(fromCachedResults: data) else {
            XCTFail("KernelPatchfinder(fromCachedResults: data) == nil!")
            return
        }
        
        try test(pf: pfRes)
    }
}
