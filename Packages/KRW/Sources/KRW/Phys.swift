//
//  Phys.swift
//  KRW
//
//  Created by Linus Henze on 2023-01-14.
//  Copyright © 2023 Pinauten GmbH. All rights reserved.
//  

import Foundation

public extension KRW {
    static func phystokv(phys: UInt64) throws -> UInt64 {
        if phystokvTable.count == 0 {
            guard let data = patchfinder.ptov_data else {
                throw KRWError.patchfinderFailed(symbol: "ptov_data")
            }
            
            let table = try KRW.slide(virt: data.table)
            
            guard let virtBaseRaw = data.virtBase else {
                throw KRWError.patchfinderFailed(symbol: "ptov_data.virtBase")
            }
            
            guard let physBaseRaw = data.physBase else {
                throw KRWError.patchfinderFailed(symbol: "ptov_data.physBase")
            }
            
            virtBase = try KRW.r64(virt: KRW.slide(virt: virtBaseRaw))
            physBase = try KRW.r64(virt: KRW.slide(virt: physBaseRaw))
            
            for i: UInt64 in 0..<8 {
                let pa  = try KRW.r64(virt: table + (i * 0x18))
                let va  = try KRW.r64(virt: table + (i * 0x18) + 0x8)
                let len = try KRW.r64(virt: table + (i * 0x18) + 0x10)
                
                phystokvTable.append(.init(pa: pa, va: va, len: len))
            }
        }
        
        for entry in phystokvTable {
            if let va = entry.translate(pa: phys) {
                return va
            }
        }
        
        // Otherwise, do static translation
        return phys &- physBase &+ virtBase
    }
    
    static func r64(phys: UInt64) throws -> UInt64 {
        try KRW.r64(virt: phystokv(phys: phys))
    }
    
    static func r32(phys: UInt64) throws -> UInt32 {
        try KRW.r32(virt: phystokv(phys: phys))
    }
    
    static func r16(phys: UInt64) throws -> UInt16 {
        try KRW.r16(virt: phystokv(phys: phys))
    }
    
    static func r8(phys: UInt64) throws -> UInt8 {
        try KRW.r8(virt: phystokv(phys: phys))
    }
    
    private static func _walkPageTable(table: UInt64, virt: UInt64) throws -> UInt64 {
        let table1Off = (virt >> 36) & 0x7
        let table1Entry = try r64(phys: table + (8 * table1Off))
        guard (table1Entry & 0x3) == 3 else {
            throw KRWError.failedToTranslate(address: virt, table: "table1", entry: table1Entry)
        }
        
        let table2 = table1Entry & 0xFFFFFFFFC000
        let table2Off = (virt >> 25) & 0x7FF
        let table2Entry = try r64(phys: table2 + (8 * table2Off))
        switch table2Entry & 0x3 {
        case 1:
            // Easy, this is a block
            return (table2Entry & 0xFFFFFE000000) | (virt & 0x1FFFFFF)
            
        case 3:
            // Another table
            let table3 = table2Entry & 0xFFFFFFFFC000
            let table3Off = (virt >> 14) & 0x7FF
            let table3Entry = try r64(phys: table3 + (8 * table3Off))
            guard (table3Entry & 0x3) == 3 else {
                throw KRWError.failedToTranslate(address: virt, table: "table3", entry: table3Entry)
            }
            
            return (table3Entry & 0xFFFFFFFFC000) | (virt & 0x3FFF)
        default:
            throw KRWError.failedToTranslate(address: virt, table: "table2", entry: table2Entry)
        }
    }
    
    static func walkPageTable(table: UInt64, virt: UInt64) throws -> UInt64 {
        let res = try _walkPageTable(table: table, virt: virt)
        if res == 0 {
            throw KRWError.failedToTranslate(address: virt, table: "Unknown", entry: 0)
        }
        
        return res
    }
    
    static func kvtophys(kv: UInt64) throws -> UInt64 {
        if ttep == nil {
            guard let cpu_ttep = patchfinder.cpu_ttep else {
                throw KRWError.patchfinderFailed(symbol: "cpu_ttep")
            }
            
            ttep = try KRW.r64(virt: KRW.slide(virt: cpu_ttep))
        }
        
        return try walkPageTable(table: ttep.unsafelyUnwrapped, virt: kv)
    }
}

internal struct phystokvEntry {
    let pa:  UInt64
    let va:  UInt64
    let len: UInt64
    
    func translate(pa: UInt64) -> UInt64? {
        let end = self.pa + len
        guard pa >= self.pa && pa < end else {
            return nil
        }
        
        return pa &- self.pa &+ self.va
    }
}
