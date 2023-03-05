//
//  Phys.swift
//  KRW
//
//  Created by Linus Henze on 2023-01-14.
//  Copyright © 2023 Pinauten GmbH. All rights reserved.
//  

import Foundation

public extension KRW {
    static func r64(phys: UInt64) throws -> UInt64 {
        PPLRW.r64(phys: phys)
    }
    
    static func r32(phys: UInt64) throws -> UInt32 {
        PPLRW.r32(phys: phys)
    }
    
    static func r16(phys: UInt64) throws -> UInt16 {
        PPLRW.r16(phys: phys)
    }
    
    static func r8(phys: UInt64) throws -> UInt8 {
        PPLRW.r8(phys: phys)
    }
    
    static func walkPageTable(table: UInt64, virt: UInt64) throws -> UInt64 {
        try PPLRW.walkPageTable(table: table, virt: virt)
    }
    
    static func kvtophys(kv: UInt64) throws -> UInt64 {
        try PPLRW.walkPageTable(table: PPLRW.cpuTTEP, virt: kv)
    }
}
