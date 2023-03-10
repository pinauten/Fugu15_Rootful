//
//  SwiftGlue.swift
//  KRW
//
//  Created by Linus Henze on 2023-01-14.
//  Copyright © 2023 Pinauten GmbH. All rights reserved.
//  

import Foundation
import KRWC

@_cdecl("pcidev_r64")
public func pcidev_r64(_ virt: UInt64) -> UInt64 {
    (try? KRW.r64(virt: virt)) ?? 0
}

@_cdecl("pcidev_rPtr")
public func pcidev_rPtr(_ virt: UInt64) -> UInt64 {
    (try? KRW.rPtr(virt: virt)) ?? 0
}

@_cdecl("pcidev_w64")
public func pcidev_w64(_ virt: UInt64, _ val: UInt64) {
    try? KRW.w64(virt: virt, value: val)
}

@_cdecl("pcidev_w32")
public func pcidev_w32(_ virt: UInt64, _ val: UInt32) {
    try? KRW.w32(virt: virt, value: val)
}

@_cdecl("physrw_map_once")
public func physrw_map_once(_ phys: UInt64) -> UInt64 {
    guard let ptr = try? KRW.map(virt: phys, size: 0x4000) else {
        return 0
    }
    
    return UInt64(UInt(bitPattern: ptr))
}

@_cdecl("translateAddr")
public func translateAddr(_ virt: UInt64) -> UInt64 {
    (try? KRW.kvtophys(kv: virt)) ?? 0
}

@_cdecl("kmemAlloc")
public func kmemAlloc(_ size: UInt64, leak: Bool) -> UInt64 {
    (try? KRW.alloc(size: size, leak: leak)) ?? 0
}

@_cdecl("rp64")
public func rp64(_ phys: UInt64) -> UInt64 {
    (try? KRW.r64(phys: phys)) ?? 0
}

@_cdecl("translateAddr_inTTEP")
public func translateAddr_inTTEP(_ ttep: UInt64, _ virt: UInt64) -> UInt64 {
    (try? KRW.walkPageTable(table: ttep, virt: virt)) ?? 0
}

@_cdecl("getPageForPPL")
public func getPageForPPL() -> UInt64 {
    guard let f = KRW.patchfinder.pmap_alloc_page_for_kern else {
        return 0
    }
    
    guard let fSlid = try? KRW.slide(virt: f) else {
        return 0
    }
    
    return (try? KRW.kcall(func: fSlid, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0, a6: 0, a7: 0, a8: 0)) ?? 0
}

@_cdecl("krw_kread")
public func krw_kread(_ kernSrc: UInt, _ dst: UnsafeMutableRawPointer, size: Int) -> Int32 {
    switch KRW.selectedExploit.unsafelyUnwrapped {
    case .tfp0:
        return krw_kread_tfp0(kernSrc, dst, size)
        
    case .weightBufs:
        return krw_kread_weightBufs(kernSrc, dst, size)
        
    case .mcbc:
        return krw_kread_mcbc(kernSrc, dst, size)
    }
}

@_cdecl("krw_kwrite")
public func krw_kwrite(_ kernDst: UInt, _ src: UnsafeRawPointer, size: Int) -> Int32 {
    switch KRW.selectedExploit.unsafelyUnwrapped {
    case .tfp0:
        return krw_kwrite_tfp0(kernDst, src, size)
        
    case .weightBufs:
        return krw_kwrite_weightBufs(kernDst, src, size)
        
    case .mcbc:
        return krw_kwrite_mcbc(kernDst, src, size)
    }
}
