//
//  Map.swift
//  KRW
//
//  Created by Linus Henze on 2023-01-14.
//  Copyright © 2023 Pinauten GmbH. All rights reserved.
//  

import Foundation
import IOSurface

public extension KRW {
    internal static func getSurfacePort(magic: UInt64 = 1337) throws -> mach_port_t {
        let surf = IOSurfaceCreate([
            kIOSurfaceWidth: 120,
            kIOSurfaceHeight: 120,
            kIOSurfaceBytesPerElement: 4
        ] as CFDictionary)
        
        let port = IOSurfaceCreateMachPort(surf!)
        
        IOSurfaceGetBaseAddress(surf!).assumingMemoryBound(to: UInt64.self).pointee = magic
        
        IOSurfaceDecrementUseCount(surf!)
        
        return port
    }
    
    static func map(phys: UInt64, size: UInt64) throws -> UnsafeMutableRawPointer? {
        let port = try getSurfacePort()
        let surface = try KRW.rPtr(virt: try KRW.ourProc!.task!.getKObject(ofPort: port) + 0x18 /* IOSurfaceSendRight -> IOSurface */)
        let desc = try KRW.rPtr(virt: surface + 0x38 /* IOSurface -> IOMemoryDescriptor */)
        let ranges = try KRW.rPtr(virt: desc + 0x60)
        
        // Write the desired address and length to the ranges entry
        try KRW.w64(virt: ranges, value: phys)
        try KRW.w64(virt: ranges + 0x8, value: size)
        
        // Change the whole object to the correct size
        try KRW.w64(virt: desc + 0x50, value: size)
        
        // Clear task and some other stuff
        try KRW.w64(virt: desc + 0x70, value: 0)
        try KRW.w64(virt: desc + 0x18, value: 0)
        try KRW.w64(virt: desc + 0x90, value: 0)
        
        // Set wired (physical addresses are by definition wired)
        try KRW.w8(virt: desc + 0x88, value: 1)
        
        // Set this to be a physical memory descriptor
        let flags = (try KRW.r32(virt: desc + 0x20) & ~0x410) | 0x20
        try KRW.w32(virt: desc + 0x20, value: flags)
        
        // Finally, clear _memRef so it's reconstructed
        try KRW.w64(virt: desc + 0x28, value: 0)
        
        // Map!
        guard let surf = IOSurfaceLookupFromMachPort(port) else {
            return nil
        }
        
        // Leak surface to keep mapping
        _ = Unmanaged.passRetained(surf)
        
        return IOSurfaceGetBaseAddress(surf)
    }
    
    static func map(virt: UInt64, size: UInt64) throws -> UnsafeMutableRawPointer? {
        try map(phys: kvtophys(kv: virt), size: size)
    }
}
