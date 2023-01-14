//
//  Test.swift
//  Fugu15
//
//  Created by Linus Henze on 2023-01-13.
//  Copyright © 2023 Pinauten GmbH. All rights reserved.
//  

import Foundation
import KernelPatchfinder
import KRW
import IOSurface

let pf = KernelPatchfinder.running!

func getSurfacePort(magic: UInt64 = 1337) throws -> mach_port_t {
    let surf = IOSurfaceCreate([
        kIOSurfaceWidth: 120,
        kIOSurfaceHeight: 120,
        kIOSurfaceBytesPerElement: 4
    ] as CFDictionary)
    
    let port = IOSurfaceCreateMachPort(surf!)
    
    print("Base: \(IOSurfaceGetBaseAddress(surf!))")
    print("Size: \(IOSurfaceGetAllocSize(surf!))")
    
    IOSurfaceGetBaseAddress(surf!).assumingMemoryBound(to: UInt64.self).pointee = magic
    
    //try dumpSurface(port: port)
    
    IOSurfaceDecrementUseCount(surf!)
    
    return port
}

func testkrwstuff() throws {
    let port = try getSurfacePort()
    let surface = try KRW.rPtr(virt: try KRW.ourProc!.task!.getKObject(ofPort: port) + 0x18 /* IOSurfaceSendRight -> IOSurface */)
    
    let surfaceBase = surface & ~0x3FFF
    let surfaceOff  = surface & 0x3FFF
    
    let mapped = try KRW.map(virt: surfaceBase, size: 0x4000)
    
    try print("krw r64: \(KRW.r64(virt: surface))")
    print("mapped: \(mapped!.advanced(by: Int(surfaceOff)).assumingMemoryBound(to: UInt64.self).pointee)")
    print("Hilo!")
    
    try KRW.doPPLBypass()
}

func withKernelCredentials<T>(_ do: () throws -> T) rethrows {
    
}
