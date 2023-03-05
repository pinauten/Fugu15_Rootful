//
//  KRW.swift
//  KRW
//
//  Created by Linus Henze on 2023-01-13.
//  Copyright © 2023 Pinauten GmbH. All rights reserved.
//

import Foundation
import KRWC
import KernelPatchfinder
import iDownload
import PatchfinderUtils

public enum KRWError: Error {
    case failed(providerError: Int32)
    case patchfinderFailed(symbol: String)
    case failedToTranslate(address: UInt64, table: String, entry: UInt64)
    case failedToGetKObject(ofPort: mach_port_t)
}

fileprivate func get_offset(_ name: UnsafePointer<CChar>) -> UInt {
    let str = String(cString: name)
    
    KRW.logger(str)
    
    return 0
}

public class KRW {
    private  static var didInit     = false
    internal static var didInitPAC  = false
    internal static var didInitPPL  = false
    public   static let patchfinder = KernelPatchfinder.running!
    
    internal static var phystokvTable: [phystokvEntry] = []
    public internal(set) static var physBase: UInt64 = 0
    public internal(set) static var virtBase: UInt64 = 0
    public internal(set) static var ttep: UInt64?
    
    internal static var signedState = Data()
    internal static var actContext: UInt64!
    internal static var mappedState: UnsafeMutablePointer<kRegisterState>!
    internal static var scratchMemory: UInt64!
    internal static var scratchMemoryMapped: UnsafeMutablePointer<UInt64>!
    internal static var kernelStack: UInt64!
    internal static var kcallThread: mach_port_t!
    
    public private(set) static var ourProc: Proc? = {
        try? Proc(pid: getpid())
    }()
    
    public private(set) static var kernelProc: Proc? = {
        try? Proc(pid: 0)
    }()
    
    public private(set) static var launchdProc: Proc? = {
        try? Proc(pid: 1)
    }()
    
    public static var logger: (_: String) -> Void = {_ in }
    
    public init() throws {
        try Self.doInit()
    }
    
    internal static func doInit() throws {
        guard !didInit else {
            return
        }
        
        let res = krw_init(get_offset)
        guard res == 0 else {
            throw KRWError.failed(providerError: res)
        }
        
        didInit = true
    }
    
    public static func kread(virt: UInt64, size: Int) throws -> Data {
        try doInit()
        
        var data = Data(repeating: 0, count: size)
        let res = data.withUnsafeMutableBytes { ptr in
            krw_kread(UInt(virt), ptr.baseAddress!, size)
        }
        
        guard res == 0 else {
            throw KRWError.failed(providerError: res)
        }
        
        return data
    }
    
    public static func kreadGeneric<T>(virt: UInt64, type: T.Type = T.self) throws -> T {
        try kread(virt: virt, size: MemoryLayout<T>.size).getGeneric(type: T.self)
    }
    
    public static func rPtr(virt: UInt64) throws -> UInt64 {
        let ptr: UInt64 = try kreadGeneric(virt: virt)
        if ((ptr >> 55) & 1) == 1 {
            return ptr | 0xFFFFFF8000000000
        }
        
        return ptr
    }
    
    public static func r64(virt: UInt64) throws -> UInt64 {
        try kreadGeneric(virt: virt)
    }
    
    public static func r32(virt: UInt64) throws -> UInt32 {
        try kreadGeneric(virt: virt)
    }
    
    public static func r16(virt: UInt64) throws -> UInt16 {
        try kreadGeneric(virt: virt)
    }
    
    public static func r8(virt: UInt64) throws -> UInt8 {
        try kreadGeneric(virt: virt)
    }
    
    public static func kwrite(virt: UInt64, data: Data) throws {
        try doInit()
        
        let res = data.withUnsafeBytes { ptr in
            krw_kwrite(UInt(virt), ptr.baseAddress!, ptr.count)
        }
        
        guard res == 0 else {
            throw KRWError.failed(providerError: res)
        }
    }
    
    public static func kwriteGeneric<T>(virt: UInt64, object: T) throws {
        try kwrite(virt: virt, data: Data(fromObject: object))
    }
    
    public static func w64(virt: UInt64, value: UInt64) throws {
        try kwriteGeneric(virt: virt, object: value)
    }
    
    public static func w32(virt: UInt64, value: UInt32) throws {
        try kwriteGeneric(virt: virt, object: value)
    }
    
    public static func w16(virt: UInt64, value: UInt16) throws {
        try kwriteGeneric(virt: virt, object: value)
    }
    
    public static func w8(virt: UInt64, value: UInt8) throws {
        try kwriteGeneric(virt: virt, object: value)
    }
    
    public static func kbase() throws -> UInt64 {
        try doInit()
        
        return UInt64(krw_kbase())
    }
    
    public static func kslide() throws -> UInt64 {
        try Self.kbase() &- 0xFFFFFFF007004000
    }
    
    public static func slide(virt: UInt64) throws -> UInt64 {
        try virt + Self.kslide()
    }
}
