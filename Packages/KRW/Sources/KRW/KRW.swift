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

public enum KRWError: Error {
    case failed(providerError: Int32)
}

fileprivate func get_offset(_ name: UnsafePointer<CChar>) -> UInt {
    let str = String(cString: name)
    
    KRW.logger(str)
    
    return 0
}

public class KRW: KRWHandler {
    private static var didInit = false
    public  static let patchfinder = KernelPatchfinder.running
    
    public static var logger: (_: String) -> Void = {_ in }
    
    public init() throws {
        try Self.doInit()
    }
    
    private static func doInit() throws {
        guard !didInit else {
            return
        }
        
        guard let pf = KernelPatchfinder.running else {
            throw KRWError.failed(providerError: 1234)
        }
        
        logger("ACT_CONTEXT: \(pf.ACT_CONTEXT ?? 0)")
        
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
    
    public static func kwrite(virt: UInt64, data: Data) throws {
        try doInit()
        
        let res = data.withUnsafeBytes { ptr in
            krw_kwrite(UInt(virt), ptr.baseAddress!, ptr.count)
        }
        
        guard res == 0 else {
            throw KRWError.failed(providerError: res)
        }
    }
    
    public static func kbase() throws -> UInt64 {
        try doInit()
        
        return UInt64(krw_kbase())
    }
    
    // iDownload KRW stuff
    public func getSupportedActions() -> iDownload.KRWOptions {
        .virtRW
    }
    
    public func getInfo() throws -> (kernelBase: UInt64, slide: UInt64) {
        let kbase = try Self.kbase()
        
        return (kernelBase: kbase, slide: kbase &- 0xFFFFFFF007004000)
    }
    
    public func resolveAddress(forName: String) throws -> iDownload.KRWAddress? {
        return nil
    }
    
    public func kread(address: iDownload.KRWAddress, size: UInt) throws -> Data {
        guard address.options == [] else {
            throw iDownload.KRWError.notSupported
        }
        
        return try Self.kread(virt: address.address, size: Int(size))
    }
    
    public func kwrite(address: iDownload.KRWAddress, data: Data) throws {
        guard address.options == [] else {
            throw iDownload.KRWError.notSupported
        }
        
        try Self.kwrite(virt: address.address, data: data)
    }
    
    public func kalloc(size: UInt) throws -> UInt64 {
        throw iDownload.KRWError.notSupported
    }
    
    public func kfree(address: UInt64) throws {
        throw iDownload.KRWError.notSupported
    }
    
    public func kcall(func: iDownload.KRWAddress, a1: UInt64, a2: UInt64, a3: UInt64, a4: UInt64, a5: UInt64, a6: UInt64, a7: UInt64, a8: UInt64) throws -> UInt64 {
        throw iDownload.KRWError.notSupported
    }
}
