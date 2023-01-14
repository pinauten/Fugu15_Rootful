//
//  iDownloadSupport.swift
//  KRW
//
//  Created by Linus Henze on 2023-01-14.
//  Copyright © 2023 Pinauten GmbH. All rights reserved.
//  

import Foundation
import iDownload

extension KRW: KRWHandler {
    public func getSupportedActions() -> iDownload.KRWOptions {
        [.virtRW, .kcall, .kalloc, .PPLBypass]
    }
    
    public func getInfo() throws -> (kernelBase: UInt64, slide: UInt64) {
        let kbase = try Self.kbase()
        
        return (kernelBase: kbase, slide: kbase &- 0xFFFFFFF007004000)
    }
    
    public func resolveAddress(forName: String) throws -> iDownload.KRWAddress? {
        return nil
    }
    
    public func kread(address: iDownload.KRWAddress, size: UInt) throws -> Data {
        guard !address.options.contains(.physical) else {
            throw iDownload.KRWError.notSupported
        }
        
        return try Self.kread(virt: address.address, size: Int(size))
    }
    
    public func kwrite(address: iDownload.KRWAddress, data: Data) throws {
        if address.options == [] {
            try Self.kwrite(virt: address.address, data: data)
        } else if address.options.contains(.physical) {
            try Self.pplwrite(phys: address.address, data: data)
        } else {
            try Self.pplwrite(virt: address.address, data: data)
        }
    }
    
    public func kalloc(size: UInt) throws -> UInt64 {
        try KRW.alloc(size: UInt64(size))
    }
    
    public func kfree(address: UInt64) throws {
        throw iDownload.KRWError.notSupported
    }
    
    public func kcall(func: iDownload.KRWAddress, a1: UInt64, a2: UInt64, a3: UInt64, a4: UInt64, a5: UInt64, a6: UInt64, a7: UInt64, a8: UInt64) throws -> UInt64 {
        guard `func`.options == [] else {
            throw iDownload.KRWError.notSupported
        }
        
        return try Self.kcall(func: `func`.address, a1: a1, a2: a2, a3: a3, a4: a4, a5: a5, a6: a6, a7: a7, a8: a8)
    }
}
