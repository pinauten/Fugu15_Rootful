//
//  APFS.swift
//  bootstrapFS
//
//  Created by Linus Henze on 24.01.23.
//

import Foundation
import CBridge

typealias APFSVolumeCreateType = @convention(c) (_: UnsafePointer<CChar>, _: CFMutableDictionary?) -> Int32
var APFSVolumeCreate: APFSVolumeCreateType!

typealias APFSVolumeDeleteType = @convention(c) (_: UnsafePointer<CChar>) -> Int32
var APFSVolumeDelete: APFSVolumeDeleteType!

var didInitAPFSFuncs = false

func apfsFuncsEnsure() throws {
    guard !didInitAPFSFuncs else {
        return
    }
    
    dlopen("/System/Library/PrivateFrameworks/APFS.framework/APFS", RTLD_NOW)
    
    let handle = dlopen(nil, 0)
    func getfunc<T>(_ name: String) throws -> T {
        guard let raw = dlsym(handle, name) else {
            throw APFSError.failedToFindAPFSFunc(name: name)
        }
        
        return unsafeBitCast(raw, to: T.self)
    }
    
    APFSVolumeCreate = try getfunc("APFSVolumeCreate")
    APFSVolumeDelete = try getfunc("APFSVolumeDelete")
}

func findAllVolumes(forContainer cont: String) throws -> [String] {
    var result: [String] = []
    for dev in try FileManager.default.contentsOfDirectory(atPath: "/dev") {
        if dev.starts(with: cont) && dev != cont {
            result.append(dev)
        }
    }
    
    return result
}

func getName(ofVolume volume: String) -> String? {
    let matching = IOServiceMatching("AppleAPFSVolume")
    var iter: io_iterator_t = 0
    let kr: kern_return_t = IOServiceGetMatchingServices(0, matching, &iter)
    
    guard kr == KERN_SUCCESS else {
        return nil
    }
    
    defer { IOObjectRelease(iter) }
    
    var service = IOIteratorNext(iter)
    while service != 0 {
        if let dev  = IORegistryEntrySearchCFProperty(service, kIOServicePlane, "BSD Name" as CFString, nil, 0) {
            if dev as? String == volume {
                if let name = IORegistryEntrySearchCFProperty(service, kIOServicePlane, "FullName" as CFString, nil, 0) {
                    IOObjectRelease(service)
                    
                    return name as? String
                }
            }
        }
        
        IOObjectRelease(service)
        service = IOIteratorNext(iter)
    }
    
    return nil
}

/**
 * Find our new root fs. If it doesn't exist, create it.
 */
func findOrCreateVolume(name volName: String) throws -> (device: String, created: Bool) {
    try apfsFuncsEnsure()
    
    let volumes = try findAllVolumes(forContainer: rootDiskDevice)
    
    for volume in volumes {
        if let name = getName(ofVolume: volume) {
            if name == volName {
                return (device: volume, created: false)
            }
        }
    }
    
    // Not found, create it
    let createDict = [
        "com.apple.apfs.volume.name": volName
    ] as CFDictionary
    let createDictMut = CFDictionaryCreateMutableCopy(nil, 0, createDict)
    
    let res = APFSVolumeCreate(rootDiskDevice, createDictMut)
    guard res == 0 else {
        throw APFSError.failedToCreateVolume(error: res)
    }
    
    guard let index = (createDictMut as! [String: Any])["com.apple.apfs.volume.fs_index"] as? NSNumber else {
        throw APFSError.failedToGetNewVolumeIndex
    }
    
    let index32 = index.int32Value + 1
    
    return (device: rootDiskDevice + "s\(index32)", created: true)
}

func kill(volume: String) throws {
    let res = APFSVolumeDelete(volume)
    if res != 0 {
        throw APFSError.failedToKillVolume(error: res)
    }
}

enum APFSError: Error {
    case failedToFindAPFSFunc(name: String)
    case failedToCreateServiceIterator(error: Int32)
    case failedToCreateVolume(error: Int32)
    case failedToGetNewVolumeIndex
    case failedToKillVolume(error: Int32)
}
