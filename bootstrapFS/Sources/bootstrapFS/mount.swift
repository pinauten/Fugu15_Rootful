//
//  mount.swift
//  bootstrapFS
//
//  Created by Linus Henze on 24.01.23.
//

import Foundation

enum MountError: Error {
    case mountFailed(error: Int32, str: String)
    case unmountFailed(error: Int32, str: String)
}

func getMountPoint() -> String {
    var statbuf = stat()
    stat(mountPointRoot, &statbuf)
    
    let rootStDev = statbuf.st_dev
    
    var i = 0
    while true {
        let mp = mountPointRoot + "/mnt\(i)"
        if !FileManager.default.fileExists(atPath: mp) {
            mkdir(mp, 0o700)
            return mp
        }
        
        // Already exists - Is something mounted here?
        if stat(mp, &statbuf) == 0 {
            if statbuf.st_dev == rootStDev {
                // Nothing mounted here
                return mp
            }
        }
        
        i += 1
    }
}

func _mount(volume: String) throws -> String {
    let mp  = getMountPoint()
    let mntBuf = malloc(8192)
    defer { free(mntBuf) }
    
    bzero(mntBuf, 8192)
    
    mntBuf?.advanced(by: 16).assumingMemoryBound(to: mode_t.self).pointee = 1
    
    let res = ("/dev/" + volume).withCString { ptr in
        mntBuf?.assumingMemoryBound(to: UnsafePointer<CChar>.self).pointee = ptr
        print("Mount: \(volume) -> \(mp)")
        return mount("apfs", mp, MNT_DONTBROWSE, mntBuf)
    }
    
    if res != 0 {
        throw MountError.mountFailed(error: errno, str: String(cString: strerror(errno)))
    }
    
    return mp
}

func mount(volume: String) throws -> String {
    for _ in 0..<10 {
        do {
            return try _mount(volume: volume)
        } catch {}
    }
    
    // One last try
    return try _mount(volume: volume)
}

func umount(mountPoint: String, allowForce: Bool = false) throws {
    var res = unmount(mountPoint, 0)
    if res != 0 {
        if allowForce {
            res = unmount(mountPoint, MNT_FORCE)
        }
        
        guard res == 0 else {
            throw MountError.unmountFailed(error: errno, str: String(cString: strerror(errno)))
        }
    }
    
    try? FileManager.default.removeItem(atPath: mountPoint)
}
