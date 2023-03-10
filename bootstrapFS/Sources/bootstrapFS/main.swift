//
//  main.swift
//  bootstrapFS
//
//  Created by Linus Henze on 24.01.23.
//

import Foundation

func ensureFuguPartition(name: String, realPath: String, rootfs: String) throws -> String {
    // First get or create our volume
    var (device, created) = try findOrCreateVolume(name: name)
    print("\(name): \(device) created: \(created)")

    // Mount it
    var mp = try mount(volume: device)
    defer { try? umount(mountPoint: mp, allowForce: true) }

    // If we didn't have to create it...
    if !created {
        if !FileManager.default.fileExists(atPath: mp + "/.Fugu15/fsPrepared") {
            // ...and it doesn't contain "/.Fugu15/fsPrepared", kill it and recreate
            
            print("Partition \(name) invalid - killing it")
            
            // Unmount
            try umount(mountPoint: mp, allowForce: true /* killing it anyway */)
            
            // Kill volume
            try kill(volume: device)
            
            // Recreate
            (device, created) = try findOrCreateVolume(name: name)
            
            // Remount
            mp = try mount(volume: device)
        } else {
            // Otherwise, we are done!
            print("Partition \(name) already prepared")
            return "/dev/" + device
        }
    }

    // Had to create volume - Prepare it
    
    // Copy real to new rootfs
    try copyRootfs(real: rootfs + realPath, new: mp)
    
    mkdir(mp + "/.Fugu15", 0o700)
    
    if name == "Fugu15Usr" {
        unlink(mp + "/usr/lib/dyld")
        try patchDYLD(real: "/usr/lib/dyld", patched: mp + "/lib/dyld", trustCache: mp + "/.Fugu15/TrustCache")
    }
    
    // Create fsPrepared file
    creat(mp + "/.Fugu15/fsPrepared", 0o600)
    sync()
    
    print("Prepared partition \(name)")

    return "/dev/" + device
}

#if os(iOS)
func main() throws {
    //let rootfs = try mount(volume: rootDiskVolume)
    //defer { try? umount(mountPoint: rootfs, allowForce: true) }
    //let rootfs = "/private/var/mnt/rootfs"
    let rootfs = "/"
    
    let app  = try ensureFuguPartition(name: "Fugu15App", realPath: "/Applications", rootfs: rootfs)
    let lib  = try ensureFuguPartition(name: "Fugu15Lib", realPath: "/Library", rootfs: rootfs)
    let bin  = try ensureFuguPartition(name: "Fugu15Bin", realPath: "/bin", rootfs: rootfs)
    let etc  = try ensureFuguPartition(name: "Fugu15Etc", realPath: "/etc", rootfs: rootfs)
    let sbin = try ensureFuguPartition(name: "Fugu15Sbin", realPath: "/sbin", rootfs: rootfs)
    let usr  = try ensureFuguPartition(name: "Fugu15Usr", realPath: "/usr", rootfs: rootfs)
    
    print("PART APP: \(app)")
    print("PART LIB: \(lib)")
    print("PART BIN: \(bin)")
    print("PART ETC: \(etc)")
    print("PART SBIN: \(sbin)")
    print("PART USR: \(usr)")
}
#else
func main() throws {
    guard CommandLine.arguments.count == 4 else {
        print("Usage: bootstrapFS <real dyld> <patched dyld out> <trust cache out>")
        exit(-1)
    }
    
    try patchDYLD(real: CommandLine.arguments[1], patched: CommandLine.arguments[2], trustCache: CommandLine.arguments[3])
}
#endif

do {
    try main()
    exit(0)
} catch let e {
    print("bootstrapFS failed!")
    print("Exception: \(e)")
    exit(-1)
}
