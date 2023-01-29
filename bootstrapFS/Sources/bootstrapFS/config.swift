//
//  config.swift
//  bootstrapFS
//
//  Created by Linus Henze on 24.01.23.
//

import Foundation

#if os(iOS)
let rootDiskDevice = "disk0s1"
let rootDiskVolume = "disk0s1s1"
let mountPointRoot = "/private/var/mnt"
let ldid = Bundle.main.executableURL!.deletingLastPathComponent().appendingPathComponent("ldid").path
#else
let rootDiskDevice = "disk3"
let rootDiskVolume = "disk3s1"
let mountPointRoot = "/tmp/mnt"
let ldid = "ldid"
#endif
