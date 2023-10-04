# Fugu15 - Rootful Edition
Fugu15 is a semi-untethered permasigned jailbreak for iOS 15.  
This version includes full support for tweaks and is rootful.  
Special thanks to [tihmstar](https://twitter.com/tihmstar) for helping to turn Fugu15 into a full jailbreak and for extensively testing it.

# WARNING - ONLY FOR DEVELOPERS
No support will be provided for this version of Fugu15. Feel free to fix it if you want to, but note that no pull requests will be accepted as I'm done with jailbreaking.  

# Tested Devices and iOS Versions
- iPhone Xs Max: iOS 15.4.1
- iPhone 13 Pro: iOS 15.1

# Building
Prerequisites:  
1. Make sure you have Xcode 14.2 installed

Now you can simply run `make` to build Fugu15 (internet connection required to download dependencies).

# Installing
Simply install it via Xcode. Currently doesn't support installation via TrollStore because of some bugs.

# Bootstrapping
Currently, there is no easy way to bootstrap this version of Fugu15. To bootstrap it:
- Remove the `doit` command from `iDownload_autorun` in `Fugu15/Fugu15/iDownloadCmds.swift`
- Jailbreak, then once you see the success message (don't tap on `Reboot Userspace`!), connect to iDownload and run the following commands:
- `stealCreds 1`
- `rsc MachOMerger`
- `rsc libdyldhook.dylib`
- `rsc ldid`
- `rsc bootstrapFS`
- `rsc tar`
- `rsc bootstrap_root.tar`
- `/private/preboot/bootstrapFS` (You may have to run this multiple times until it works)
- `rootfs /dev/disk0s1s8 /dev/disk0s1s9 /dev/disk0s1s10 /dev/disk0s1s11 /dev/disk0s1s12 /dev/disk0s1s13` (You might need to adjust the partition names based on the bootstrapFS output)
- `cd /`
- `/private/preboot/tar -xvf /private/preboot/bootstrap_root.tar`
- Now reboot your device and add the `doit` command back to `iDownload_autorun`
- Jailbreak, then once you see the success message (don't tap on `Reboot Userspace`!), connect to iDownload and install OpenSSH via dpkg (debs not provided)
- Tap on the `Reboot Userspace` button
- After the userspace reboot, SSH should be running. Use it to install Sileo and libhooker (debs not provided)
- When done correctly, you should now have a rootful jailbreak which supports all Tweaks!

# iDownload
Like all Fugu jailbreaks, Fugu15 ships with iDownload. The iDownload shell can be accessed on port 1337 (run `iproxy 1337 1337 &` and then `nc 127.1 1337` to connect to iDownload).  
Type `help` to see a list of supported commands.  
The following commands are especially useful:
- `r64/r32/r16/r8 <address>`: Read a 64/32/16/8 bit integer at the given kernel address. Add the `@S` suffix to slide the given address or `@P` to read from a physical address.
- `w64/w32/w16/w8 <address> <value>`: Write the given 64/32/16/8 bit integer to the given kernel address. Also supports the suffixes described above and additionally `@PPL` to write to a PPL protected address (see `krwhelp`).
- `kcall <address> <up to 8 arguments>`: Call the kernel function at the given address, passing up to 8 64-Bit integer arguments.
- `tcload <path to TrustCache>`: Load the given TrustCache into the kernel

# Credits
The following open-source software is used by Fugu15:
- [ldid](https://github.com/ProcursusTeam/ldid): Used to resign the patched dyld. License: [GNU Affero General Public License v3.0](https://github.com/ProcursusTeam/ldid/blob/master/COPYING)
- [libgrabkernel](https://github.com/tihmstar/libgrabkernel): Used to download the kernel for the device so the patchfinder can be run. License: [MIT](https://github.com/tihmstar/libgrabkernel/blob/master/LICENSE)
- [libtakeover](https://github.com/tihmstar/libtakeover): `inject_criticald`, used to inject `FuFuGuGu.dylib` into launchd. License: [GNU Lesser General Public License](https://github.com/tihmstar/libtakeover/blob/master/LICENSE)
- [multicast_bytecopy](https://github.com/potmdehex/multicast_bytecopy): One of the kernel exploits included in Fugu15. License: Unknown - No license provided
- [Procursus Bootstrap](https://github.com/ProcursusTeam/Procursus): The bootstrap used by Fugu15. License: [BSD 0-Clause](https://github.com/ProcursusTeam/Procursus/blob/main/LICENSE). The tools included in the bootstrap are released under many different licenses, please see the procursus repo for more information
- [Sileo](https://github.com/Sileo/Sileo): The package manager included in Fugu15. License: [BSD 4-Clause](https://github.com/Sileo/Sileo/blob/main/LICENSE)
- [weightBufs](https://github.com/0x36/weightBufs): One of the kernel exploits included in Fugu15. License: [MIT](https://github.com/0x36/weightBufs/blob/main/LICENSE)

# License
MIT. See the `LICENSE` file.
