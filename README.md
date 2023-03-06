# Fugu15
Fugu15 is a semi-untethered permasigned jailbreak for iOS 15.  
It contains a code-signing bypass, kernel exploit, kernel PAC bypass and PPL bypass.  
Additionally, it can be installed via Safari, i.e. a computer is not required, except for a Web Server that hosts Fugu15.  

# Progress
Current Fugu15 progress.

## Fugu15
- [x] Make Fugu15 a non-rootless jailbreak
- [ ] Automatically mount Fugu15 partitions over real rootFS
- [ ] Allow execution of self-signed binaries
- [ ] Allow loading of self-signed binaries
- [ ] Implement Tweak Injection
- [ ] Allow unsigned code
- [ ] ???

## FuFuGuGu
Library injected into launchd and xpcproxy
- [x] Successfully inject into launchd
- [x] Hook required methods
- [ ] Launch stashd before userspace reboots
- [x] Survive userspace reboots
- [x] Implement service that can be looked up by applications
- [ ] Provide service to add CSDebugged to applications
- [ ] Provide service to add CDHash to TrustCache
- [ ] Provide service to allow applications to access sandboxed files/folders
- [ ] Provide service to allow applications to execute unsigned code
- [ ] Implement libkrw/libkernrw/libwhateverrw support
- [ ] Load tweak injection library
- [ ] ???

## stashd
Helper service
- [x] Transfer PPL bypass to stashd
- [x] Transfer PAC bypass to stashd
- [x] Survive userspace reboot
- [x] Transfer primitives to launchd
- [ ] ???

## dyld
- [x] Patch dyld to allow `DYLD_INSERT_LIBRARIES` (done via `DYLD_AMFI_FAKE`)
- [x] Automatically patch dyld
- [ ] ???

# Tested Devices and iOS Versions
- iPhone 12 (SRD): iOS 15.4.1

FIXME: Other iOS versions/devices are currently not supported

# Building
Prerequisites:  
1. Make sure you have Xcode 14.2 installed

Now you can simply run `make` to build Fugu15 (internet connection required to download dependencies).

# Installing
Note: This is only relevant if you built Fugu15 yourself. If you're using a precompiled release, see the instructions for your release.

~~There are three ways to install Fugu15 on your device: Via Safari, USB or TrollStore.~~
Install via Xcode or TrollStore for now.

## Installing via TrollStore
1. Make sure you have TrollStore installed
2. AirDrop `Fugu15.tipa` to your device
3. Select TrollStore in the "Open with..." prompt

# iDownload
Like all Fugu jailbreaks, Fugu15 ships with iDownload. The iDownload shell can be accessed on port 1337 (run `iproxy 1337 1337 &` and then `nc 127.1 1337` to connect to iDownload).  
Type `help` to see a list of supported commands.  
The following commands are especially useful:
- `r64/r32/r16/r8 <address>`: Read a 64/32/16/8 bit integer at the given kernel address. Add the `@S` suffix to slide the given address or `@P` to read from a physical address.
- `w64/w32/w16/w8 <address> <value>`: Write the given 64/32/16/8 bit integer to the given kernel address. Also supports the suffixes described above and additionally `@PPL` to write to a PPL protected address (see `krwhelp`).
- `kcall <address> <up to 8 arguments>`: Call the kernel function at the given address, passing up to 8 64-Bit integer arguments.
- `tcload <path to TrustCache>`: Load the given TrustCache into the kernel

# Procursus Bootstrap and Sileo
Fugu15 also ships with the procursus bootstrap and Sileo. Run the `bootstrap` command in iDownload to install both. Afterwards, you might have to respring to force Sileo to show up on the Home Screen (`uicache -r`).

Procursus is installed into the `/private/preboot/jb` directory and `/var/jb` is a symlink to it.

FIXME: Do non-rootless install.

# FIXME
This README is incomplete.
