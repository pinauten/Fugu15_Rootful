# Fugu15
Fugu15 is a semi-untethered permasigned jailbreak for iOS 15.  
It contains a code-signing bypass, kernel exploit, kernel PAC bypass and PPL bypass.  
Additionally, it can be installed via Safari, i.e. a computer is not required, except for a Web Server that hosts Fugu15.  

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
