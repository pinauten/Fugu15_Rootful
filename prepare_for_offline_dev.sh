#!/bin/bash

mkdir -p OfflinePackages
cd OfflinePackages

git clone https://github.com/pinauten/SwiftUtils.git
git clone https://github.com/pinauten/SwiftMachO.git
git clone https://github.com/pinauten/PatchfinderUtils.git
git clone https://github.com/pinauten/KernelPatchfinder.git
git clone https://github.com/pinauten/iDownload.git
git clone https://github.com/weichsel/ZIPFoundation.git

cd ..

# Apply patch
patch -p1 < Fugu15Offline.patch
