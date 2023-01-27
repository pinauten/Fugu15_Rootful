SDK=iphoneos
SDK_PATH=$(shell xcrun --sdk $(SDK) --show-sdk-path)

TARGET=arm64e-apple-ios14.0
CONFIG=debug

SWIFTC_ARGS=-sdk "$(SDK_PATH)" -target $(TARGET) -O -framework IOKit -framework CoreServices -D__DARWIN_OPAQUE_ARM_THREAD_STATE64
SWIFT_BUILD_ARGS=-c $(CONFIG) --product FuFuGuGu -Xcc "-DIOS_BUILD" -Xcc -target -Xcc $(TARGET) -Xcc -Wno-incompatible-sysroot $(addprefix -Xswiftc ,$(SWIFTC_ARGS))

all: libFuFuGuGu.dylib

.PHONY: all build_clean clean

libFuFuGuGu.dylib: .build/$(CONFIG)/libFuFuGuGu.dylib FORCE
	@cp .build/$(CONFIG)/libFuFuGuGu.dylib libFuFuGuGu.dylib
	codesign -s - -f libFuFuGuGu.dylib

.build/$(CONFIG)/%: Sources/FuFuGuGu FORCE
	@echo Building libFuFuGuGu.dylib
	swift build $(SWIFT_BUILD_ARGS)
	
build_clean:
	rm -rf .build
	
clean: build_clean
	rm -f libFuFuGuGu.dylib

FORCE: ;
