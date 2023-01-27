SDK=iphoneos
SDK_PATH=$(shell xcrun --sdk $(SDK) --show-sdk-path)

TARGET=arm64-apple-ios14.0
CONFIG=debug

SWIFTC_ARGS=-sdk "$(SDK_PATH)" -target $(TARGET) -O -framework IOKit -framework CoreServices -D__DARWIN_OPAQUE_ARM_THREAD_STATE64
SWIFT_BUILD_ARGS=-c $(CONFIG) -Xcc "-DIOS_BUILD" -Xcc -target -Xcc $(TARGET) -Xcc -Wno-incompatible-sysroot $(addprefix -Xswiftc ,$(SWIFTC_ARGS))

all: bootstrapFS

.PHONY: all build_clean clean

bootstrapFS: .build/$(CONFIG)/bootstrapFS FORCE
	@cp .build/$(CONFIG)/bootstrapFS bootstrapFS
	codesign -s - -f --entitlements bootstrapFS.entitlements bootstrapFS

.build/$(CONFIG)/%: Sources/% FORCE
	@echo Building bootstrapFS
	swift build $(SWIFT_BUILD_ARGS)
	
build_clean:
	rm -rf .build
	
clean: build_clean
	rm -f bootstrapFS

FORCE: ;
