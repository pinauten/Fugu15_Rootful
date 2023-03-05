SDK=iphoneos
SDK_PATH=$(shell xcrun --sdk $(SDK) --show-sdk-path)

TARGET=arm64e-apple-ios14.0
CONFIG=debug

SWIFTC_ARGS=-sdk "$(SDK_PATH)" -target $(TARGET) -O -framework IOKit -framework CoreServices
SWIFT_BUILD_ARGS=-c $(CONFIG) -Xcc "-DIOS_BUILD" -Xcc -target -Xcc $(TARGET) -Xcc -Wno-incompatible-sysroot $(addprefix -Xswiftc ,$(SWIFTC_ARGS)) --sdk "$(SDK_PATH)"

all: stashd

.PHONY: all build_clean clean

stashd: .build/$(CONFIG)/stashd FORCE
	@cp .build/$(CONFIG)/stashd stashd_tmp
	@echo Codesigning stashd
	codesign -s - --entitlements stashd.entitlements stashd_tmp
	@mv stashd_tmp stashd

.build/$(CONFIG)/%: Sources/% FORCE
	@echo Building stashd
	swift build $(SWIFT_BUILD_ARGS)
	
build_clean:
	rm -rf .build
	rm -f stashd_tmp
	
clean: build_clean
	rm -f stashd

FORCE: ;
