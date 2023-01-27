SDK=iphoneos
SDK_PATH=$(shell xcrun --sdk $(SDK) --show-sdk-path)

TARGET=arm64e-apple-ios14.0
CONFIG=debug

SWIFTC_ARGS=-sdk "$(SDK_PATH)" -target $(TARGET) -O -framework IOKit -framework CoreServices
SWIFT_BUILD_ARGS=-c $(CONFIG) -Xcc "-DIOS_BUILD" -Xcc -target -Xcc $(TARGET) -Xcc -Wno-incompatible-sysroot $(addprefix -Xswiftc ,$(SWIFTC_ARGS))

all: jailbreakd

.PHONY: all build_clean clean

jailbreakd: .build/$(CONFIG)/jailbreakd FORCE
	@cp .build/$(CONFIG)/jailbreakd jailbreakd_tmp
	@echo Codesigning jailbreakd
	codesign -s - --entitlements jailbreakd.entitlements jailbreakd_tmp
	@mv jailbreakd_tmp jailbreakd

.build/$(CONFIG)/%: Sources/% FORCE
	@echo Building jailbreakd
	cd Sources/MIGServer && mig -arch arm64 -sheader include/initServer.h -header ../../../Fugu15/Fugu15/init.h -user ../../../Fugu15/Fugu15/init.c init.mig
	cd Sources/MIGServer && mig -arch arm64 -sheader include/initServer.h -header ../../../FuFuGuGu/Sources/CBridge/init.h -user ../../../FuFuGuGu/Sources/CBridge/init.c init.mig
	swift build $(SWIFT_BUILD_ARGS)
	
build_clean:
	rm -rf .build
	rm -f jailbreakd_tmp
	
clean: build_clean
	rm -f jailbreakd

FORCE: ;
