.PHONY: all

all: jbinjector.dylib

jbinjector.dylib: jbinjector/jbinjector.c
	xcrun -sdk iphoneos clang -arch arm64e $< -o $@ -shared; codesign -s - $@
