.PHONY: all clean

all: jbinjector.dylib

jbinjector.dylib: jbinjector_arm64.dylib jbinjector_arm64e.dylib
	lipo -create -output $@ $<

jbinjector_arm64.dylib: jbinjector/jbinjector.c
	xcrun -sdk iphoneos clang -arch arm64 $< -o $@ -shared; codesign -s - $@

jbinjector_arm64e.dylib: jbinjector/jbinjector.c
	xcrun -sdk iphoneos clang -arch arm64e $< -o $@ -shared; codesign -s - $@

clean:
	rm -f jbinjector.dylib jbinjector_arm64.dylib jbinjector_arm64e.dylib
