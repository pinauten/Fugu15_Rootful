.PHONY: all clean

all: jbinjector.dylib

jbinjector.dylib: jbinjector/jbinjector.c jbinjector/CodeSignature.c
	xcrun -sdk iphoneos clang -arch arm64 -arch arm64e $^ -o $@ -shared; codesign -s - $@

clean:
	rm -f jbinjector.dylib
