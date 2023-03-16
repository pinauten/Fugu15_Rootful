.PHONY: all clean

all: libdyldhook.dylib

libdyldhook.dylib: libdyldhook.c libdyldhook.S task.c CodeSignature.c sha256.c
	xcrun -sdk iphoneos clang -arch arm64e $^ -o $@ -shared -Xlinker -add_split_seg_info -Xlinker -no_auth_data
	codesign -s - $@

clean:
	rm -f libdyldhook.dylib
