//
//  CodeSignature.c
//  mmapTest
//
//  Created by Linus Henze on 2023-03-13.
//

#include "CodeSignature.h"

#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/dyld_images.h>
#include <mach-o/nlist.h>
#include <CommonCrypto/CommonDigest.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/fcntl.h>
#include <unistd.h>

#define safeClose(fd) do{if ((fd) != -1){close(fd); fd = -1;}}while(0)
#define safeFree(buf) do{if ((buf)){free(buf); buf = NULL;}}while(0)
#define safeMmapFree(buf, size) do{if ((buf) && (buf) != MAP_FAILED){munmap(buf, size); buf = NULL;}}while(0)
#define assure(cond) do {if (!(cond)){err = __LINE__; goto error;}}while(0)

#pragma mark parsing
int trustCDHashForCSSuperBlob(struct mach_header_64 *mh, const CS_CodeDirectory *csdir, size_t fatOffset, size_t cdOffset, int (^trustCDHash)(uint8_t*, size_t, uint8_t, size_t, size_t, size_t, struct mach_header_64 *)) {
    int err = 0;
    uint8_t hash[CC_SHA384_DIGEST_LENGTH] = {};
    size_t hashSize = sizeof(hash);
    switch (csdir->hashType) {
        case CS_HASHTYPE_SHA1:
            CC_SHA1(csdir, ntohl(csdir->length), hash);
            hashSize = 20;
            break;
        case CS_HASHTYPE_SHA256:
            CC_SHA256(csdir, ntohl(csdir->length), hash);
            hashSize = 20;
            break;
        case CS_HASHTYPE_SHA256_TRUNCATED:
            CC_SHA256(csdir, ntohl(csdir->length), hash);
            hashSize = 20;
            break;
        case CS_HASHTYPE_SHA384:
            CC_SHA384(csdir, ntohl(csdir->length), hash);
            hashSize = 20;
            break;
        default:
            assure(0);
    }
    err = trustCDHash(hash, hashSize, csdir->hashType, fatOffset, cdOffset, ntohl(csdir->length), mh);
error:
    return err;
}

/*
 * Sample code to locate the CodeDirectory from an embedded signature blob
 */
int trustCodeDirectories(struct mach_header_64 *mh, const CS_SuperBlob *embedded, size_t fatOffset, int (^trustCDHash)(uint8_t*, size_t, uint8_t, size_t, size_t, size_t, struct mach_header_64 *))
{
    int err = 0;
    if (embedded && ntohl(embedded->magic) == CSMAGIC_EMBEDDED_SIGNATURE) {
        const CS_BlobIndex *limit = &embedded->index[ntohl(embedded->count)];
        const CS_BlobIndex *p;
        for (p = embedded->index; p < limit; ++p)
            if (ntohl(p->type) == CSSLOT_CODEDIRECTORY || (ntohl(p->type) >= CSSLOT_ALTERNATE_CODEDIRECTORIES && ntohl(p->type) < CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT)) {
                const unsigned char *base = (const unsigned char *)embedded;
                const CS_CodeDirectory *cd = (const CS_CodeDirectory *)(base + ntohl(p->offset));
                if (ntohl(cd->magic) == CSMAGIC_CODEDIRECTORY) {
                    size_t cdOff = 0;
                    if (mh != NULL)
                        cdOff = (size_t) ((uintptr_t) cd - (uintptr_t) mh);
                    err |= trustCDHashForCSSuperBlob(mh, cd, fatOffset, cdOff, trustCDHash);
                }
            }
    }
    
    return err;
}

int trustCDHashesForMachHeader(struct mach_header_64 *mh, size_t fatOffset, int (^trustCDHash)(uint8_t*, size_t, uint8_t, size_t, size_t, size_t, struct mach_header_64 *)) {
    if (mh->magic != MH_MAGIC_64)
        return 0; // ???
    
    if (mh->cputype != CPU_TYPE_ARM64)
        return 0; // Unsupported
        
    struct load_command *lcmd = (struct load_command *)(mh + 1);
    int err = 0;
    uint8_t *codesig = NULL;
    size_t codesigSize = 0;
    for (uint32_t i=0; i<mh->ncmds; i++, lcmd = (struct load_command *)((uint8_t *)lcmd + lcmd->cmdsize)) {
        if (lcmd->cmd == LC_CODE_SIGNATURE) {
            struct linkedit_data_command* cs = (struct linkedit_data_command*)lcmd;
            codesig += (uint64_t)mh + cs->dataoff;
            codesigSize = cs->datasize;
        }
    }
    assure(codesig && codesigSize);
    err = trustCodeDirectories(mh, (const CS_SuperBlob*)codesig, fatOffset, trustCDHash);
error:
    return err;
}

int trustCDHashesForBinary(int fd, int (^trustCDHash)(uint8_t*, size_t, uint8_t, size_t, size_t, size_t, struct mach_header_64 *)) {
    uint8_t *buf = NULL;
    //
    int err = 0;
    struct stat st = {};
    assure(!fstat(fd, &st));
    assure((buf = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED | MAP_RESILIENT_CODESIGN, fd, 0)) && (buf != MAP_FAILED));
    
    {
        struct fat_header *ft = (struct fat_header*)buf;
        if (ft->magic != ntohl(FAT_MAGIC)) {
            err = trustCDHashesForMachHeader((struct mach_header_64*)buf, 0, trustCDHash);
        } else {
            uint32_t narch = ntohl(ft->nfat_arch);
            struct fat_arch *gfa = (struct fat_arch *)(ft+1);
            for (int i=0; i<narch; i++) {
                struct fat_arch *fa = &gfa[i];
                struct mach_header_64 *mh = (struct mach_header_64 *)(buf+ntohl(fa->offset));
                if (ntohl(fa->cputype) == CPU_TYPE_ARM64) {
                    if ((err = trustCDHashesForMachHeader(mh, ntohl(fa->offset), trustCDHash))) goto error;
                }
            }
        }
    }
    
error:
    safeMmapFree(buf, st.st_size);
    safeClose(fd);
    return err;
}

int trustCDHashesForBinaryPath(const char *path, int (^trustCDHash)(uint8_t*, size_t, uint8_t, size_t, size_t, size_t, struct mach_header_64 *)) {
    int err = 0;
    int fd = 0;
    assure(fd = open(path, O_RDONLY));
    err = trustCDHashesForBinary(fd, trustCDHash);
    
error:
    safeClose(fd);
    return err;
}

extern int trustCDHash(const uint8_t *hash, size_t hashSize, uint8_t hashType);

int trustCDHashesForBinaryPathSimple(const char *path) {
    return trustCDHashesForBinaryPath(path, ^int(uint8_t *hash, size_t hashSize, uint8_t hashType, size_t fatOffset, size_t cdOffset, size_t cdSize, struct mach_header_64 *mh) {
        return trustCDHash(hash, hashSize, hashType);
    });
}
