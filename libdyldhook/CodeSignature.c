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

#include "sha256.h"

#define safeClose(fd) do{if ((fd) != -1){close(fd); fd = -1;}}while(0)
#define safeFree(buf) do{if ((buf)){free(buf); buf = NULL;}}while(0)
#define safeMmapFree(buf, size) do{if ((buf) && (buf) != MAP_FAILED){munmap(buf, size); buf = NULL;}}while(0)
#define assure(cond) do {if (!(cond)){err = __LINE__; goto error;}}while(0)

extern int trustCDHash(const uint8_t *hash, size_t hashSize, uint8_t hashType);

#pragma mark parsing
int trustCDHashForCSSuperBlob(struct mach_header_64 *mh, const CS_CodeDirectory *csdir, size_t fatOffset, size_t cdOffset) {
    int err = 0;
    uint8_t hash[SHA256_BLOCK_SIZE];
    size_t hashSize = 0;
    switch (csdir->hashType) {
        case CS_HASHTYPE_SHA256: {
            SHA256_CTX ctx;
            sha256_init(&ctx);
            sha256_update(&ctx, (void*) csdir, ntohl(csdir->length));
            sha256_final(&ctx, hash);
            hashSize = 20;
            break;
        }
        default:
            // Other hashes are not supported anyway
            assure(0);
    }
    err = trustCDHash(hash, hashSize, csdir->hashType);
error:
    return err;
}

/*
 * Sample code to locate the CodeDirectory from an embedded signature blob
 */
int trustCodeDirectories(struct mach_header_64 *mh, const CS_SuperBlob *embedded, size_t fatOffset)
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
                    err |= trustCDHashForCSSuperBlob(mh, cd, fatOffset, cdOff);
                }
            }
    }
    
    return err;
}
