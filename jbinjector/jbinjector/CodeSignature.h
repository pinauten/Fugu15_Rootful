//
//  CodeSignature.h
//  mmapTest
//
//  Created by Linus Henze on 2023-03-13.
//

#ifndef CodeSignature_h
#define CodeSignature_h

#include <stdio.h>
#include <stdint.h>
#include <mach-o/loader.h>

#pragma mark codehashes

/*
 * Magic numbers used by Code Signing
 */
enum {
    CSMAGIC_REQUIREMENT    = 0xfade0c00,        /* single Requirement blob */
    CSMAGIC_REQUIREMENTS = 0xfade0c01,        /* Requirements vector (internal requirements) */
    CSMAGIC_CODEDIRECTORY = 0xfade0c02,        /* CodeDirectory blob */
    CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0, /* embedded form of signature data */
    CSMAGIC_DETACHED_SIGNATURE = 0xfade0cc1, /* multi-arch collection of embedded signatures */
};

enum {
    CS_PAGE_SIZE_4K                = 4096,
    CS_PAGE_SIZE_16K               = 16384,

    CS_HASHTYPE_SHA1              = 1,
    CS_HASHTYPE_SHA256            = 2,
    CS_HASHTYPE_SHA256_TRUNCATED  = 3,
    CS_HASHTYPE_SHA384 = 4,

    CS_HASH_SIZE_SHA1             = 20,
    CS_HASH_SIZE_SHA256           = 32,
    CS_HASH_SIZE_SHA256_TRUNCATED = 20,

    CSSLOT_CODEDIRECTORY                 = 0,
    CSSLOT_INFOSLOT                      = 1,
    CSSLOT_REQUIREMENTS                  = 2,
    CSSLOT_RESOURCEDIR                   = 3,
    CSSLOT_APPLICATION                   = 4,
    CSSLOT_ENTITLEMENTS                  = 5,
    CSSLOT_ALTERNATE_CODEDIRECTORIES     = 0x1000,
    CSSLOT_ALTERNATE_CODEDIRECTORY_MAX   = 5,
    CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT =
    CSSLOT_ALTERNATE_CODEDIRECTORIES + CSSLOT_ALTERNATE_CODEDIRECTORY_MAX,
    CSSLOT_CMS_SIGNATURE                 = 0x10000,
//    kSecCodeSignatureAdhoc      = 2
};


/*
 * Structure of an embedded-signature SuperBlob
 */
typedef struct __BlobIndex {
    uint32_t type;                  /* type of entry */
    uint32_t offset;                /* offset of entry */
} CS_BlobIndex;

typedef struct __SuperBlob {
    uint32_t magic;                 /* magic number */
    uint32_t length;                /* total length of SuperBlob */
    uint32_t count;                 /* number of index entries following */
    CS_BlobIndex index[];           /* (count) entries */
    /* followed by Blobs in no particular order as indicated by offsets in index */
} CS_SuperBlob;


/*
 * C form of a CodeDirectory.
 */
typedef struct __CodeDirectory {
    uint32_t magic;                 /* magic number (CSMAGIC_CODEDIRECTORY) */
    uint32_t length;                /* total length of CodeDirectory blob */
    uint32_t version;               /* compatibility version */
    uint32_t flags;                 /* setup and mode flags */
    uint32_t hashOffset;            /* offset of hash slot element at index zero */
    uint32_t identOffset;           /* offset of identifier string */
    uint32_t nSpecialSlots;         /* number of special hash slots */
    uint32_t nCodeSlots;            /* number of ordinary (code) hash slots */
    uint32_t codeLimit;             /* limit to main image signature range */
    uint8_t  hashSize;              /* size of each hash in bytes */
    uint8_t  hashType;              /* type of hash (cdHashType* constants) */
    uint8_t  spare1;                /* unused (must be zero) */
    uint8_t  pageSize;              /* log2(page size in bytes); 0 => infinite */
    uint32_t spare2;                /* unused (must be zero) */
    /* followed by dynamic content as located by offset fields above */
} CS_CodeDirectory;

int trustCDHashesForBinary(int fd, int (^trustCDHash)(uint8_t*, size_t, uint8_t, size_t, size_t, size_t, struct mach_header_64 *));
int trustCDHashesForBinaryPath(const char *path, int (^trustCDHash)(uint8_t*, size_t, uint8_t, size_t, size_t, size_t, struct mach_header_64 *));
int trustCodeDirectories(struct mach_header_64 *mh, const CS_SuperBlob *embedded, size_t fatOffset, int (^trustCDHash)(uint8_t*, size_t, uint8_t, size_t, size_t, size_t, struct mach_header_64 *));
int trustCDHashesForBinaryPathSimple(const char *path);

#endif /* CodeSignature_h */
