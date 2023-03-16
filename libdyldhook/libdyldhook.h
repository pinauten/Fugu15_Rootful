#ifndef libdyldhook_h
#define libdyldhook_h

#include <stdint.h>
#include <mach/mach.h>

#define FUFUGUGU_MSG_MAGIC 0x4675467547754775

#define FUFUGUGU_ACTION_CSDEBUG 0
#define FUFUGUGU_ACTION_TRUST   1

struct FuFuGuGuMsg {
    mach_msg_header_t hdr;
    uint64_t          magic;
    uint64_t          action;
};

struct FuFuGuGuMsgCSDebug {
    struct FuFuGuGuMsg base;
    uint64_t           pid;
    uint64_t           forceDisablePAC;
};

struct FuFuGuGuMsgTrust {
    struct FuFuGuGuMsg base;
    uint64_t           hashType;
    uint64_t           hashLen;
    uint8_t            hash[0];
};

struct FuFuGuGuMsgTrust20 {
    struct FuFuGuGuMsg base;
    uint64_t           hashType;
    uint64_t           hashLen;
    uint8_t            hash[20];
};

struct FuFuGuGuMsgReply {
    mach_msg_header_t hdr;
    uint64_t          magic;
    uint64_t          action;
    uint64_t          status;
};

struct FuFuGuGuMsgReplyCSDebug {
    struct FuFuGuGuMsgReply base;
    int pacDisabled;
};

#endif /* libdyldhook_h */
