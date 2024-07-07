/* Copyright (c) (2015-2017,2019-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_debug.h"
#include <corecrypto/ccsha2.h>
#include <corecrypto/cchmac.h>
#include "cc_internal.h"

#if !CC_USE_L4
#include <sys/errno.h>
#include <sys/mman.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#endif

#if !CC_KERNEL && !CC_USE_L4
#include <unistd.h>
#endif

#if !CC_USE_L4
#include <mach-o/loader.h>
#else
#include <libSEPOS.h>
#endif

#if CC_KERNEL
const uint64_t cc_dylib_in_cache = MH_DYLIB_IN_CACHE;
#else
const uint64_t cc_dylib_in_cache = 0;
#endif

#include "fipspost.h"
#include "fipspost_priv.h"

#include "fipspost_get_hmac.h"

static const struct segment_command* segment_advance(
        const struct segment_command* peek_seg_cmd);

/* --------------------------------------------------------------------------
   Advance the segment to the next segment_command. Because the 'cmdsize'
   member is at the same location for both the segment_command and the
   segment_command_64 structure, it's not necessary to cast the struct.
 -------------------------------------------------------------------------- */
static const struct segment_command* segment_advance(
        const struct segment_command* peek_seg_cmd)
{
    return (const struct segment_command*)(((const unsigned char*)peek_seg_cmd) +
            peek_seg_cmd->cmdsize);
}

/*
 * This function is used by both the iOS and OSX integrity checking code.
 * It handles reading the mach_header of the executable and creating the HMAC
 * of the __TEXT, __TEXT segment
 */
int fipspost_get_hmac(const struct mach_header* pmach_header,
        unsigned char* result_buf, size_t max_offset)
{
    int result = 0; // Set to zero for sucesses until it all works
    const uint8_t *end_region = NULL;
    const struct load_command* load_cmd = NULL;
    const struct segment_command* peek_seg_cmd = NULL;
    uint32_t num_load_commands = 0;
    uint32_t load_idx, sect_idx, num_sect;
    const unsigned char* sect_data;

    const struct ccdigest_info* di = ccsha256_di();
    unsigned char hmac_buffer[CCSHA256_OUTPUT_SIZE];
    unsigned char hmac_key = 0;
    int hash_created = 0;

    /*
     * Establish the maximum extent of the valid memory region to work with, if
     * supplied.
     */
    if (max_offset != 0) {
        /* Protect against the max_offset being large enough to place the end_region at 0. */
        uintptr_t hdr_offset = 0;
        if (cc_add_overflow((uintptr_t)pmach_header, max_offset, &hdr_offset)) {
            return CCPOST_GENERIC_FAILURE;
        }
        end_region = (const uint8_t *)hdr_offset;
    }

    /* There must be at least enough space for the first two headers. */
    if (max_offset > 0 && max_offset <
            (sizeof(struct mach_header_64) + sizeof(struct load_command))) {
        return CCPOST_GENERIC_FAILURE;
    }

    if (pmach_header->magic == MH_MAGIC_64) {
        const struct mach_header_64* pmach64_header =
                (const struct mach_header_64*)pmach_header;
        num_load_commands = pmach64_header->ncmds;
        load_cmd = (const struct load_command*)(pmach64_header + 1);
    } else if (pmach_header->magic == MH_MAGIC) {
        num_load_commands = pmach_header->ncmds;
        load_cmd = (const struct load_command*)(pmach_header + 1);
    }

    if (NULL == load_cmd) {
        return CCPOST_LIBRARY_ERROR;
    }

    /* Setup the buffer to receive the HMAC. */
    memset(hmac_buffer, 0, sizeof(hmac_buffer));
    cchmac_ctx_decl(di->state_size, di->block_size, ctx);
    cchmac_init(di, ctx, 1, &hmac_key);

    peek_seg_cmd = (const struct segment_command*)load_cmd;

    /*
     * If the supplied ptr is after the available end region (when set), or
     * ever before the supplied pmach_header (which should always be earlier in
     * memory than any of the executable pages), then return failure.
     */
#define CHECK_REGION(ptr) do {                                                      \
        if ((end_region != NULL && (const uint8_t *)((ptr) + 1) > end_region) ||    \
                ((const uint8_t *)(ptr)) < (const uint8_t *)pmach_header) {         \
            return CCPOST_GENERIC_FAILURE;                                           \
        }                                                                           \
    } while (0);

    uint64_t mach_header_vmaddr = 0;

    /*
     * Iterate through all of the load commands and identify the ones relating
     * to the TEXT segments that must be hashed into the HMAC.
     */
    for (load_idx = 0; load_idx < num_load_commands; load_idx++,
            peek_seg_cmd = segment_advance(peek_seg_cmd)) {
        CHECK_REGION(peek_seg_cmd);

        /*
         * Both 64-bit and 32-bit segment_command objects contain the 'segname'
         * in the same place.
         */
        if (strncmp("__TEXT", peek_seg_cmd->segname, strlen("__TEXT")) &&
            strncmp("__TEXT_EXEC", peek_seg_cmd->segname, strlen("__TEXT_EXEC"))) {
            continue;
        }

        /* Identify the sub-segment that contains the TEXT data. */
        if (LC_SEGMENT_64 == load_cmd->cmd) {
            /* Almost identical to the the 32-bit section below. */
            const struct segment_command_64* seg_cmd;
            const struct section_64* sect;

            seg_cmd = (const struct segment_command_64*)peek_seg_cmd;
            sect = (const struct section_64*)(seg_cmd + 1);
            num_sect = (unsigned int)seg_cmd->nsects;

            CHECK_REGION(seg_cmd);

            if (cc_dylib_in_cache && strcmp("__TEXT", peek_seg_cmd->segname) == 0) {
                mach_header_vmaddr = seg_cmd->vmaddr;
            }

            for (sect_idx = 0; sect_idx < num_sect; sect_idx++, sect++) {
                CHECK_REGION(sect);
                /* Check the section name and the segment name. */
                if (strcmp(sect->sectname, "__text") ||
                        (strcmp(sect->segname, "__TEXT") && strcmp(sect->segname, "__TEXT_EXEC"))) {
                    continue;
                }

                /* Only match one section; calculate the hash from it and return. */
                if (pmach_header->flags & cc_dylib_in_cache) {
                    /* If we are in a kernel collection, the sect->address already points to the
                     * location of the data.  The section->offset field is not usable as it is
                     * an offset from the kernel collection file, not the mach header we have
                     * access to here
                     */
                    intptr_t slide = (intptr_t)((uint64_t)pmach_header - mach_header_vmaddr);
                    sect_data = (const unsigned char*)(uintptr_t)sect->addr + slide;
                } else {
                    sect_data = (const unsigned char*)pmach_header + sect->offset;
                }

                CHECK_REGION(sect_data + sect->size - 1);
                cchmac_update(di, ctx, (size_t)sect->size, sect_data);
                hash_created = 1;
                break;
            }
            if (hash_created) {
                /* The text text section was found and processed. */
                break;
            }
        } else if (LC_SEGMENT == load_cmd->cmd) {
            /* Almost identical to the the 64-bit section above. */
            const struct segment_command* seg_cmd = NULL;
            const struct section* sect;

            seg_cmd = (const struct segment_command*)peek_seg_cmd;
            num_sect = (unsigned int)seg_cmd->nsects;
            sect = (const struct section*)(seg_cmd + 1);

            CHECK_REGION(seg_cmd);

            if (cc_dylib_in_cache && strcmp("__TEXT", peek_seg_cmd->segname) == 0) {
                mach_header_vmaddr = seg_cmd->vmaddr;
            }

            for (sect_idx = 0; sect_idx < num_sect; sect_idx++, sect++) {
                CHECK_REGION(sect);
                /* Check the section name and the segment name. */
                if (strcmp(sect->sectname, "__text") ||
                        (strcmp(sect->segname, "__TEXT") && strcmp(sect->segname, "__TEXT_EXEC"))) {
                    continue;
                }

                /* Only match one section; calculate the hash from it and return. */
                if (pmach_header->flags & cc_dylib_in_cache) {
                    /* If we are in a kernel collection, the sect->address already points to the
                     * location of the data.  The section->offset field is not usable as it is
                     * an offset from the kernel collection file, not the mach header we have
                     * access to here
                     */
                    intptr_t slide = (intptr_t)((uint64_t)pmach_header - mach_header_vmaddr);
                    sect_data = (const unsigned char*)(uintptr_t)sect->addr + slide;
                } else {
                    sect_data = (const unsigned char*)pmach_header + sect->offset;
                }

                CHECK_REGION(sect_data + sect->size - 1);
                cchmac_update(di, ctx, (size_t)sect->size, sect_data);
                hash_created = 1;
                break;
            }
            if (hash_created) {
                /* The text text section was found and processed. */
                break;
            }
        }
    }
#undef CHECK_REGION

    if (hash_created) {
        cchmac_final(di, ctx, hmac_buffer);
        memcpy(result_buf, hmac_buffer, sizeof(hmac_buffer));
    } else {
        failf("could not create the hash");
        result = CCPOST_GENERIC_FAILURE;
    }

    return result;
}
