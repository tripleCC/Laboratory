/* Copyright (c) (2013,2015-2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_internal.h"
#include "cccmac_internal.h"

int cccmac_one_shot_generate(const struct ccmode_cbc *cbc,
            size_t key_nbytes, const void *key,
            size_t data_nbytes, const void *data,
            size_t mac_nbytes, void *mac) {
    CC_ENSURE_DIT_ENABLED

    int status;
    cccmac_mode_decl(cbc, cmac);
    status=cccmac_init(cbc, cmac, key_nbytes, key);
    cc_require(status==0,errOut);
    status=cccmac_update(cmac, data_nbytes, data);
    cc_require(status==0,errOut);
    status=cccmac_final_generate(cmac, mac_nbytes, mac);
    cc_require(status==0,errOut);
errOut:
    cccmac_mode_clear(cbc, cmac);
    return status;

}

int cccmac_one_shot_verify(const struct ccmode_cbc *cbc,
                        size_t key_nbytes, const void *key,
                        size_t data_nbytes, const void *data,
                        size_t mac_nbytes, const void *mac) {
    CC_ENSURE_DIT_ENABLED

    int status;
    cccmac_mode_decl(cbc, cmac);
    status=cccmac_init(cbc, cmac, key_nbytes, key);
    cc_require(status==0,errOut);
    status=cccmac_update(cmac, data_nbytes, data);
    cc_require(status==0,errOut);
    status=cccmac_final_verify(cmac, mac_nbytes, mac);
    cc_require(status==0,errOut);
errOut:
    cccmac_mode_clear(cbc, cmac);
    return status;
    
}
