/**
 * Copyright (c) 2017 - 2020, Nordic Semiconductor ASA
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form, except as embedded into a Nordic
 *    Semiconductor ASA integrated circuit in a product or a software update for
 *    such product, must reproduce the above copyright notice, this list of
 *    conditions and the following disclaimer in the documentation and/or other
 *    materials provided with the distribution.
 *
 * 3. Neither the name of Nordic Semiconductor ASA nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * 4. This software, with or without modification, must only be used with a
 *    Nordic Semiconductor ASA integrated circuit.
 *
 * 5. Any software provided in binary form under this license must not be reverse
 *    engineered, decompiled, modified and/or disassembled.
 *
 * THIS SOFTWARE IS PROVIDED BY NORDIC SEMICONDUCTOR ASA "AS IS" AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY, NONINFRINGEMENT, AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL NORDIC SEMICONDUCTOR ASA OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#ifdef DX_LINUX_PLATFORM /*for linux platform only !!*/
#include <pthread.h>
#endif

#include "ssi_pal_types.h"
#include "ssi_pal_mem.h"
#include "sns_silib.h"
#include "ssi_aes.h"
#include "crys_aesccm.h"
#include "integration_test_plat_defs.h"
#include "integration_test_ssi_data.h"
#include "integration_test_ssi_defs.h"
#include "ssi_util_key_derivation.h"
#include "ssi_util_error.h"


/*Globals*/
extern CRYS_RND_State_t *rndState_ptr;
extern CRYS_RND_WorkBuff_t *rndWorkBuff_ptr;

static bool is_kdr_set(void)
{
    if ((NRF_CC_HOST_RGF->HOST_IOT_KDR0 == 1) &&
        (NRF_CC_HOST_RGF->HOST_IOT_KDR0 == 1) &&
        (NRF_CC_HOST_RGF->HOST_IOT_KDR0 == 1) &&
        (NRF_CC_HOST_RGF->HOST_IOT_KDR0 == 1))
    {
        return true;
    }
}

static void set_lcs_secure(void)
{
    /* Set life-cycle state to Secure (write once per reset) */
    NRF_CC_HOST_RGF->HOST_IOT_LCS = CC_HOST_RGF_HOST_IOT_LCS_LCS_Secure << CC_HOST_RGF_HOST_IOT_LCS_LCS_Pos;

    /* Needed in order to delay until register is written before continuing to verify (next step) */
    NRF_CC_HOST_RGF->HOST_IOT_LCS;

    /* Verify CLS set to Secure */
    if (((NRF_CC_HOST_RGF->HOST_IOT_LCS & CC_HOST_RGF_HOST_IOT_LCS_LCS_IS_VALID_Msk) >> CC_HOST_RGF_HOST_IOT_LCS_LCS_IS_VALID_Pos) != CC_HOST_RGF_HOST_IOT_LCS_LCS_IS_VALID_Valid)
    {

        INTEG_TEST_PRINT("LCS is invalid! \n");
    }

    if (((NRF_CC_HOST_RGF->HOST_IOT_LCS & CC_HOST_RGF_HOST_IOT_LCS_LCS_Msk) >> CC_HOST_RGF_HOST_IOT_LCS_LCS_Pos) != CC_HOST_RGF_HOST_IOT_LCS_LCS_Secure)
    {

        INTEG_TEST_PRINT("LCS not secure! \n");
    }
}


static void set_kdr(void)
{
    /* Enable the CC310 HW (needed to set KDR) */
    NRF_CRYPTOCELL->ENABLE = 1;

    /*
    The following tasks could be done here to achieve a higher degree of trust, but are not demonstrated:

    * Secure configuration area should be authenticated and decrypted using CRYPTOCELL KPRTL key.
      See Example: Data at rest for more information.

    * After reading the secure configuration area from flash to SRAM, and successfully
      authenticating and decrypting its content, KPRTL key must be locked from use until next reset
      by writing register CC_HOST_RGF->HOST_IOT_KPRTL_LOCK
    */

    /* Set Life cycle state (LCS) to Secure */
    set_lcs_secure();

    /* Set KDR */
    NRF_CC_HOST_RGF->HOST_IOT_KDR0 = 0xBADEBA11;
    NRF_CC_HOST_RGF->HOST_IOT_KDR1 = 0xBADEBA11;
    NRF_CC_HOST_RGF->HOST_IOT_KDR2 = 0xBADEBA11;
    NRF_CC_HOST_RGF->HOST_IOT_KDR3 = 0xBADEBA11;

    /* Verify that KDR is set */
    if (!is_kdr_set())
    {
        INTEG_TEST_PRINT("KDR not set correctly\n");
    }

    /* Disable the CC310 HW */
    //NRF_CRYPTOCELL->ENABLE = 0;
}


static void key_derivation(void)
{
    SaSiUtilError_t err;

    /* Derive keys according to NIST SP800-108, where
       AES-CMAC is used as pseudo-random function */

    /* Key labels, max allowed size of 64 bytes */
    const uint8_t key_label[11] = {"KEY ENC KEY"};

    /* Context for above key labels, max allowed size of 64 bytes.
       This example use the device ID which is unique for each IC. */
    const uint32_t key_context[2] = {NRF_FICR->DEVICEID[0],
                                     NRF_FICR->DEVICEID[1]};

    /* Array in SRAM for holding derived key value once complete */
    uint8_t secret_key[16] = {0};

    /* Derive external storage key */
    err = SaSi_UtilKeyDerivation(SASI_UTIL_ROOT_KEY,
                                 NULL,
                                 key_label,
                                 sizeof(key_label),
                                 (const uint8_t *)key_context,
                                 sizeof(key_context),
                                 secret_key,
                                 sizeof(secret_key));
    if (err != SASI_UTIL_OK)
    {  
        INTEG_TEST_PRINT("Error wile deriving key. Err code: %u\n", err);
    }
    else
    {
        INTEG_TEST_PRINT("Successfully derived key \n");
    }

    /* Do crypto operation with the key here, now just dumping the key instead... */


    /* Secret_key no longer needed, so we clear the memory holding the key */
    SaSi_PalMemSetZero(&secret_key, sizeof(secret_key));
}


int main(void)
{
    int ret = 0;

    /* Setup logging etc */
    ret = integration_tests_setup();
    if (ret != 0)
    {
        INTEG_TEST_PRINT("integration_tests_setup failed\n");
        return ret;
    }

    /* Set root key and set secure mode. This would typically be done in the bootloader and the page
       holding the root key should be protected using ACL */
    set_kdr();

    /* Get the derived key. This would typically be done in the application where the key is needed
       for crypto operations. */
    key_derivation();

    return ret;
}
