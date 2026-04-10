#include "hal.h"
#include "api.h"
#include <stdint.h>

uint8_t g_sk[CRYPTO_SECRETKEYBYTES];
uint8_t g_pk[CRYPTO_PUBLICKEYBYTES];
uint8_t g_ct[CRYPTO_CIPHERTEXTBYTES];
uint8_t g_ss[CRYPTO_BYTES];

volatile uint8_t g_keypair_done = 0;
volatile uint32_t g_pk_check = 0;
volatile uint32_t g_sk_check = 0;

// static uint32_t simple_sum(const uint8_t *buf, uint32_t len)
// {
//     uint32_t s = 0;
//     for (uint32_t i = 0; i < len; i++) {
//         s += buf[i];
//     }
//     return s;
// }

int main(void)
{
    trigger_setup();
    init_uart();
    crypto_kem_keypair(g_pk, g_sk);
    // g_pk_check = simple_sum(g_pk, CRYPTO_PUBLICKEYBYTES);
    // g_sk_check = simple_sum(g_sk, CRYPTO_SECRETKEYBYTES);
    g_keypair_done = 1;
    // trigger_high();
    //crypto_kem_enc(g_ct, g_ss, g_pk);
    crypto_kem_dec(g_ss, g_ct, g_sk);
    // trigger_low();

    while (1) {
    }
}