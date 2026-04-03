/*
    This file is part of the ChipWhisperer Example Targets
    Copyright (C) 2021 NewAE Technology Inc.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdint.h>
#include <stdlib.h>

#if HAL_TYPE != HAL_k82f || USE_TRUSTED_CRYPTO != 1
#include "uECC.c"
#include "uECC_vli.h"
#include "types.h"
#endif

#include "hal.h"
#include "simpleserial.h"

#if HAL_TYPE == HAL_k82f
#include "MK82F25615.h"
#include "core_cm4.h"
#include "fsl_ltc.h"
#endif

#if HAL_TYPE == HAL_stm32f3
#include "stm32f303x8.h"
#include "core_cm4.h"
#endif

#include "arm_etm.h"

// At the moment, only 256-bit curves are supported
static const uint16_t size_curve = 32;

uint8_t pcsamp_enable;

uint8_t setreg(uint8_t* x, uint8_t len)
{
        uint32_t val;
        val = x[4] + (x[3] << 8) + (x[2] << 16) + (x[1] << 24);
// Must match capture/trace/TraceWhisperer.py:
//0:  DWT->CTRL
//1:  DWT->COMP0
//2:  DWT->COMP1
//3:  ETM->CR
//4:  ETM->TESSEICR
//5:  ETM->TEEVR
//6:  ETM->TECR1
//7:  ETM->TRACEIDR
//8:  TPI->ACPR
//9:  TPI->SPPR
//10: TPI->FFCR
//11: TPI->CSPSR
//12: ITM->TCR
        if       (x[0] == 0)    {DWT->CTRL = val;}
        else if  (x[0] == 1)    {DWT->COMP0 = val;}
        else if  (x[0] == 2)    {DWT->COMP1 = val;}
        else if  (x[0] == 3)    {ETM_SetupMode(); ETM->CR = val; ETM_TraceMode();}
        else if  (x[0] == 4)    {ETM_SetupMode(); ETM->TESSEICR = val; ETM_TraceMode();}
        else if  (x[0] == 5)    {ETM_SetupMode(); ETM->TEEVR    = val; ETM_TraceMode();}
        else if  (x[0] == 6)    {ETM_SetupMode(); ETM->TECR1    = val; ETM_TraceMode();}
        else if  (x[0] == 7)    {ETM_SetupMode(); ETM->TRACEIDR = val; ETM_TraceMode();}
        else if  (x[0] == 8)    {TPI->ACPR    = val;}
        else if  (x[0] == 9)    {TPI->SPPR    = val;}
        else if  (x[0] == 10)   {TPI->FFCR    = val;}
        else if  (x[0] == 11)   {TPI->CSPSR   = val;}
        else if  (x[0] == 12)   {ITM->TCR     = val;}

	return 0x00;
}


uint8_t getreg(uint8_t* x, uint8_t len)
{
        uint32_t val;
        if       (x[0] == 0)    {val = DWT->CTRL;}
        else if  (x[0] == 1)    {val = DWT->COMP0;}
        else if  (x[0] == 2)    {val = DWT->COMP1 ;}
        else if  (x[0] == 3)    {val = ETM->CR;}
        else if  (x[0] == 4)    {val = ETM->TESSEICR;}
        else if  (x[0] == 5)    {val = ETM->TEEVR;}
        else if  (x[0] == 6)    {val = ETM->TECR1;}
        else if  (x[0] == 7)    {val = ETM->TRACEIDR;}
        else if  (x[0] == 8)    {val = TPI->ACPR;}
        else if  (x[0] == 9)    {val = TPI->SPPR;}
        else if  (x[0] == 10)   {val = TPI->FFCR;}
        else if  (x[0] == 11)   {val = TPI->CSPSR;}
        else if  (x[0] == 12)   {val = ITM->TCR;}
        else {val = 0;}

        x[3] = val & 0xff;
        x[2] = (val >> 8) & 0xff;
        x[1] = (val >> 16) & 0xff;
        x[0] = (val >> 24) & 0xff;
	simpleserial_put('r', 4, x);
	return 0x00;
}

void enable_trace(void)
{
    // Enable SWO pin (not required on K82)
    #if HAL_TYPE == HAL_stm32f3
       DBGMCU->CR |= DBGMCU_CR_TRACE_IOEN_Msk;
    #endif

    // Configure TPI
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk; // Enable access to registers
    TPI->ACPR = 0; // SWO trace baud rate = cpu clock / (ACPR+1)

    #if HAL_TYPE == HAL_stm32f3
       TPI->SPPR = 2; // default to SWO with NRZ encoding
       //TPI->SPPR = 1; // SWO with Manchester encoding
    #else
       TPI->SPPR = 0; // default to parallel trace mode
    #endif

    TPI->FFCR = 0x102; // packet framing enabled
    //TPI->FFCR = 0x100; // no framing: for DWT/ITM only, no ETM
    TPI->CSPSR =0x00000008; // 4 trace lanes

    // Configure ITM:
    ITM->LAR = 0xC5ACCE55;
    ITM->TCR = (1 << ITM_TCR_TraceBusID_Pos) // Trace bus ID for TPIU
             | (1 << ITM_TCR_DWTENA_Pos) // Enable events from DWT
             | (0 << ITM_TCR_SYNCENA_Pos) // Disable sync packets!
             | (1 << ITM_TCR_ITMENA_Pos); // Main enable for ITM
    ITM->TER = 0xFFFFFFFF; // Enable all stimulus ports
    ITM->TPR = 0x00000000; // allow unpriviledged access

    // Configure DWT:
    DWT->CTRL = (0xf << DWT_CTRL_POSTINIT_Pos);// countdown counter for PC sampling, must be written
                                               // before enabling PC sampling
    DWT->CTRL |=(1 << DWT_CTRL_CYCTAP_Pos)     // Prescaler for PC sampling: 0 = x32, 1 = x512
              | (8 << DWT_CTRL_POSTPRESET_Pos) // PC sampling postscaler
              | (0 << DWT_CTRL_PCSAMPLENA_Pos) // disable PC sampling
              | (1 << DWT_CTRL_SYNCTAP_Pos)    // sync packets every 16M cycles
              | (0 << DWT_CTRL_EXCTRCENA_Pos)  // disable exception trace
              | (1 << DWT_CTRL_CYCCNTENA_Pos); // enable cycle counter

    // Configure DWT PC comparator 0:
    DWT->COMP0 = 0x00001d60; // AES subbytes
    DWT->MASK0 = 0;
    DWT->FUNCTION0 = (0 << DWT_FUNCTION_DATAVMATCH_Pos) // address match
                   | (0 << DWT_FUNCTION_CYCMATCH_Pos)
                   | (0 << DWT_FUNCTION_EMITRANGE_Pos)
                   | (8 << DWT_FUNCTION_FUNCTION_Pos); // Iaddr CMPMATCH event

    // Configure DWT PC comparator 1:
    DWT->COMP1 = 0x00001d68; // AES mixcolumns
    DWT->MASK1 = 0;
    DWT->FUNCTION1 = (0 << DWT_FUNCTION_DATAVMATCH_Pos) // address match
                   | (0 << DWT_FUNCTION_CYCMATCH_Pos)
                   | (0 << DWT_FUNCTION_EMITRANGE_Pos)
                   | (8 << DWT_FUNCTION_FUNCTION_Pos); // Iaddr CMPMATCH event


    // Configure ETM:
    ETM->LAR = 0xC5ACCE55;
    ETM_SetupMode();
    ETM->CR = ETM_CR_ETMEN; // Enable ETM output port
    ETM->TRACEIDR = 1; // Trace bus ID for TPIU
    ETM->FFLR = 0; // Stall processor when FIFO is full
    ETM->TEEVR = 0x000150a0;    // EmbeddedICE comparator 0 or 1 (DWT->COMP0 or DWT->COMP1)
    //ETM->TEEVR = 0x00000020;    // EmbeddedICE comparator 0 only
    //ETM->TEEVR = 0x00000021;    // EmbeddedICE comparator 1 only
    ETM->TESSEICR = 0xf; // set EmbeddedICE watchpoint 0 as a TraceEnable start resource.
    ETM->TECR1 = 0; // tracing is unaffected by the trace start/stop logic
    ETM_TraceMode();
}

uint8_t set_pcsample_params(uint8_t* x, uint8_t len)
{
    uint8_t postinit;
    uint8_t postreset;
    uint8_t cyctap;
    pcsamp_enable = x[0] & 1;
    cyctap = x[1] & 1;
    postinit  = x[2] & 0xf;
    postreset = x[3] & 0xf;

    // must clear everything before updating postinit field:
    DWT->CTRL = 0;
    // then update postinit:
    DWT->CTRL = (postinit << DWT_CTRL_POSTINIT_Pos);
    // then update the reset, but don't turn on PC sampling yet;
    // that will be handled in trigger_high_pcsamp
    DWT->CTRL = (cyctap << DWT_CTRL_CYCTAP_Pos)
              | (postreset << DWT_CTRL_POSTPRESET_Pos)
              | (postinit << DWT_CTRL_POSTINIT_Pos)
              | (1 << DWT_CTRL_SYNCTAP_Pos)
              | (1 << DWT_CTRL_CYCCNTENA_Pos);
    simpleserial_put('r', 4, x);
    return 0x00;
}


// in order for PC sample packets to be easily parsed, PC sampling must
// begin *after* we start capturing trace data
void trigger_high_pcsamp(void)
{
    if (pcsamp_enable == 1)
    {
        DWT->CTRL |= (1 << DWT_CTRL_PCSAMPLENA_Pos); // enable PC sampling
    }
    trigger_high();
}


void trigger_low_pcsamp(void)
{
    trigger_low();
    DWT->CTRL &= ~(1 << DWT_CTRL_PCSAMPLENA_Pos); // disable PC sampling
}



void print(const char *ptr)
{
   while (*ptr != (char)0) {
      putch(*ptr);
      ptr++;
   }
}

#if HAL_TYPE == HAL_k82f && USE_TRUSTED_CRYPTO == 1

#define ROUND_BEFORE_RESEED 50000
#define ECC_ARRAY_LENGTH 80

// Curve parameters. Defaults to NIST secp256r1 at boot.
uint8_t curve_p[ECC_ARRAY_LENGTH] = {0};
uint8_t curve_a[ECC_ARRAY_LENGTH] = {0};
uint8_t curve_b[ECC_ARRAY_LENGTH] = {0};
uint8_t curve_gen_x[ECC_ARRAY_LENGTH] = {0};
uint8_t curve_gen_y[ECC_ARRAY_LENGTH] = {0};
ltc_pkha_ecc_point_t curve_gen_point = {curve_gen_x, curve_gen_y};

uint8_t fp_scalar[ECC_ARRAY_LENGTH] = {0};

uint8_t curve_p_x[ECC_ARRAY_LENGTH] = {0};
uint8_t curve_p_y[ECC_ARRAY_LENGTH] = {0};
ltc_pkha_ecc_point_t curve_p_point = {curve_p_x, curve_p_y};

uint8_t curve_h_x[ECC_ARRAY_LENGTH] = {0};
uint8_t curve_h_y[ECC_ARRAY_LENGTH] = {0};
ltc_pkha_ecc_point_t curve_h_point = {curve_h_x, curve_h_y};

uint8_t curve_out_x[ECC_ARRAY_LENGTH] = {0};
uint8_t curve_out_y[ECC_ARRAY_LENGTH] = {0};
ltc_pkha_ecc_point_t curve_output_point = {curve_out_x, curve_out_y};


uint8_t set_a(uint8_t* a, uint8_t len)
{
   if (len != size_curve) {
      return 0x01;
   }

   for (int i = 0; i < size_curve; i++) {
      curve_a[size_curve - 1 - i] = a[i];
   }
   return 0x00;
}


uint8_t set_b(uint8_t* b, uint8_t len)
{
   if (len != size_curve) {
      return 0x01;
   }

   for (int i = 0; i < size_curve; i++) {
      curve_b[size_curve - 1 - i] = b[i];
   }
   return 0x00;
}


uint8_t set_p(uint8_t* p, uint8_t len) {
   if (len != size_curve) {
      return 0x01;
   }

   for (int i = 0; i < size_curve; i++) {
      curve_p[size_curve - 1 - i] = p[i];
   }
   return 0x00;
}


uint8_t set_gx(uint8_t* x, uint8_t len)
{
   for (int i = 0; i < size_curve; i++) {
      curve_gen_x[size_curve - 1 - i] = x[i];
   }
   return 0x00;
}


uint8_t set_gy(uint8_t* y, uint8_t len)
{
   for (int i = 0; i < size_curve; i++) {
      curve_gen_y[size_curve - 1 - i] = y[i];
   }
   return 0x00;
}


uint8_t set_px(uint8_t* x, uint8_t len)
{
   for (int i = 0; i < size_curve; i++) {
      curve_p_x[size_curve - 1 - i] = x[i];
   }
   return 0x00;
}


uint8_t set_py(uint8_t* y, uint8_t len)
{
   for (int i = 0; i < size_curve; i++) {
      curve_p_y[size_curve - 1 - i] = y[i];
   }
   return 0x00;
}


uint8_t set_hx(uint8_t* x, uint8_t len)
{
   for (int i = 0; i < size_curve; i++) {
      curve_h_x[size_curve - 1 - i] = x[i];
   }
   return 0x00;
}


uint8_t set_hy(uint8_t* y, uint8_t len)
{
   for (int i = 0; i < size_curve; i++) {
      curve_h_y[size_curve - 1 - i] = y[i];
   }
   return 0x00;
}


uint8_t get_qx(uint8_t* x, uint8_t len)
{
   for (int i = 0; i < size_curve; i++) {
      x[i] = curve_out_x[size_curve - 1 - i];
   }
   simpleserial_put('r', size_curve, x);
   return 0x00;
}


uint8_t get_qy(uint8_t* y, uint8_t len)
{
   for (int i = 0; i < size_curve; i++) {
      y[i] = curve_out_y[size_curve - 1 - i];
   }
   simpleserial_put('r', size_curve, y);
   return 0x00;
}


uint8_t run_pmul(uint8_t* k, uint8_t len)
{
   // P * k
   for (int i = 0; i < size_curve; i++) {
      fp_scalar[i] = k[size_curve - 1 - i];
   }
   memset(curve_out_x, 0, ECC_ARRAY_LENGTH);
   memset(curve_out_y, 0, ECC_ARRAY_LENGTH);

   LTC_Init(LTC0);
   trigger_high_pcsamp();
   LTC_PKHA_ECC_PointMul(
      LTC0, 
      &curve_p_point, 
      fp_scalar,
      size_curve,
      curve_p, 
      NULL,
      curve_a,
      curve_b, 
      size_curve,
      kLTC_PKHA_TimingEqualized, 
      kLTC_PKHA_IntegerArith,
      &curve_output_point, 
      NULL
   );
   trigger_low_pcsamp();
      
   return 0x00;
}


uint8_t run_pmul_fixed(uint8_t* k, uint8_t len)
{
   // G * k
   for (int i = 0; i < size_curve; i++) {
      fp_scalar[i] = k[size_curve - 1 - i];
   }
   memset(curve_out_x, 0, ECC_ARRAY_LENGTH);
   memset(curve_out_y, 0, ECC_ARRAY_LENGTH);

   LTC_Init(LTC0);
   trigger_high_pcsamp();
   LTC_PKHA_ECC_PointMul(
      LTC0, 
      &curve_gen_point, 
      fp_scalar,
      size_curve,
      curve_p, 
      NULL,
      curve_a,
      curve_b, 
      size_curve,
      kLTC_PKHA_TimingEqualized, 
      kLTC_PKHA_IntegerArith,
      &curve_output_point, 
      NULL
   );
   trigger_low_pcsamp();
      
   return 0x00;
}


uint8_t run_add(uint8_t* unused, uint8_t unused_len)
{
   memset(curve_out_x, 0, ECC_ARRAY_LENGTH);
   memset(curve_out_y, 0, ECC_ARRAY_LENGTH);
   
   LTC_Init(LTC0);
   trigger_high_pcsamp();
   LTC_PKHA_ECC_PointAdd(
      LTC0,
      &curve_p_point,
      &curve_h_point,
      curve_p,
      NULL,
      curve_a,
      curve_b,
      size_curve,
      kLTC_PKHA_IntegerArith,
      &curve_output_point
   );
   trigger_low_pcsamp();
   return 0x00;
}


static void set_default_curve(void) {
   // Resets curve to NIST secp256r1
   static const uint8_t P[] = {
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff
   };
   static const uint8_t B[] = {
      0x4b, 0x60, 0xd2, 0x27, 0x3e, 0x3c, 0xce, 0x3b, 0xf6, 0xb0, 0x53, 0xcc,
      0xb0, 0x06, 0x1d, 0x65, 0xbc, 0x86, 0x98, 0x76, 0x55, 0xbd, 0xeb, 0xb3,
      0xe7, 0x93, 0x3a, 0xaa, 0xd8, 0x35, 0xc6, 0x5a
   };
   static const uint8_t Gx[] = {
      0x96, 0xc2, 0x98, 0xd8, 0x45, 0x39, 0xa1, 0xf4, 0xa0, 0x33, 0xeb, 0x2d,
      0x81, 0x7d, 0x03, 0x77, 0xf2, 0x40, 0xa4, 0x63, 0xe5, 0xe6, 0xbc, 0xf8,
      0x47, 0x42, 0x2c, 0xe1, 0xf2, 0xd1, 0x17, 0x6b
   };
   static const uint8_t Gy[] = {
      0xf5, 0x51, 0xbf, 0x37, 0x68, 0x40, 0xb6, 0xcb, 0xce, 0x5e, 0x31, 0x6b,
      0x57, 0x33, 0xce, 0x2b, 0x16, 0x9e, 0x0f, 0x7c, 0x4a, 0xeb, 0xe7, 0x8e,
      0x9b, 0x7f, 0x1a, 0xfe, 0xe2, 0x42, 0xe3, 0x4f
   };

   memcpy(curve_p, P, size_curve);
   memcpy(curve_a, P, size_curve);
   curve_a[0] = 0xfc;
   memcpy(curve_b, B, size_curve);
   memcpy(curve_gen_x, Gx, size_curve);
   memcpy(curve_gen_y, Gy, size_curve);
}

#else
// Use globals for pmul input (P) and output (Q) points because
// they're too big to transmit all in one simpleserial transfer:
// H is used for adding points: Q = P + H
uECC_word_t P[uECC_MAX_WORDS * 2] = {0};
uECC_word_t H[uECC_MAX_WORDS * 2] = {0};
uECC_word_t Q[uECC_MAX_WORDS * 2] = {0};


uint8_t set_px(uint8_t* x, uint8_t len)
{
   if (len != size_curve) {
      return 0x01;
   }
   uECC_vli_bytesToNative(P, x, size_curve);
   return 0x00;
}


uint8_t set_py(uint8_t* y, uint8_t len)
{
   if (len != size_curve) {
      return 0x01;
   }
   uECC_vli_bytesToNative(P + uECC_MAX_WORDS, y, size_curve);
   return 0x00;
}


uint8_t set_hx(uint8_t* x, uint8_t len)
{
   if (len != size_curve) {
      return 0x01;
   }
   uECC_vli_bytesToNative(H, x, size_curve);
   return 0x00;
}


uint8_t set_hy(uint8_t* y, uint8_t len)
{
   if (len != size_curve) {
      return 0x01;
   }
   uECC_vli_bytesToNative(H + uECC_MAX_WORDS, y, size_curve);
   return 0x00;
}


uint8_t get_qx(uint8_t* x, uint8_t len)
{
   uECC_vli_nativeToBytes(x, size_curve, Q);
   simpleserial_put('r', 32, x);
   return 0x00;
}


uint8_t get_qy(uint8_t* y, uint8_t len)
{
   uECC_vli_nativeToBytes(y, size_curve, Q + uECC_MAX_WORDS);
   simpleserial_put('r', 32, y);
   return 0x00;
}



uint8_t run_pmul(uint8_t* k, uint8_t len)
{
   uECC_word_t kwords[uECC_MAX_WORDS];
   const struct uECC_Curve_t* curve = uECC_secp256r1();

   uECC_vli_bytesToNative(kwords, k, size_curve);

   trigger_high_pcsamp();
   uECC_point_mult(Q, P, kwords, curve);
   trigger_low_pcsamp();
   return 0x00;
}


uint8_t run_pmul_fixed(uint8_t* k, uint8_t len)
{
   const struct uECC_Curve_t* curve = uECC_secp256r1();
   uECC_word_t kwords[uECC_MAX_WORDS];

   uECC_vli_bytesToNative(kwords, k, size_curve);

   trigger_high_pcsamp();
   uECC_point_mult(Q, curve->G, kwords, curve);
   trigger_low_pcsamp();
   return 0x00;
}


uint8_t set_a(uint8_t* unused_a, uint8_t unused_len)
{
   return 0x01;  // Not supported for uECC
}


uint8_t set_b(uint8_t* unused_b, uint8_t unused_len)
{
   return 0x01;  // Not supported for uECC
}


uint8_t set_p(uint8_t* unused_p, uint8_t unused_len)
{
   return 0x01;  // Not supported for uECC
}

uint8_t set_gx(uint8_t* unused_x, uint8_t unused_len)
{
   return 0x01;  // Not supported for uECC
}


uint8_t set_gy(uint8_t* unused_y, uint8_t unused_len)
{
   return 0x01;  // Not supported for uECC
}


uint8_t run_add(uint8_t* unused, uint8_t unused_len)
{
   const struct uECC_Curve_t* curve = uECC_secp256r1();

   // There's no helper to add points in uECC
   // Implementing the solution from https://github.com/kmackay/micro-ecc/issues/31
   uECC_word_t z[uECC_MAX_WORDS];
   uECC_word_t copy_P[2 * uECC_MAX_WORDS];

   uECC_vli_set(copy_P, P, curve->num_words);
   uECC_vli_set(copy_P + uECC_MAX_WORDS, P + uECC_MAX_WORDS, curve->num_words);
   uECC_vli_set(Q, H, curve->num_words);
   uECC_vli_set(Q + uECC_MAX_WORDS, H + uECC_MAX_WORDS,  curve->num_words);

   trigger_high_pcsamp();
   
   XYcZ_add(copy_P, copy_P + uECC_MAX_WORDS, Q, Q + uECC_MAX_WORDS, curve);

   // Find final 1/Z value
   uECC_vli_modMult_fast(z, P, copy_P + uECC_MAX_WORDS, curve);
   uECC_vli_modInv(z, z, curve->p, curve->num_words);
   uECC_vli_modMult_fast(z, z, copy_P, curve);
   uECC_vli_modMult_fast(z, z, P + uECC_MAX_WORDS, curve);

   apply_z(Q, Q + uECC_MAX_WORDS, z, curve);

   trigger_low_pcsamp();

   return 0x00;
}


static void set_default_curve(void) {
   return;
}

#endif


uint8_t reset(uint8_t* x, uint8_t len)
{
   // Reset key here if needed
   set_default_curve();
	return 0x00;
}

uint8_t info(uint8_t* x, uint8_t len)
{
   print("ChipWhisperer simpleserial-trace-ecc, compiled ");
   print(__DATE__);
   print(", ");
   print(__TIME__);
   print("\n");
	return 0x00;
}


uint8_t reenable_trace(uint8_t* x, uint8_t len)
{
   enable_trace();
	return 0x00;
}


int main(void)
{
   platform_init();
   init_uart();
   trigger_setup();
   set_default_curve();

   simpleserial_init();
   simpleserial_addcmd('k', 32, run_pmul);
   simpleserial_addcmd('f', 32, run_pmul_fixed);
   simpleserial_addcmd('d',  0, run_add);
   simpleserial_addcmd('a', 32, set_px);
   simpleserial_addcmd('b', 32, set_py);
   simpleserial_addcmd('h', 32, set_hx);
   simpleserial_addcmd('j', 32, set_hy);
   simpleserial_addcmd('p', 32, get_qx);
   simpleserial_addcmd('q', 32, get_qy);

   // Set curve params
   simpleserial_addcmd('G', 32, set_gx);
   simpleserial_addcmd('H', 32, set_gy);
   simpleserial_addcmd('P', 32, set_p);
   simpleserial_addcmd('A', 32, set_a);
   simpleserial_addcmd('B', 32, set_b);

   simpleserial_addcmd('x',  0, reset);
   simpleserial_addcmd('i',  0, info);
   simpleserial_addcmd('e',  0, reenable_trace);
   simpleserial_addcmd('s',  5, setreg);
   simpleserial_addcmd('g',  5, getreg);
   simpleserial_addcmd('c',  4, set_pcsample_params);

   enable_trace();

   while(1)
      simpleserial_get();
}
