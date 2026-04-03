// pqm4 is designed such that it runs on a read board so because of that it needs 
// some hardware dependancy 
// The problem is that on a STM32 implementation, DRDY (data ready) is one bit that signals that 
// a random variable (RNG) is ready and it can be used and the firmware waits for that one.
// The problem was that in the Qiling simulation environment, RNG was not implemented, shich means that 
// DRDY was always 0 which means that it was hanging and never terminated, so because of that 
// I needed to write my own function and because I could not really create something random, 
// I did it by using a pseudo-random number generator by applying this  xorshift3, which of course 
// can be changed and probably when I will have a real board this file should not exist anymore 

#include "params.h"
#include <stdint.h>
//pqm4 hal_setup stub 
void hal_setup(int c) { (void)c; }


uint32_t rng_get_random_blocking(void)
{
    static uint32_t state = 0xdeadbeef;
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return state;
}