#include "trng.h"
#include <cstdlib>

trng_t::trng_t ( void ) {
  std::srand(0);
}

// For the TRNG, std::rand is guaranteed to produce at least 15 bits of pseudorandomness. Use 8 instances of the low-order 8 bits to compose a 64-bit pseudorandom word.
// The std::rand PRNG is seeded with 0 when initialized.
reg_t trng_t::read( void ) {
  return (  (((reg_t)std::rand()& 0xFF)<<56) |
            (((reg_t)std::rand()& 0xFF)<<48) |
            (((reg_t)std::rand()& 0xFF)<<40) |
            (((reg_t)std::rand()& 0xFF)<<32) |
            (((reg_t)std::rand()& 0xFF)<<24) |
            (((reg_t)std::rand()& 0xFF)<<16) |
            (((reg_t)std::rand()& 0xFF)<<8) |
            ((reg_t)std::rand()& 0xFF) );
}
