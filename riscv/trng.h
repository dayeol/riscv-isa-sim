// See LICENSE for license details.

#ifndef _RISCV_TRNG_H
#define _RISCV_TRNG_H

#include "processor.h"

class trng_t {
public:
  trng_t ( void );
  reg_t read( void );
};

#endif // _RISCV_TRNG_H
