// See LICENSE for license details.

#ifndef _RISCV_PUF_H
#define _RISCV_PUF_H

#include "processor.h"

#define NUM_PUF_BITS 512

class puf_t {
public:
  puf_t (uint64_t identity);
  ~puf_t ( void );
  reg_t readout( void );

  reg_t select;
  reg_t disable;
  reg_t reset;
  reg_t cycles;

private:
  reg_t* puf_values;
  reg_t tiny_hash(reg_t key);
};

#endif // _RISCV_PUF_H
