#include "puf.h"
#include <cstdlib>

puf_t::puf_t (uint64_t identity) {
  int i;
  puf_values = (reg_t*)malloc(NUM_PUF_BITS * sizeof(reg_t));
  for (i=0; i<NUM_PUF_BITS; i++) {
    puf_values[i] = tiny_hash(identity + tiny_hash(i));
  }
  select = 0;
  disable = 0;
  reset = 0;
  cycles = 0;
}

puf_t::~puf_t ( void ) {
  free(puf_values);
}

reg_t puf_t::readout( void ) {
  if (disable) {
    return 0;
  } else {
    return puf_values[select%NUM_PUF_BITS];
  }
}

reg_t puf_t::tiny_hash(reg_t key) {
  key = (~key) + (key << 21); // key = (key << 21) - key - 1;
  key = key ^ (key >> 24);
  key = (key + (key << 3)) + (key << 8); // key * 265
  key = key ^ (key >> 14);
  key = (key + (key << 2)) + (key << 4); // key * 21
  key = key ^ (key >> 28);
  key = key + (key << 31);
  return key;
}
