require64;
reg_t v = mmu.load_uint64(RB);
mmu.store_uint64(RB, std::min(RA,v));
RC = v;
