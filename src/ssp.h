#pragma once
#include <gmp.h>

#include "lwe.h"

typedef mpz_t poly_t[GAMMA_D];


void write_ssp(int fd);
void read_polynomial(int fd, poly_t pp, uint32_t i);



#define poly_eq(pp, qq) mpz_eqv(pp, qq, GAMMA_D)
