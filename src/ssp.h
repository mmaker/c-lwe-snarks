#pragma once
#include <gmp.h>

#include "lwe.h"

typedef mpz_t poly_t[GAMMA_D+1];

#define T 0
#define V(i) ((i)+1)


void write_ssp(int fd);
void read_polynomial(int fd, poly_t pp, uint32_t i);
void evaluate_polynomial(mpz_t rop, poly_t t, mpz_t x, mpz_t modulus);

#define poly_init(pp) mpz_initv(pp, GAMMA_D)
#define poly_clear(pp) mpz_clearv(pp, GAMMA_D)
#define poly_eq(pp, qq) mpz_eqv(pp, qq, GAMMA_D+1)
