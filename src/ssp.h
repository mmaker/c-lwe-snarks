#pragma once
#include <flint/nmod_poly.h>

#include "lwe.h"
static const size_t ssp_length = GAMMA_D * 8 * (GAMMA_M+3);

#define ssp_t_offset 0
#define ssp_v_offset(i) (GAMMA_D * 8 * ((i)+1))


void nmod_poly_import(nmod_poly_t *pp, void *_buf, size_t degree);
void nmod_poly_export(void *_buf, nmod_poly_t *pp, size_t degree);
void random_ssp(mpz_t input, uint8_t *circuit, rng_t rng);
