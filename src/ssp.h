#pragma once
#include <flint/nmod_poly.h>

#include "lwe.h"

void nmod_poly_import(nmod_poly_t *pp, void *_buf, size_t degree);
void nmod_poly_export(void *_buf, nmod_poly_t *pp, size_t degree);
void random_ssp(int input_fd, int circuit_fd, gamma_t gamma);
