#pragma once
#include <flint/nmod_poly.h>

#include "lwe.h"

void nmod_poly_import(nmod_poly_t *pp, void *_buf, slong degree);
void nmod_poly_export(void *_buf, const nmod_poly_t *pp);
