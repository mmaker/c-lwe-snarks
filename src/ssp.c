#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <gmp.h>
#include <flint/nmod_poly.h>

#include "lwe.h"
#include "ssp.h"

void nmod_poly_export(void *_buf, const nmod_poly_t *pp)
{
  const slong degree = nmod_poly_degree(pp);
  assert(degree <= GAMMA_D);
  assert(nmod_poly_modulus(pp) == GAMMA_P);

  uint64_t *buf = (uint64_t *) _buf;
  for (slong i = 0; i < degree; i++) {
    buf[i] = nmod_poly_get_coeff_ui(pp, i);
  }
}

void nmod_poly_import(nmod_poly_t *pp, void *_buf, slong degree)
{
  assert(degree > 0);

  uint64_t *buf = (uint64_t *) _buf;
  for (slong i = 0; i < degree; i++) {
    nmod_poly_set_coeff_ui(pp, i, buf[i]);
  }
}
