#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/random.h>
#include <unistd.h>
#include <strings.h>

#include <gmp.h>
#include <flint/nmod_poly.h>

#include "lwe.h"
#include "ssp.h"

void nmod_poly_export(void *_buf, nmod_poly_t *pp, size_t degree)
{
  assert(nmod_poly_modulus(*pp) == GAMMA_P);

  uint64_t *buf = (uint64_t *) _buf;
  for (size_t i = 0; i < degree; i++) {
    buf[i] = nmod_poly_get_coeff_ui(*pp, i);
  }
}

void nmod_poly_import(nmod_poly_t *pp, void *_buf, size_t degree)
{
  uint64_t *buf = (uint64_t *) _buf;
  for (size_t i = 0; i < degree; i++) {
    nmod_poly_set_coeff_ui(*pp, i, buf[i]);
  }
}


void random_ssp(int input_fd, int circuit_fd, gamma_t gamma)
{

  uint8_t buf[8 *GAMMA_D];
  const size_t buflen = sizeof(buf);

  // create a valid inut
  bzero(buf, buflen);
  mpz_t input;
  mpz_init(input);
  mpz_urandomb(input, gamma.rstate, GAMMA_M);
  mpz_export(buf, NULL, -1, sizeof(uint8_t), -1, 0, input);
  write(input_fd, buf, GAMMA_M/8);

  // make up some space for t at the beginning of the file
  bzero(buf, buflen);
  write(circuit_fd, buf, buflen);

  nmod_poly_t one;
  nmod_poly_init(one, GAMMA_P);
  nmod_poly_set_coeff_ui(one, 0, 1);

  nmod_poly_t v_i;
  nmod_poly_init(v_i, GAMMA_P);

  nmod_poly_t t;
  nmod_poly_init(t, GAMMA_P);

  for (size_t i = 0; i < GAMMA_M+1; i++) {
    getrandom(buf, buflen, GRND_NONBLOCK);
    nmod_poly_import(&v_i, buf, GAMMA_D);
    nmod_poly_export(buf, &v_i, GAMMA_D);
    write(circuit_fd, buf, buflen);

    if (i == 0  || mpz_tstbit(input, i-1)) {
      nmod_poly_add(t, t, v_i);
    }
  }

  nmod_poly_sub(t, t, one);
  nmod_poly_export(buf, &t, GAMMA_D);
  pwrite(circuit_fd, buf, buflen, 0);

  mpz_clear(input);
  nmod_poly_clear(v_i);
  nmod_poly_clear(t);
  nmod_poly_clear(one);
}
