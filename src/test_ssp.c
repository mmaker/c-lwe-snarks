#include "config.h"

#include <assert.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/random.h>
#include <string.h>

#include <flint/nmod_poly.h>

#include "ssp.h"

void test_import_export()
{
  nmod_poly_t p, q;
  nmod_poly_init(p, GAMMA_P);
  nmod_poly_init(q, GAMMA_P);

  nmod_poly_set_coeff_ui(p, 0, 2);
  nmod_poly_set_coeff_ui(p, 1, 1);
  nmod_poly_set_coeff_ui(p, 2, 3);

  uint64_t buf[3];
  nmod_poly_export(buf, &p, 3);
  nmod_poly_import(&q, buf, 3);

  nmod_poly_sub(p, p, q);
  assert(nmod_poly_degree(p) == -1);

  nmod_poly_clear(p);
  nmod_poly_clear(q);
}


void test_ssp()
{
  uint8_t *circuit = calloc(1, SSP_SIZE);
  mpz_t witness;
  mpz_init(witness);
  random_ssp(witness, circuit);

  nmod_poly_t one;
  nmod_poly_init(one, GAMMA_P);
  nmod_poly_set_coeff_ui(one, 0, 1);

  nmod_poly_t test;
  nmod_poly_init(test, GAMMA_P);
  nmod_poly_t t;
  nmod_poly_init(t, GAMMA_P);
  nmod_poly_t v_i;
  nmod_poly_init(v_i, GAMMA_P);

  // read t(x)
  nmod_poly_import(&t, &circuit[ssp_t_offset], GAMMA_D);

  // read v_0(x)
  nmod_poly_import(&test, &circuit[ssp_v_offset(0)], GAMMA_D);
  // read all others
  for (size_t i = 1; i < GAMMA_M; i++) {
    if (mpz_tstbit(witness, i-1)) {
      nmod_poly_import(&v_i, &circuit[ssp_v_offset(i)], GAMMA_D);
      nmod_poly_add(test, test, v_i);
    }
  }
  nmod_poly_pow(test, test, 2);
  nmod_poly_sub(test, test, one);

  nmod_poly_rem(test, test, t);
  assert(nmod_poly_degree(test) == -1);

  free(circuit);
  mpz_clear(witness);
  nmod_poly_clear(test);
  nmod_poly_clear(t);
  nmod_poly_clear(v_i);
  nmod_poly_clear(one);
}


int main()
{
  test_import_export();
  test_ssp();
}
