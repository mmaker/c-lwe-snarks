#define _GNU_SOURCE

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
  nmod_poly_export(buf, &p, 2);
  nmod_poly_import(&p, buf, 2);

  nmod_poly_sub(p, p, q);
  assert(nmod_poly_degree(q) == -1);
}



void test_ssp()
{
  gamma_t gamma = param_gen();
  const char * circuit_filename = "/tmp/circuit";

  int cfd = open(circuit_filename, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
  mpz_t witness;
  mpz_init(witness);
  random_ssp(witness, cfd, gamma);
  close(cfd);

  cfd = open(circuit_filename, O_RDONLY | O_LARGEFILE);

  nmod_poly_t one;
  nmod_poly_init(one, GAMMA_P);
  nmod_poly_set_coeff_ui(one, 0, 1);

  nmod_poly_t test;
  nmod_poly_init(test, GAMMA_P);
  nmod_poly_t t;
  nmod_poly_init(t, GAMMA_P);
  nmod_poly_t v_i;
  nmod_poly_init(v_i, GAMMA_P);

  uint8_t buf[8 * GAMMA_D];
  const size_t buflen = sizeof(buf);

  // read t(x)
  bzero(buf, buflen);
  read(cfd, buf, buflen);
  nmod_poly_import(&t, buf, GAMMA_D);

  // read v_0(x)
  read(cfd, buf, buflen);
  nmod_poly_import(&test, buf, GAMMA_D);

  // read all others
  for (size_t i = 0; i < GAMMA_M; i++) {
    read(cfd, buf, buflen);
    if (mpz_tstbit(witness, i)) {
      nmod_poly_import(&v_i, buf, GAMMA_D);
      nmod_poly_add(test, test, v_i);
    }
  }
  nmod_poly_pow(test, test, 2);
  nmod_poly_sub(test, test, one);

  nmod_poly_rem(test, test, t);
  assert(nmod_poly_degree(test) == -1);

  close(cfd);
  mpz_clear(witness);
  param_clear(&gamma);
  nmod_poly_clear(test);
  nmod_poly_clear(t);
  nmod_poly_clear(v_i);
}

int main()
{
  test_import_export();
  test_ssp();
}
