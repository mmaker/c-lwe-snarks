#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <gmp.h>
#include <flint/nmod_poly.h>

#include "entropy.h"
#include "lwe.h"
#include "timeit.h"


#define COEFFS_FILENAME "/home/maker/coeffs"

#define fail_if_error() do {                    \
    if (errno > 0) {                            \
      perror("Failed");                         \
      exit(EXIT_FAILURE);                       \
    }                                           \
  } while(0)


void benchmark_eval()
{
  rng_t rng;
  RNG_INIT(rng);
  sk_t sk;
  key_gen(sk, rng);

  mpz_t m[GAMMA_D];
  ct_t ct;
  ct_init(ct);

  nmod_poly_t coeffs;
  nmod_poly_init(coeffs, GAMMA_P);

  int cfd = open(COEFFS_FILENAME, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
  fail_if_error();
  uint8_t buf[CT_BLOCK];

  for (size_t i = 0; i != GAMMA_D; i++) {
    nmod_poly_set_coeff_ui(coeffs, i, rand_modp());

    mpz_init(m[i]);
    mpz_set_ui(m[i], rand_modp());
    regev_encrypt(ct, rng, sk, m[i]);
    ct_export(buf, ct);
    write(cfd, buf, CT_BLOCK);
  }
  close(cfd);
  fail_if_error();

  ct_t evaluated;
  ct_init(evaluated);

  cfd = open(COEFFS_FILENAME, O_RDONLY | O_LARGEFILE);
  static const size_t length = GAMMA_D * CT_BYTES;
  uint8_t *c8 = mmap(NULL, length, PROT_READ, MAP_PRIVATE, cfd, 0);
  madvise(c8, length, MADV_SEQUENTIAL);

  fail_if_error();
  INIT_TIMEIT();
  START_TIMEIT();
  eval_poly(evaluated, c8, coeffs, GAMMA_D);
  END_TIMEIT();

  printf(TIMEIT_FORMAT "\n", GET_TIMEIT());
  munmap(c8, length);
  close(cfd);
  fail_if_error();

  mpz_clearv(m, GAMMA_D);
  nmod_poly_clear(coeffs);
  ct_clear(evaluated);
  ct_clear(ct);

  key_clear(sk);
  rng_clear(rng);
}


int main() {
  benchmark_eval();
}
