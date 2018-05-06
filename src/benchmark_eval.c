#define _GNU_SOURCE

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <gmp.h>

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
  gamma_t gamma = param_gen();
  sk_t sk;
  key_gen(sk, gamma);

  INIT_TIMEIT();
  mpz_t m[GAMMA_D], coeffs[GAMMA_D];
  ct_t ct;
  ct_init(ct);

  int cfd = open(COEFFS_FILENAME, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
  fail_if_error();
  uint8_t buf[CT_BLOCK];

  for (size_t i = 0; i != GAMMA_D; i++) {
    mpz_init(m[i]);
    mpz_init(coeffs[i]);
    mpz_urandomm(m[i], gamma.rstate, gamma.p);
    mpz_urandomm(coeffs[i], gamma.rstate, gamma.p);
    regev_encrypt(ct, gamma, gamma.rstate, sk, m[i]);
    ct_export(buf, ct);
    write(cfd, buf, CT_BLOCK);
  }
  close(cfd);
  fail_if_error();

  ct_t evaluated;
  ct_init(evaluated);

  cfd = open(COEFFS_FILENAME, O_RDONLY | O_LARGEFILE);
  fail_if_error();
  START_TIMEIT();
  eval_fd(evaluated, gamma, cfd, coeffs, GAMMA_D);
  END_TIMEIT();

  printf(TIMEIT_FORMAT "\n", GET_TIMEIT());
  close(cfd);
  fail_if_error();

  mpz_t got;
  mpz_init(got);
  regev_decrypt(got, gamma, sk, evaluated);

  mpz_t correct;
  mpz_init(correct);
  mpz_dotp(correct, gamma.p, m, coeffs, GAMMA_D);
  assert(!mpz_cmp(got, correct));

  mpz_clears(got, correct, NULL);
  mpz_clearv(m, GAMMA_D);
  mpz_clearv(coeffs, GAMMA_D);
  ct_clear(evaluated);
  ct_clear(ct);

  key_clear(sk, gamma);
  param_clear(&gamma);
}


int main() {
  benchmark_eval();
}
