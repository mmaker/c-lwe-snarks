#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <sys/random.h>
#include <sys/syscall.h>

#include <gmp.h>

#include "lwe.h"
#include "timeit.h"

void benchmark_encrypt()
{
  gamma_t gamma = param_gen();

  sk_t sk;
  key_gen(sk, gamma);

  mpz_t m;
  mpz_init(m);

  ctx_t c;
  ct_init(c, gamma);

  INIT_TIMEIT();
  for (size_t i = 0; i < 100; i++) {
    mpz_urandomm(m, gamma.rstate, gamma.p);
    START_TIMEIT();
    encrypt(c, gamma, sk, m);
    END_TIMEIT();

    printf(TIMEIT_FORMAT "\n", GET_TIMEIT());
  }

  key_clear(sk, gamma);
  mpz_clear(m);
  param_clear(&gamma);

}


int main() {
  benchmark_encrypt();
}