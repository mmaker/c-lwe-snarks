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

  ct_t c;
  ct_init(c);

  INIT_TIMEIT();
  for (size_t i = 0; i < 1e4; i++) {
    mpz_set_ui(m, rand_modp());
    regev_encrypt(c, gamma, gamma.rstate, sk, m);

    START_TIMEIT();
    regev_decrypt(m, gamma, sk, c);
    END_TIMEIT();

    printf(TIMEIT_FORMAT "\n", GET_TIMEIT());
  }

  key_clear(sk);
  mpz_clear(m);
  param_clear(&gamma);

}


int main() {
  benchmark_encrypt();
}
