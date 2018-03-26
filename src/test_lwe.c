#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <sys/random.h>
#include <sys/syscall.h>

#include <gmp.h>

#include "lwe.h"


void test_correctness()
{
  gamma_t gamma = param_gen();
  sk_t sk;
  key_gen(sk, gamma);

  mpz_t m, _m;

  mpz_init(m);
  mpz_init(_m);

  ctx_t c;
  ct_init(c, gamma);

  for (size_t i = 0; i < 100; i++) {
    mpz_urandomm(m, gamma.rstate, gamma.p);
    encrypt(c, gamma, sk, m);
    decrypt(_m, gamma, sk, c);
    assert(!mpz_cmp(m, _m));
  }

  key_clear(sk, gamma);
  mpz_clears(m, _m, NULL);
  param_clear(&gamma);

}

void test_eval()
{
  gamma_t gamma = param_gen();
  sk_t sk;
  key_gen(sk, gamma);

  const size_t d = 1000;

  for (size_t tries = 0; tries != 10; ++tries) {
    printf("%lu\n", tries);

    mpz_t m[d], coeffs[d];
    ctx_t ct[d];
    for(size_t i = 0; i != d; ++i) {
      mpz_init(m[i]);
      mpz_init(coeffs[i]);
      ct_init(ct[i], gamma);
      mpz_urandomm(m[i], gamma.rstate, gamma.p);
      mpz_urandomm(coeffs[i], gamma.rstate, gamma.p);
      encrypt(ct[i], gamma, sk, m[i]);
    }

    ctx_t evaluated;
    ct_init(evaluated, gamma);
    eval(evaluated, gamma, ct, coeffs, d);

    mpz_t got;
    mpz_init(got);
    decrypt(got, gamma, sk, evaluated);

    mpz_t correct;
    mpz_init(correct);
    clear_lin_comb(correct, m, coeffs, gamma, d);

    assert(!mpz_cmp(got, correct));

    for (size_t i = 0; i != d; ++i) {
      mpz_clear(m[i]);
      mpz_clear(coeffs[i]);
      ct_clear(ct[i], gamma);
    }
  }

  key_clear(sk, gamma);
  param_clear(&gamma);
}


void test_errdist_uniform()
{
  mpz_t e;
  mpz_init(e);
  gamma_t gamma = param_gen();

  int signs = 0;
  for (size_t i = 0; i < 1e6; i++) {
    errdist_uniform(e, gamma);
    signs += mpz_sgn(e);
  }
  printf("%d\n", signs);
  assert(abs(signs) < 1e3);
  mpz_clear(e);
  param_clear(&gamma);
}

int main()
{
  test_errdist_uniform();
  test_correctness();
  test_eval();
  return EXIT_SUCCESS;
}
