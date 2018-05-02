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

  ct_t c;
  ct_init(c);

  for (size_t i = 0; i < 10; i++) {
    mpz_urandomm(m, gamma.rstate, gamma.p);
    encrypt(c, gamma, gamma.rstate, sk, m);
    decrypt(_m, gamma, sk, c);
    assert(!mpz_cmp(m, _m));
  }

  ct_clear(c);
  key_clear(sk, gamma);
  mpz_clears(m, _m, NULL);
  param_clear(&gamma);

}


void dot_product(mpz_t rop, mpz_t modulus, mpz_t a[], mpz_t b[], size_t len);

void test_eval()
{
  gamma_t gamma = param_gen();
  sk_t sk;
  key_gen(sk, gamma);

  const size_t d = 100;

  for (size_t tries = 0; tries != 10; tries++) {
    mpz_t m[d], coeffs[d];
    ct_t ct[d];

    for(size_t i = 0; i != d; i++) {
      mpz_init(m[i]);
      mpz_init(coeffs[i]);
      ct_init(ct[i]);
      mpz_urandomm(m[i], gamma.rstate, gamma.p);
      mpz_urandomm(coeffs[i], gamma.rstate, gamma.p);
      encrypt(ct[i], gamma, gamma.rstate, sk, m[i]);
    }

    ct_t evaluated;
    ct_init(evaluated);
    eval(evaluated, gamma, ct, coeffs, d);

    mpz_t got;
    mpz_init(got);
    decrypt(got, gamma, sk, evaluated);

    mpz_t correct;
    mpz_init(correct);
    dot_product(correct, gamma.p, m, coeffs, d);
    assert(!mpz_cmp(got, correct));

    mpz_clears(got, correct, NULL);
    mpz_clearv(m, d);
    mpz_clearv(coeffs, d);
    ct_clear(evaluated);
    ct_clearv(ct, d);
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
  assert(abs(signs) < 1e4);
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
