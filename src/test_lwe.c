#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/random.h>
#include <sys/syscall.h>

#include <gmp.h>

#include "lwe.h"


void test_import_export()
{
  gamma_t gamma = param_gen();
  sk_t sk;
  key_gen(sk, gamma);

  mpz_t m;
  mpz_init(m);

  ct_t c, _c;
  ct_init(c);
  ct_init(_c);

  uint8_t buf[CT_BYTES];
  for (size_t i = 0; i < 10; i++) {

    mpz_urandomm(m, gamma.rstate, gamma.p);
    encrypt(c, gamma, gamma.rstate, sk, m);
    ct_export(buf, c);
    ct_import(_c, buf);
    for (size_t i = 0; i < GAMMA_N+1; i++) {
      assert(!mpz_cmp(_c[i], c[i]));
    }
  }

  ct_clear(c);
  ct_clear(_c);
  key_clear(sk, gamma);
  mpz_clear(m);
  param_clear(&gamma);
}



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

  for (size_t i = 0; i < 1e1; i++) {
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


#define fail_if_error() do {                    \
  if (errno > 0) {                              \
    perror("Failed");                           \
    exit(EXIT_FAILURE);                         \
  }                                             \
  } while(0)

void test_eval()
{
  gamma_t gamma = param_gen();
  sk_t sk;
  key_gen(sk, gamma);

  const size_t d = 1;

  for (size_t tries = 0; tries != 10; tries++) {
    mpz_t m[d], coeffs[d];
    ct_t ct;

    int cfd = open("/tmp/coeffs", O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
    fail_if_error();
    uint8_t buf[d * CT_BYTES];

    for(size_t i = 0; i != d; i++) {
      mpz_init(m[i]);
      mpz_init(coeffs[i]);
      ct_init(ct);
      mpz_urandomm(m[i], gamma.rstate, gamma.p);
      mpz_urandomm(coeffs[i], gamma.rstate, gamma.p);
      encrypt(ct, gamma, gamma.rstate, sk, m[i]);
      ct_export(&buf[i * CT_BYTES], ct);
    }
    write(cfd, buf, d * CT_BYTES);
    close(cfd);
    fail_if_error();

    ct_t evaluated;
    ct_init(evaluated);

    cfd = open("/tmp/coeffs", O_RDONLY);
    fail_if_error();
    eval_fd(evaluated, gamma, cfd, coeffs, d);
    close(cfd);
    fail_if_error();

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
    ct_clear(ct);
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
  test_import_export();
  test_eval();
  return EXIT_SUCCESS;
}
