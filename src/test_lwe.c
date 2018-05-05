#define _GNU_SOURCE

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
#include "tests.h"


#define setup()                                 \
  gamma_t gamma = param_gen();                  \
  sk_t sk;                                      \
  key_gen(sk, gamma)

#define teardown()                              \
  key_clear(sk, gamma);                         \
  param_clear(&gamma)


void test_import_export()
{
  setup();
  mpz_t m;
  mpz_init(m);

  ct_t c, _c;
  ct_init(c);
  ct_init(_c);

  uint8_t buf[CT_BLOCK];
  for (size_t i = 0; i < 10; i++) {
    mpz_urandomm(m, gamma.rstate, gamma.p);
    regev_encrypt(c, gamma, gamma.rstate, sk, m);
    ct_export(buf, c);
    ct_import(_c, buf);
    for (size_t i = 0; i < GAMMA_N+1; i++) {
      assert(!mpz_cmp(_c[i], c[i]));
    }
  }

  ct_clear(c);
  ct_clear(_c);
  mpz_clear(m);
  teardown();
}



void test_correctness()
{
  setup();

  mpz_t m, _m;
  mpz_init(m);
  mpz_init(_m);

  ct_t c;
  ct_init(c);

  for (size_t i = 0; i < 1e1; i++) {
    mpz_urandomm(m, gamma.rstate, gamma.p);
    regev_encrypt(c, gamma, gamma.rstate, sk, m);
    regev_decrypt(_m, gamma, sk, c);
    assert(!mpz_cmp(m, _m));
  }

  ct_clear(c);
  mpz_clears(m, _m, NULL);
  teardown();
}


#define fail_if_error() do {                    \
  if (errno > 0) {                              \
    perror("Failed");                           \
  }                                             \
  } while(0)

void test_eval()
{
  setup();
  const size_t d = 10;
  const char * coeffs_filename = "/tmp/coeffs";

  for (size_t tries = 0; tries != 10; tries++) {
    mpz_t m[d], coeffs[d];
    ct_t ct;

    int cfd = open(coeffs_filename, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
    fail_if_error();
    uint8_t buf[d * CT_BLOCK];

    for(size_t i = 0; i != d; i++) {
      mpz_init(m[i]);
      mpz_init(coeffs[i]);
      ct_init(ct);
      mpz_urandomm(m[i], gamma.rstate, gamma.p);
      mpz_urandomm(coeffs[i], gamma.rstate, gamma.p);
      regev_encrypt(ct, gamma, gamma.rstate, sk, m[i]);
      ct_export(&buf[i * CT_BLOCK], ct);
    }
    write(cfd, buf, d * CT_BLOCK);
    close(cfd);
    fail_if_error();

    ct_t evaluated;
    ct_init(evaluated);

    cfd = open(coeffs_filename, O_RDONLY | O_LARGEFILE);
    fail_if_error();
    eval_fd(evaluated, gamma, cfd, coeffs, d);
    close(cfd);
    fail_if_error();

    mpz_t got;
    mpz_init(got);
    regev_decrypt(got, gamma, sk, evaluated);

    mpz_t correct;
    mpz_init(correct);
    mpz_dotp(correct, gamma.p, m, coeffs, d);
    assert(!mpz_cmp(got, correct));

    mpz_clears(got, correct, NULL);
    mpz_clearv(m, d);
    mpz_clearv(coeffs, d);
    ct_clear(evaluated);
    ct_clear(ct);
  }

  teardown();
}



void test_smudging()
{
  setup();

  ct_t ct;
  mpz_t m, _m;
  ct_init(ct);
  mpz_inits(m, _m, NULL);

  for (size_t i=0; i<100; i++) {
    mpz_urandomm(m, gamma.rstate, gamma.p);

    regev_encrypt(ct, gamma, gamma.rstate, sk, m);
    ct_smudge(ct, gamma);

    regev_decrypt(_m, gamma, sk, ct);
    assert(!mpz_cmp(m, _m));
  }

  ct_clear(ct);
  mpz_clears(m, _m, NULL);
  teardown();
}

int main()
{
  test_correctness();
  test_import_export();
  test_eval();
  test_smudging();

  return EXIT_SUCCESS;
}
