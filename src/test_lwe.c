#include "config.h"

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

#include <flint/nmod_poly.h>
#include <gmp.h>

#include "lwe.h"
#include "tests.h"


#define setup()                                      \
  rng_t rng;                                         \
  rseed_t rseed;                                     \
  getrandom(&rseed, sizeof(rseed_t), GRND_NONBLOCK); \
  rng_init(rng, rseed);                              \
  sk_t sk;                                           \
  key_gen(sk)

#define teardown()                              \
  key_clear(sk);                                \
  rng_clear(rng)


void test_import_export()
{
  setup();
  rng_t _rng;
  rng_init(_rng, rseed);
  mpz_t m;
  mpz_init(m);

  ct_t c, _c;
  ct_init(c);
  ct_init(_c);


  mpz2_urandommv(c, rng, GAMMA_LOGQ, GAMMA_N);
  mpz2_urandommv(_c, _rng, GAMMA_LOGQ, GAMMA_N);
  assert(!mpz_cmp(_c[0], c[0]));


  uint8_t buf[CT_BYTES];
  for (size_t trials = 0; trials < 10; trials++) {
    mpz_set_ui(m, rand_modp());
    regev_encrypt(c, rng, sk, m);
    ct_export(buf, c);
    ct_import(_c, _rng, buf);
    for (size_t i = 0; i <= GAMMA_N; i++) {
      assert(!mpz_cmp(_c[i], c[i]));
    }
  }

  ct_clear(c);
  ct_clear(_c);
  mpz_clear(m);
  rng_clear(_rng);
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
    mpz_set_ui(m, rand_modp());
    regev_encrypt(c, rng, sk, m);
    regev_decrypt(_m, sk, c);
    assert(!mpz_cmp(m, _m));
  }

  ct_clear(c);
  mpz_clears(m, _m, NULL);
  teardown();
}

void ct_addmul_ui(ct_t rop, ct_t a, uint64_t b);

#define fail_if_error() do {                    \
  if (errno > 0) {                              \
    perror("Failed");                           \
  }                                             \
  } while(0)

void test_eval()
{
  setup();
  rng_t _rng;
  rng_init(_rng, rseed);
  const size_t d = 100;
  //const char * coeffs_filename = BASEDIR "coeffs";

  uint8_t (*buf)[CT_BYTES] = (uint8_t (*) [CT_BYTES]) calloc(1, d * CT_BYTES);

  for (size_t tries = 0; tries != 1; tries++) {
    mpz_t m[d];

    nmod_poly_t coeffs;
    nmod_poly_init(coeffs, GAMMA_P);
    ct_t ct;
    ct_init(ct);

    //int cfd = open(coeffs_filename, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
    //fail_if_error();

    for (size_t i = 0; i != d; i++) {
      mpz_init(m[i]);
      mpz_set_ui(m[i], rand_modp());
      nmod_poly_set_coeff_ui(coeffs, i, 1);
      regev_encrypt(ct, rng, sk, m[i]);
      ct_export(buf[i], ct);
    }
    //write(cfd, buf, d * CT_BYTES);
    //close(cfd);
    //fail_if_error();

    mpz_t got;
    mpz_init(got);
    ct_t evaluated;
    ct_init(evaluated);

    //cfd = open(coeffs_filename, O_RDONLY | O_LARGEFILE);
    //const size_t length = d * CT_BYTES;
    //uint8_t *c8 = mmap(NULL, length, PROT_READ, MAP_PRIVATE, cfd, 0);
    // madvise(c8, length, MADV_SEQUENTIAL);
    //    fail_if_error();
    //ct_import(ct, _rng, buf);
    //ct_mul_ui(evaluated, ct, 1);

    eval_poly(evaluated, _rng, buf, coeffs, d);
    regev_decrypt(got, sk, evaluated);

    /* rng_init(_rng, rseed); */
    /* for (size_t i = 0; i != d; i++) { */
    /*   ct_import(ct, _rng, &buf[i * CT_BYTES]); */
    /*   regev_decrypt(got, sk, ct); */
    /*   assert(!mpz_cmp(got, m[i])); */
    /* } */
    //munmap(c8, length);
    //close(cfd);
    //fail_if_error();

    mpz_t correct;
    mpz_init_set_ui(correct, 0);
    for (size_t i = 0 ; i < d; i++) {
      mpz_addmul_ui(correct, m[i], nmod_poly_get_coeff_ui(coeffs, i));
    }
    mpz_mod_ui(correct, correct, GAMMA_P);
    assert(!mpz_cmp(got, correct));

    mpz_clears(got, correct, NULL);
    mpz_clearv(m, d);
    ct_clear(evaluated);
    ct_clear(ct);
    nmod_poly_clear(coeffs);
  }

  free(buf);
  rng_clear(_rng);
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
    mpz_set_ui(m, rand_modp());

    regev_encrypt(ct, rng, sk, m);
    ct_smudge(ct);

    regev_decrypt(_m, sk, ct);
    assert(!mpz_cmp(m, _m));
  }

  ct_clear(ct);
  mpz_clears(m, _m, NULL);
  teardown();
}


void test_modq()
{
  setup();

  mpz_t a, b, q;
  mpz_inits(a, b, q, NULL);
  mpz_ui_pow_ui(q, 2, GAMMA_LOGQ);

  /* it should work even on unitialized data */
  modq(a);
  modq(b);

  for (size_t tries = 0; tries < 100; tries++) {
    mpz2_urandomb(a, rng, GAMMA_LOGQ+128);
    mpz_set(b, a);

    modq(a);
    modq(b);
    assert(!mpz_cmp(a, b));
  }
  mpz_clears(a, b, q, NULL);
  teardown();
}

int main()
{
  test_modq();
  test_correctness();
  test_import_export();
  test_eval();
  test_smudging();

  return EXIT_SUCCESS;
}
