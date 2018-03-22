#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <sys/random.h>
#include <sys/syscall.h>

#include <gmp.h>

typedef struct gamma {
  mpz_t p;
  mpz_t q;
  uint64_t log_sigma;
  uint64_t n;
  gmp_randstate_t rstate;
} gamma_t;

typedef struct ctx {
  mpz_t* a;
  mpz_t b;
} ctx_t;

typedef mpz_t* sk_t;


void dot_product(mpz_t rop, mpz_t *a, mpz_t *b, size_t len)
{
  mpz_set_ui(rop, 0);
  for (size_t i = 0; i != len; i++) {
    mpz_addmul(rop, a[i], b[i]);
  }
}

gamma_t param_gen()
{

  gamma_t gamma;
  mpz_init(gamma.p);
  mpz_set_ui(gamma.p, 469572863);

  // mpz_init_set_str
  mpz_init(gamma.q);
  mpz_ui_pow_ui(gamma.q, 2, 800);

  gamma.log_sigma = 650;
  gamma.n = 1200;

  uint64_t rseed;
  gmp_randinit_default(gamma.rstate);
  getrandom(&rseed, sizeof(uint64_t), GRND_NONBLOCK);
  gmp_randseed_ui(gamma.rstate, rseed);

  return gamma;
}


void param_del(gamma_t *g)
{
  mpz_clear(g->q);
  mpz_clear(g->p);
}


sk_t key_gen(gamma_t gamma)
{
  sk_t sk = malloc(sizeof(mpz_t) * gamma.n);
  for (size_t i = 0; i < gamma.n; i++) {
    mpz_init(sk[i]);
    mpz_urandomm(sk[i], gamma.rstate, gamma.q);
  }

  return sk;
}

void key_del(sk_t *sk, gamma_t gamma)
{
  for (size_t i = 0; i < gamma.n; i++) {
    mpz_clear((*sk)[i]);
  }
  free(sk);
}

void ctx_init(ctx_t *ct, gamma_t gamma)
{
  ct->a = malloc(sizeof(mpz_t) * gamma.n);
  for (size_t i = 0; i != gamma.n; i++) {
    mpz_init(ct->a[i]);
  }
  mpz_init(ct->b);
}

void ct_clear(ctx_t *ct, gamma_t gamma)
{
  mpz_clear(ct->b);
  for (size_t i = 0; i != gamma.n; i++) {
    mpz_clear(ct->a[i]);
  }
  free(ct->a);
}

void chi(mpz_t e, gamma_t gamma)
{
  mpz_urandomb(e, gamma.rstate, gamma.log_sigma + 3);
  if (e->_mp_d[0] & 1) mpz_mul_ui(e, e, -1);
}

void encrypt(ctx_t *c, gamma_t gamma, sk_t sk, mpz_t m) {
  assert(mpz_cmp(gamma.p, m) > 0);

  // sample the error
  mpz_t e;
  mpz_init(e);
  chi(e, gamma);

  mpz_mul(c->b, e, gamma.p);

  // sample a
  for (size_t i=0; i < gamma.n; i++) {
    mpz_urandomm(c->a[i], gamma.rstate, gamma.q);
  }

  dot_product(c->b, sk, c->a, gamma.n);
  mpz_add(c->b, c->b, m);
  mpz_mod(c->b, c->b, gamma.q);

  mpz_clear(e);
}

void decrypt(mpz_t m, gamma_t gamma, sk_t sk, ctx_t ct)
{
  dot_product(m, ct.a, sk, gamma.n);
  mpz_sub(m, ct.b, m);
  mpz_mod(m, m, gamma.q);
  mpz_mod(m, m, gamma.p);
}

void eval(ctx_t *rop, gamma_t gamma, ctx_t *c, mpz_t *coeff, size_t d)
{

  for (size_t i = 0; i != gamma.n; i++) {
    mpz_set_ui(rop->a[i], 0);
    for (size_t j = 0; j != d; j++) {
      mpz_addmul(rop->a[i], c[j].a[i], coeff[j]);
    }
    mpz_mod(rop->a[i], rop->a[i], gamma.q);
  }

  mpz_set_ui(rop->b, 0);
  for (size_t j = 0; j != d; j++) {
    mpz_addmul(rop->b, c[j].b, coeff[j]);
  }
  mpz_mod(rop->b, rop->b, gamma.q);
}

void clear_lin_comb(mpz_t rop, mpz_t *m, mpz_t *coeffs, gamma_t gamma, size_t N)
{
  for (size_t i = 0; i != N; ++i) {
    mpz_addmul(rop, m[i], coeffs[i]);
  }
  mpz_mod(rop, rop, gamma.p);
}

void test_correctness()
{
  gamma_t gamma = param_gen();
  sk_t sk = key_gen(gamma);

  mpz_t m, _m;

  mpz_init(m);
  mpz_init(_m);

  ctx_t c;
  ctx_init(&c, gamma);

  for (size_t i = 0; i < (1<<15); i++) {
    mpz_urandomm(m, gamma.rstate, gamma.p);
    encrypt(&c, gamma, sk, m);
    decrypt(_m, gamma, sk, c);
    assert(!mpz_cmp(m, _m));
  }

  key_del(&sk, gamma);
  mpz_clears(m, _m, NULL);
  param_del(&gamma);

}

void test_eval()
{
  gamma_t gamma = param_gen();
  sk_t sk = key_gen(gamma);

  const int d = 1000;

  for (size_t tries = 0; tries != 1000; ++tries) {
    printf("%lu\n", tries);

    mpz_t m[d], coeffs[d];
    ctx_t ct[d];
    for(size_t i = 0; i != d; ++i) {
      mpz_init(m[i]);
      mpz_init(coeffs[i]);
      ctx_init(&ct[i], gamma);
      mpz_urandomm(m[i], gamma.rstate, gamma.p);
      mpz_urandomm(coeffs[i], gamma.rstate, gamma.p);
      encrypt(&ct[i], gamma, sk, m[i]);
    }
    
    ctx_t evaluated;
    ctx_init(&evaluated, gamma);
    eval(&evaluated, gamma, ct, coeffs, d);

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
      ct_clear(&ct[i], gamma);
    }
  }

  key_del(&sk, gamma);  
  param_del(&gamma);
}


int main()
{
  // test_correctness();
  test_eval();
  return EXIT_SUCCESS;
}
