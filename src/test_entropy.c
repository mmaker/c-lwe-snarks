#include "config.h"

#include <assert.h>
#include <stdlib.h>
#include "entropy.h"
#include "tests.h"


void test_nonzero()
{
  rng_t prg;
  RNG_INIT(prg);

  mpz_t a;
  mpz_init(a);
  mpz2_urandomb(a, prg, 736);

  assert(mpz_cmp_ui(a, 0));
  mpz_clear(a);
  rng_clear(prg);
}


void test_deterministic()
{
  rng_t rng, _rng;
  rseed_t seed;
  getrandom(seed, sizeof(rseed_t), GRND_NONBLOCK);
  rng_init(rng, seed);
  rng_init(_rng, seed);


  mpz_t a, b;
  mpz_inits(a, b, NULL);
  mpz2_urandomb(a, rng, 64);
  mpz2_urandomb(b, _rng, 64);
  assert(!mpz_cmp(a, b));


  mpz2_urandomb(a, rng, 1);
  mpz2_urandomb(b, _rng, 1);
  assert(!mpz_cmp(a, b));


  mpz2_urandomb(a, rng, 5);
  mpz2_urandomb(b, _rng, 5);
  assert(!mpz_cmp(a, b));


  mpz2_urandomb(a, rng, 32);
  mpz2_urandomb(b, _rng, 32);
  assert(!mpz_cmp(a, b));


  mpz2_urandomb(a, rng, 40);
  mpz2_urandomb(b, _rng, 40);
  assert(!mpz_cmp(a, b));


  mpz2_urandomb(a, rng,  512 + 8);
  mpz2_urandomb(b, _rng, 512 + 8);
  assert(!mpz_cmp(a, b));


  mpz2_urandomb(a, rng, 512);
  mpz2_urandomb(b, _rng, 512);
  assert(!mpz_cmp(a, b));

  for (size_t rest = 0; rest < 16; rest++) {
    mpz2_urandomb(a, rng, 736 + rest);
    mpz2_urandomb(b, _rng, 736 + rest);
    assert(!mpz_cmp(a, b));
  }

  rng_clear(rng);
  rng_clear(_rng);

}


void test_deterministic_urandomb()
{
  rng_t rng, _rng;
  rseed_t seed;
  getrandom(seed, sizeof(rseed_t), GRND_NONBLOCK);
  rng_init(rng, seed);
  rng_init(_rng, seed);

  const size_t size = 800;
  mpz_t a[size], b[size];
  for (size_t i = 0; i < size; i++) {
    mpz_init(a[i]);
    mpz_init(b[i]);
  }

  for (size_t i = 0; i < size; i++) {
    mpz2_urandomb(a[i], rng, 700);
    mpz2_urandomb(b[i], _rng, 700);
    assert(!mpz_cmp(a[i], b[i]));
  }

  for (size_t i = 0; i < size; i++) {
    mpz_clear(a[i]);
    mpz_clear(b[i]);
  }
  rng_clear(rng);
  rng_clear(_rng);
}


void test_accumulate()
{
  rng_t rng;
  rng_t _rng;
  rseed_t seed;
  getrandom(seed, sizeof(rseed_t), GRND_NONBLOCK);
  rng_init(rng, seed);
  rng_init(_rng, seed);

  const size_t n = 92 * 1470 * 1000;
  uint8_t *sink = malloc(n);
  rng_gen(rng, sink, n);

  uint8_t *_sink = malloc(n);
  for (size_t i = 0; i <1470 * 1000; i++) {
    rng_gen(_rng, &_sink[i * 92], 92);
  }

  assert(sink[0] == _sink[0]);
  assert(sink[n-1] == _sink[n-1]);

  free(sink);
  free(_sink);
  rng_clear(rng);
  rng_clear(_rng);

}
void test_seek()
{
  rng_t rng;
  rng_t _rng;
  rseed_t seed;
  getrandom(seed, sizeof(rseed_t), GRND_NONBLOCK);
  rng_init(rng, seed);
  rng_init(_rng, seed);


  uint8_t sink[512];
  rng_gen(rng, sink, 512);
  uint64_t got, expected;
  rng_seek(_rng, 512);

  rng_gen(_rng, &got, 8);
  rng_gen(rng, &expected, 8);
  assert(got == expected);
}


int main()
{
  test_nonzero();
  test_deterministic();
  test_deterministic_urandomb();
  test_accumulate();
  test_seek();
}
