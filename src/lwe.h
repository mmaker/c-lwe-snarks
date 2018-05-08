#pragma once
#include <assert.h>
#include <stdint.h>
#include <sys/random.h>

#include <flint/nmod_poly.h>
#include <gmp.h>


/* Parameter generation */

#ifdef NDEBUG
#define GAMMA_D (1UL << 15)
#else
#define GAMMA_D (1UL << 8)
#endif

#define GAMMA_N 1470
#define GAMMA_LOGQ 736
#define GAMMA_P 0xfffffffbUL
/* must be divisible by 8 */
#define GAMMA_M (64)
#define GAMMA_LU 10
#define GAMMA_LOG_SMUDGING 640
#define GAMMA_LOG_SIGMA 556
#define LOGQ_BYTES 92
#define LOGP_BYTES 4
#define CT_BYTES (LOGQ_BYTES * (GAMMA_N+1))
/* CT_BLOCK is the block to be written on disk.
   Depending on the device it will need to be a power of 2 divisible by sizeof((void *)).
*/
#define CT_BLOCK CT_BYTES //(1 << 18)


typedef uint8_t rseed_t[32];
typedef gmp_randstate_t rng_t;

void rng_init(rng_t rs, uint8_t *rseed);
void rng_clear(rng_t rs);
#define RNG_INIT(rs) do {                              \
    rseed_t rseed;                                      \
    getrandom(&rseed, sizeof(rseed_t), GRND_NONBLOCK);  \
    rng_init(rs, rseed);                                \
  } while(0)


/* secret key generation */
typedef mpz_t sk_t[GAMMA_N];

void key_gen(sk_t sk, rng_t rng);
void key_clear(sk_t sk);


/* error distributions */
void errdist_uniform(mpz_t e, rng_t rng);

/* ciphertext */
typedef mpz_t ct_t[GAMMA_N+1];

void ct_init(ct_t ct);
void ct_clear(ct_t ct);

void ct_export(uint8_t *buf, ct_t ct);
void ct_import(ct_t ct, uint8_t *buf);

void decompress_encryption(ct_t c, gmp_randstate_t rs, mpz_t b);
void regev_encrypt2(ct_t c, gmp_randstate_t rs, sk_t sk, mpz_t m, void (*chi)(mpz_t, gmp_randstate_t));

void mpz_add_dotp(mpz_t rop, mpz_t a[], mpz_t b[], size_t len);

static inline
void mpz_dotp(mpz_t rop, mpz_t a[], mpz_t b[], size_t len) {
  mpz_set_ui(rop, 0);
  mpz_add_dotp(rop, a, b, len);
}

static inline
void regev_encrypt(ct_t c, gmp_randstate_t rs, sk_t sk, mpz_t m)
{
  regev_encrypt2(c, rs, sk, m, errdist_uniform);
}


void regev_decrypt(mpz_t m, sk_t sk, ct_t ct);
void ct_smudge(ct_t ct, rng_t rng);
void ct_add(ct_t rop, ct_t a, ct_t b);
void ct_mul_ui(ct_t rop, ct_t a, uint64_t b);
void eval_poly(ct_t rop, uint8_t *c8, nmod_poly_t coeffs, size_t d);

#define ct_clearv(vs, len) do {                     \
    for (size_t i = 0; i < len; i++) {              \
      ct_clear((vs)[i]);                            \
  }                                                 \
} while (0)


#define mpz_clearv(vs, len) do {                    \
  for (size_t i = 0; i < len; i++) {                \
    mpz_clear((vs)[i]);                             \
  }                                                 \
} while (0)

#define mpz_initv(vs, len) do {                 \
    for (size_t i = 0; i < len; i++) {          \
      mpz_init2((vs)[i], GAMMA_LOGQ);           \
    }                                           \
  } while (0)


#define mpz_urandommv(vs, rstate, bits, len) do {       \
    for (size_t i = 0; i < len; i++) {                  \
      mpz_urandomb(vs[i], rstate, bits);                \
    }                                                   \
  } while (0)


static inline
uint64_t rand_modp()
{
  uint64_t rop;
  getrandom(&rop, sizeof(rop), GRND_NONBLOCK);
  return rop % GAMMA_P;
}


#define SIZ(x) ((x)->_mp_size)
#define PTR(x) ((x)->_mp_d)

#define MPN_NORMALIZE(DST, NLIMBS)                                      \
  do {									\
    while (1)								\
      {									\
	if ((DST)[(NLIMBS) - 1] != 0)					\
	  break;							\
	(NLIMBS)--;							\
      }									\
  } while (0)


/**
 *
 */
static inline void modq(mpz_t a)
{
  assert(SIZ(a) >= 0);

  int pos = (GAMMA_LOGQ / 64) ;
  if (SIZ(a) > pos) {
    PTR(a)[pos] &= (1UL << 32) - 1;
    MPN_NORMALIZE(PTR(a), pos);
    SIZ(a) = pos;
  }
}
