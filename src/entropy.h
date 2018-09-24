#pragma once
#include "config.h"

#include <unistd.h>

#include <gmp.h>

#include "gmp-impl.h"
#include "aes.h"



extern gmp_randstate_t _rstate;
extern unsigned long int _rseed;

typedef gmp_randstate_t rng_t;

typedef uint8_t rseed_t[32];
typedef gmp_randstate_t rng_t;

void rng_init(rng_t rs, uint8_t *rseed);
void rng_clear(rng_t rs);
#define RNG_INIT(rs) do {                              \
    rseed_t rseed;                                      \
    getrandom(&rseed, sizeof(rseed_t), GRND_NONBLOCK);  \
    rng_init(rs, rseed);                                \
  } while(0)



void mpz_entropy_init();


#ifdef HAVE_SYS_RANDOM_H
#include <sys/random.h>

#else
#include <sys/syscall.h>
#include <linux/random.h>

static inline ssize_t
getrandom(void *buffer, size_t length, unsigned int flags)
{
  return syscall(SYS_getrandom, buffer, length, flags);
}

#endif
