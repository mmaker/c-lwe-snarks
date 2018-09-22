#pragma once

#include "config.h"
#include <unistd.h>

#include <gmp.h>

extern gmp_randstate_t _rstate;
extern unsigned long int _rseed;


void mpz_entropy_init();


#if HAVE_SYS_RANDOM_H
#include <sys/random.h>

#else
#include <linux/random.h>
#include <sys/syscall.h>

static inline ssize_t
getrandom(void *buffer, size_t length, unsigned int flags)
{
  return syscall(SYS_getrandom, buffer, length, flags);
}

#endif
