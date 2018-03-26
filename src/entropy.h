#pragma once

#include <linux/random.h>
#include <sys/syscall.h>
#include <sys/random.h>
#include <unistd.h>

#include <gmp.h>

extern gmp_randstate_t _rstate;
extern unsigned long int _rseed;


void mpz_entropy_init();
