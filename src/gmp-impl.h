/* Here copy-pasted (with slight changes) some bits of gmp-impl.h.
 * This file shall allow for easier control of mpz_* instances.
 */
#pragma once

#include <gmp.h>

#define SIZ(x) ((x)->_mp_size)
#define PTR(x) ((x)->_mp_d)
#define ALLOC(x) ((x)->_mp_alloc)

#define UNLIKELY(cond)                 __GMP_UNLIKELY(cond)
#define MPN_NORMALIZE(DST, NLIMBS)                                      \
  do {									\
    while (1)								\
      {									\
	if ((DST)[(NLIMBS) - 1] != 0)					\
	  break;							\
	(NLIMBS)--;							\
      }									\
  } while (0)


#define MPZ_NEWALLOC(z,n) (UNLIKELY ((n) > ALLOC(z))         \
                           ? (mp_ptr) _mpz_realloc(z,n)      \
                           : PTR(z))
