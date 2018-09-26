#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT([mangiafuoco], [0.1], [michele.orru@ens.fr])


AC_CONFIG_SRCDIR([src/lwe.c])
AC_CONFIG_HEADERS([src/config.h])

# Checks for programs.

#AC_CHECK_TARGET_TOOL([latexmk], [latexmk], [no])
#AS_IF([test "x$latexmk" = "xno"], [AC_MSG_ERROR([cannot find pdflatex.])])
AC_PROG_CC([gcc clang cc])
AC_PROG_CC_C99
AC_PROG_RANLIB

# Checks for libraries.
AC_CHECK_LIB(gmp, __gmpz_init, ,
             [AC_MSG_ERROR([GNU MP not found, see https://gmplib.org/])])
AC_CHECK_LIB(flint, nmod_poly_init, ,
             [AC_MSG_ERROR([FLINT not found, see https://www.flintlib.org/])])
# AC_CHECK_LIB(crypto, CRYPTO_new_ex_data, ,
#              [AC_MSG_ERROR([OpenSSL not found, please install libssl-dev.])])

# have _GNU_SOURCE defined aroud.
AC_USE_SYSTEM_EXTENSIONS
AC_DEFINE([_DEFAULT_SOURCE], [1], [Enable _DEFAULT_SOURCE extensions (like for madivise(2)])


AC_DEFINE_UNQUOTED([BASEDIR], ["$srcdir/"], [Source directory])

# Checks for header files.
AC_CHECK_HEADERS([limits.h stdint.h stdlib.h string.h unistd.h])
AC_CHECK_SIZEOF(mp_limb_t, 8, [#include <gmp.h>])
AC_CHECK_SIZEOF(uint32_t, 4, [#include <stdint.h>])
AC_CHECK_SIZEOF(unsigned long long, 8, [])

AC_CHECK_HEADERS([sys/random.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_MALLOC
#AC_CHECK_FUNCS([dup2 setlocale strdup])


AM_INIT_AUTOMAKE

# Clear out compiler/linker flags
CFLAGS+=" -pedantic -Wall -std=c11 "

# Shut up automake
#AM_SILENT_RULES([yes])
#AC_SUBST([AM_MAKEFLAGS], [--no-print-directory])

# Adding package options

AC_ARG_ENABLE(debug,
   AS_HELP_STRING([--enable-debug], [enable debugging, default: no]),
   CFLAGS+=" -UNDEBUG -O0 -ggdb -fbounds-check",
   CFLAGS+=" -DNDEBUG -O3 -march=native -fopenmp")


AC_DEFINE([AESNI], [0], [Use aes-ni])
AM_CONDITIONAL([AESNI], [false])

#AC_ARG_VAR([ss_base], [ss base])
#AS_IF([test "x$ss_base" = x], [ss_base="1"])
#AC_DEFINE_UNQUOTED([SS_BASE], [$ss_base], [log of secret shares representation, default: 1.])


AC_OUTPUT([Makefile
           src/Makefile
           ])
