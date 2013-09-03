#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([duo_cosign], [0.1], [dev@weblogin.org])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_SRCDIR([duo_cosign.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h sys/param.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset strcspn strdup strerror])

# submodule jansson paths
JSON_INCLUDE="./jansson/src"
JSON_STATIC_LIB="./jansson/src/.libs/libjansson.a"
AC_SUBST(JSON_INCLUDE)
AC_SUBST(JSON_STATIC_LIB)

AC_CONFIG_SUBDIRS([jansson])
AC_OUTPUT(Makefile)
