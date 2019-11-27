#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([simple-sctp-server-client], [0.01a], [psb1979@hotmail.com])

AC_CONFIG_SRCDIR([src/server/main.cpp])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])

#AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_INIT_AUTOMAKE([foreign])

AM_SILENT_RULES([yes])

AC_PROG_RANLIB

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AX_CXX_COMPILE_STDCXX_14
AC_PROG_CPP


# Checks for libraries.
AX_CHECK_OPENSSL
AX_PTHREAD
AX_WITH_CURSES


# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h sys/socket.h])


# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T


# Checks for library functions.
AC_CHECK_FUNCS([memset strerror])

# Include usrsctp as subproject
AC_CONFIG_SUBDIRS([src/third_party/usrsctp])

AC_CONFIG_FILES([Makefile src/Makefile \
				src/common/Makefile src/third_party/gopt-10.0/Makefile \
				src/server/Makefile src/client/Makefile src/certs/Makefile \
				tests/Makefile])

AC_OUTPUT
