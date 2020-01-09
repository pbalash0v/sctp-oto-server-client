#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([simple-sctp-server-client], [0.01a], [psb1979@hotmail.com])

AC_CONFIG_SRCDIR([src/lib/sctp_server/sctp_server.cpp])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])

AM_INIT_AUTOMAKE([foreign])

AM_SILENT_RULES([yes])

LT_INIT([disable-shared])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX([clang++ g++])
AC_LANG([C++])
#m4_ifdef([AX_CXX_COMPILE_STDCXX_14], [AX_CXX_COMPILE_STDCXX_14([noext],[mandatory])], [AC_MSG_ERROR([AX_CXX_COMPILE_STDCXX_14 macro missing. Install autoconf-archive package and run autoreconf again.])])
AX_CXX_COMPILE_STDCXX_14([noext],[mandatory])
AC_PROG_CPP


# Checks for libraries.
#m4_ifdef([AX_CHECK_OPENSSL], [AX_CHECK_OPENSSL], [AC_MSG_ERROR([AX_CHECK_OPENSSL macro missing. Install autoconf-archive package and run autoreconf again.])])
#m4_ifdef([AX_PTHREAD], [AX_PTHREAD], [AC_MSG_ERROR([AX_PTHREAD macro missing. Install autoconf-archive package and run autoreconf again.])])
#m4_ifdef([AX_WITH_CURSES], [AX_WITH_CURSES], [AC_MSG_ERROR([AX_WITH_CURSES macro missing. Install autoconf-archive package and run autoreconf again.])])

m4_ifdef([PKG_PROG_PKG_CONFIG], [PKG_PROG_PKG_CONFIG], [AC_MSG_ERROR([PKG_PROG_PKG_CONFIG macro missing. Install pkg-config package and run autoreconf again.])])

AX_CHECK_OPENSSL([], [AC_MSG_ERROR([OpenSSL dev not found. Install libssl-dev package and run autoreconf again.])])

AX_PTHREAD([], [AC_MSG_ERROR([Pthread not found.])])

AX_WITH_CURSES
AM_CONDITIONAL([WITH_NCURSES], [test "x$ax_cv_ncursesw" = xyes || test "x$ax_cv_ncurses" = xyes])

#if test "x$ax_cv_ncursesw" != xyes && test "x$ax_cv_ncurses" != xyes; then
#	AC_MSG_ERROR([requires either NcursesW or Ncurses library])
#fi

PKG_CHECK_MODULES([OPENCV], [opencv], [found_opencv=yes], [:])
AM_CONDITIONAL([WITH_OPENCV], [test x"$found_opencv" = xyes])


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
AC_CONFIG_SUBDIRS([src/lib/third_party/usrsctp])

AC_CONFIG_FILES([Makefile \
				src/Makefile \
				src/lib/Makefile \
				src/lib/third_party/Makefile \
				src/lib/sctp_common/Makefile \
				src/lib/sctp_server/Makefile \
				src/lib/sctp_client/Makefile \
				src/certs/Makefile \
				src/examples/Makefile \
				src/examples/third_party/Makefile \
				src/examples/broadcast/Makefile \
				src/examples/random_discard/Makefile \
				src/examples/mjpeg_streaming/Makefile \
				src/examples/certs/Makefile \
				src/examples/third_party/gopt-10.0/Makefile \
				tests/Makefile])

AC_OUTPUT
