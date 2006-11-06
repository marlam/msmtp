dnl configure.ac
dnl Process this file with autoconf to produce a configure script.
#
# This file is part of msmtp, an SMTP client.
#
# Copyright (C) 2003, 2004, 2005, 2006
# Christophe Nowicki
# Martin Lambers <marlam@marlam.de>
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software Foundation,
#   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
#

AC_INIT([msmtp], [1.4.9], [marlam@marlam.de])
AC_CONFIG_SRCDIR([src/msmtp.c])
AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE
AM_CONFIG_HEADER([config.h])

AC_PROG_CC
gl_EARLY
AC_PROG_RANLIB
AC_PROG_INSTALL

AC_C_CONST

AC_HEADER_STDC


dnl System
case "${target}" in *-*-mingw32*) windows=yes ;; *) windows=no ;; esac


dnl gnulib 
gl_INIT


dnl Gettext
AM_GNU_GETTEXT([external])


dnl Functions
AC_CHECK_FUNCS([syslog], [], [])
AC_SEARCH_LIBS([nanosleep], [rt posix4])


dnl Networking libraries, getaddrinfo()
if test "$windows" = "yes"; then
    LIBS="$LIBS -lws2_32"
    AC_ARG_ENABLE([win2000-and-older], 
        AC_HELP_STRING([--enable-win2000-and-older], 
            [build a binary that works on Windows 2000 and older systems]),
        [win2000_and_older=$enableval])
    if test "$win2000_and_older" != "yes"; then
        AC_DEFINE([HAVE_GETADDRINFO], [], [Have getaddrinfo() function])
    fi
else
    AC_CHECK_FUNC([socket], [], 
        [AC_CHECK_LIB([socket], [socket], [LIBS="$LIBS -lsocket"])])
    AC_CHECK_FUNC([getaddrinfo], 
        [AC_DEFINE(HAVE_GETADDRINFO, [], [Have getaddrinfo() function])
            [have_getaddrinfo=yes]],
        [AC_CHECK_FUNC([gethostbyname], [], 
            [AC_CHECK_LIB([nsl], [gethostbyname], [LIBS="$LIBS -lnsl"])])
         AC_CHECK_FUNC([hstrerror], [], 
            [AC_CHECK_LIB([resolv], [hstrerror], [LIBS="$LIBS -lresolv"])])])
fi


dnl TLS/SSL
have_tls=no
tls_lib=none
want_tls=yes
want_gnutls=yes
want_openssl=yes
AC_ARG_WITH([ssl], [AC_HELP_STRING([--with-ssl=[gnutls|openssl|no]],
        [TLS/SSL support: GnuTLS (default), OpenSSL, or none.])],
        if test "$withval" = "gnutls"; then
            want_tls=yes
	    want_gnutls=yes
            want_openssl=no
	elif test "$withval" = "openssl"; then
            want_tls=yes
            want_gnutls=no
            want_openssl=yes
	elif test "$withval" = "no"; then
            want_tls=no
            want_gnutls=no
            want_openssl=no
	else
	    AC_MSG_ERROR([Use --with-ssl=gnutls or --with-ssl=openssl or --with-ssl=no])
	fi)
if test "$want_gnutls" = "yes"; then
    # Test for GNU TLS >= 1.2.0. Since LIBGNUTLS_VERSION_NUMBER was not added
    # before 1.2.9, we test for gnutls_x509_crt_sign2(), which was added in 
    # 1.2.0.
    AC_LIB_HAVE_LINKFLAGS([gnutls], [], 
        [#include <gnutls/gnutls.h>
	 #include <gnutls/x509.h>],
        [gnutls_x509_crt_sign2(0, 0, 0, 0, 0)])
    if test "$HAVE_LIBGNUTLS" != yes; then
        AC_MSG_WARN([Cannot find GNU TLS, disabling])
    else
	have_tls=yes
        tls_lib="GNU TLS"
	LIBS="$LIBS $LIBGNUTLS"
    fi
fi
if test "$want_openssl" = "yes" -a "$have_tls" = "no"; then
    have_openssl=no
    if test "$windows" = "yes"; then
        AC_LIB_HAVE_LINKFLAGS([ssl32], [eay32], 
	    [#include <openssl/ssl.h>
	     #include <openssl/err.h>],
            [SSL_library_init(); ERR_get_error(); ])
        if test "$HAVE_LIBSSL32" = yes; then
	    have_openssl=yes
            LIBS="$LIBS $LIBSSL32"
        fi
    else
        AC_LIB_HAVE_LINKFLAGS([ssl], [crypto], 
	    [#include <openssl/ssl.h>
	     #include <openssl/err.h>],
            [SSL_library_init(); ERR_get_error(); ])
        if test "$HAVE_LIBSSL" = yes; then
	    have_openssl=yes
            LIBS="$LIBS $LIBSSL"
        fi
    fi
    if test "$have_openssl" != "yes"; then
        AC_MSG_WARN([Cannot find OpenSSL, disabling])
    else
        AC_DEFINE([HAVE_OPENSSL], [], [Build with OpenSSL support])
        have_tls=yes
        tls_lib="OpenSSL"
    fi
fi
if test "$have_tls" = "yes"; then
    AC_DEFINE([HAVE_TLS], [], [Build with TLS/SSL support])
    tls_obj="tls.o"
elif test "$want_tls" = "yes"; then
    AC_MSG_WARN([Neither GNU TLS nor OpenSSL found, disabling TLS/SSL support])
fi
AC_SUBST([tls_obj])


dnl GNU SASL
AC_ARG_WITH([libgsasl], [AC_HELP_STRING([--with-libgsasl],
	[Use GNU SASL authentication library.])],
    [libgsasl=$withval], [libgsasl=yes])
if test "$libgsasl" != "no"; then
    AC_LIB_HAVE_LINKFLAGS([gsasl], [], [#include <gsasl.h>],
        [gsasl_check_version(0);])
    if test "$HAVE_LIBGSASL" != yes; then
        libgsasl=no
        AC_MSG_WARN([Cannot find GNU SASL, disabling])
    else
        libgsasl=yes
	LIBS="$LIBS $LIBGSASL"
    fi
fi


dnl GNU Libidn
AC_ARG_WITH([libidn], [AC_HELP_STRING([--with-libidn],
	[Support IDN (needs GNU Libidn)])],
    [libidn=$withval], [libidn=yes])
if test "$libidn" != "no"; then
    AC_LIB_HAVE_LINKFLAGS([idn], [], [#include <stringprep.h>],
        [stringprep_check_version(0);])
    if test "$HAVE_LIBIDN" != yes; then
        libidn=no
        AC_MSG_WARN([Cannot find GNU Libidn, disabling])
    else
        libidn=yes
	LIBS="$LIBS $LIBIDN"
    fi
fi


dnl Global #defines for all source files
AH_VERBATIM([UNUSED],
[/* Let gcc know about unused variables to suppress warnings.
   Disable this feature for other compilers. */
#ifndef __attribute__
# if __GNUC__ < 2 || (__GNUC__ == 2 && __GNUC_MINOR__ < 8) || __STRICT_ANSI__
#  define __attribute__(x)
# endif
#endif
#ifndef UNUSED
# define UNUSED __attribute__ ((__unused__))
#endif])
AH_VERBATIM([gettext],
[/* Common gettext #defines. */
#define _(String) gettext (String)
#define N_(String) gettext_noop (String)])
AH_VERBATIM([W32_NATIVE],
[/* Define to 1 if the native W32 API should be used. */
#if (defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__
#define W32_NATIVE 1
#endif])


dnl End.
AC_CONFIG_FILES([Makefile doc/Makefile gnulib/Makefile po/Makefile.in src/Makefile])
AC_OUTPUT

echo
echo "Install prefix ....... : $prefix"
echo "TLS/SSL support ...... : $have_tls (Library: $tls_lib)"
echo "GNU SASL support ..... : $libgsasl"
echo "GNU Libidn support ... : $libidn"
echo "NLS support .......... : $USE_NLS"
