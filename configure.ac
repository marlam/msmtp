dnl configure.ac
dnl Process this file with autoconf to produce a configure script.
#
# This file is part of msmtp, an SMTP client.
#
# Copyright (C) 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010
# Christophe Nowicki
# Martin Lambers <marlam@marlam.de>
# Jay Soffian <jaysoffian@gmail.com> (Mac OS X keychain support)
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

AC_INIT([msmtp], [1.4.21], [marlam@marlam.de])
AC_CONFIG_SRCDIR([src/msmtp.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([build-aux])
AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE
AM_CONFIG_HEADER([config.h])

AC_PROG_CC
gl_EARLY
AC_PROG_RANLIB
AC_PROG_INSTALL
AC_SYS_LARGEFILE

dnl System
AC_DEFINE_UNQUOTED([PLATFORM], ["${target}"], [Platform triplet])
case "${target}" in *-*-mingw32*) windows=yes ;; *) windows=no ;; esac

dnl gnulib 
gl_INIT

dnl We provide a replacement for the fseeko() function ourselves instead
dnl of using the gnulib module because the gnulib module has a bug;
dnl see http://article.gmane.org/gmane.comp.lib.gnulib.bugs/16923
AC_CHECK_FUNCS([fseeko fseeko64])
AH_VERBATIM([fseeko], [
#ifndef HAVE_FSEEKO
# ifdef HAVE_FSEEKO64
#  define fseeko(s,o,w) fseeko64(s,o,w)
# else
#  define fseeko(s,o,w) fseek(s,o,w)
# endif
#endif])

dnl Gettext
AM_GNU_GETTEXT([external])

dnl Functions
AC_CHECK_FUNCS([syslog], [], [])

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
	AC_CHECK_FUNCS([gnutls_priority_set_direct], [], [])
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

dnl gnome-keyring support (requires pkg-config).
AC_ARG_WITH([gnome-keyring],
    [AC_HELP_STRING([--with-gnome-keyring],[Support GNOME Keyring])],
    [gnome_keyring=$withval],[gnome_keyring=no])
if test "$gnome_keyring" != "no"; then
    PKG_CHECK_MODULES([GNOMEKEYRING], [gnome-keyring-1],
        [gnome_keyring="yes"
	 CFLAGS="$CFLAGS $GNOMEKEYRING_CFLAGS"
         LIBS="$LIBS $GNOMEKEYRING_LIBS"
         AC_DEFINE([HAVE_GNOMEKEYRING], [1],
	     [Define to 1 if you have GNOME Keyring API.])],
	[gnome_keyring="no"
	 AC_MSG_WARN([Cannot find GNOME Keyring API, disabling])])
fi

dnl MacOS X Keychain Services (Security Framework)
AC_ARG_WITH([macosx-keyring],
    [AC_HELP_STRING([--with-macosx-keyring],[Support Mac OS X Keyring])],
    [macosx_keyring=$withval],[macosx_keyring=no])
if test "$macosx_keyring" != "no"; then
    AC_CACHE_CHECK([for SecKeychainGetVersion],
	ac_cv_func_SecKeychainGetVersion,
        [ac_save_LIBS="$LIBS"
         LIBS="$LIBS -Wl,-framework -Wl,Security"
         AC_TRY_LINK([#include <Security/Security.h>],
            [SecKeychainGetVersion(NULL);],
            [ac_cv_func_SecKeychainGetVersion=yes],
            [ac_cv_func_SecKeychainGetVersion=no])
         LIBS="$ac_save_LIBS"])
    if test $ac_cv_func_SecKeychainGetVersion = yes; then
        macosx_keyring=yes
        AC_DEFINE([HAVE_MACOSXKEYRING], 1,
            [Define to 1 if you have the MacOS X Keychain Services API.])
        LIBS="$LIBS -Wl,-framework -Wl,Security"
    else
        macosx_keyring=no
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
AC_CONFIG_FILES([Makefile build-aux/Makefile gnulib/Makefile \
	src/Makefile po/Makefile.in doc/Makefile scripts/Makefile])
AC_OUTPUT

echo
echo "Install prefix ......... : $prefix"
echo "TLS/SSL support ........ : $have_tls (Library: $tls_lib)"
echo "GNU SASL support ....... : $libgsasl"
echo "GNU Libidn support ..... : $libidn"
echo "NLS support ............ : $USE_NLS"
echo "GNOME Keyring support .. : $gnome_keyring"
echo "MacOS X Keychain support : $macosx_keyring"
