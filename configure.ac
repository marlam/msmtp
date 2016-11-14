dnl configure.ac
dnl Process this file with autoconf to produce a configure script.
#
# This file is part of msmtp, an SMTP client.
#
# Copyright (C) 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012,
# 2013, 2014, 2015, 2016
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

dnl Autotools init stuff
AC_INIT([msmtp], [1.6.6], [marlam@marlam.de], [msmtp], [http://msmtp.sourceforge.net/])
AC_CONFIG_SRCDIR([src/msmtp.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])
AC_CANONICAL_TARGET
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AM_INIT_AUTOMAKE([1.11.1 silent-rules no-texinfo.tex -Wall])
AM_SILENT_RULES([yes])
AC_PROG_CC
AC_PROG_INSTALL
AC_LANG([C])

dnl System
AC_DEFINE_UNQUOTED([PLATFORM], ["${target}"], [Platform triplet])
case "${target}" in *-*-mingw*) LIBS="$LIBS -lws2_32" ;; esac

dnl Gettext
AM_GNU_GETTEXT([external])

dnl Headers, functions, and types
AC_CHECK_HEADERS([sysexits.h netdb.h arpa/inet.h sys/socket.h sys/wait.h])
AC_CHECK_FUNCS([fmemopen fseeko fseeko64 getpass getservbyname link mkstemp strndup syslog vasprintf])
AC_SEARCH_LIBS([nanosleep], [rt posix4])
AC_SEARCH_LIBS([socket], [socket])
AC_CHECK_SIZEOF([long long])

dnl pkg-config (required to detect libraries)
PKG_PROG_PKG_CONFIG([])
if test -z "$PKG_CONFIG"; then
    AC_MSG_ERROR([pkg-config not found])
fi

dnl TLS/SSL
have_tls="no"
tls_lib="none"
want_tls="yes"
want_gnutls="yes"
want_openssl="yes"
tls_CFLAGS=""
tls_LIBS=""
with_ssl_was_used=no
AC_ARG_WITH([ssl], [],
    with_ssl_was_used=yes
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
	AC_MSG_ERROR([Use --with-tls=gnutls or --with-tls=openssl or --with-tls=no])
    fi)
if test "$with_ssl_was_used" = "yes"; then
    AC_MSG_WARN([--with-ssl is deprecated, use --with-tls instead])
fi
AC_ARG_WITH([tls], [AS_HELP_STRING([--with-tls=[gnutls|openssl|no]],
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
	AC_MSG_ERROR([Use --with-tls=gnutls or --with-tls=openssl or --with-tls=no])
    fi)
if test "$want_gnutls" = "yes"; then
    PKG_CHECK_MODULES([libgnutls], [gnutls >= 0.0], [HAVE_LIBGNUTLS=1], [HAVE_LIBGNUTLS=0])
    if test "$HAVE_LIBGNUTLS" != "1"; then
	AC_MSG_WARN([library libgnutls not found:])
	AC_MSG_WARN([$libgnutls_PKG_ERRORS])
	AC_MSG_WARN([libgnutls is provided by GnuTLS; Debian package: libgnutls-dev])
    else
	have_tls="yes"
	tls_lib="GnuTLS"
	tls_CFLAGS="$libgnutls_CFLAGS"
	tls_LIBS="$libgnutls_LIBS"
	AC_DEFINE([HAVE_LIBGNUTLS], [1], [Define to 1 if libgnutls is available])
    fi
fi
if test "$want_openssl" = "yes" -a "$have_tls" = "no"; then
    PKG_CHECK_MODULES([libssl], [openssl >= 0.0], [HAVE_LIBSSL=1], [HAVE_LIBSSL=0])
    if test "$HAVE_LIBSSL" != "1"; then
	AC_MSG_WARN([library libssl not found:])
	AC_MSG_WARN([$libssl_PKG_ERRORS])
	AC_MSG_WARN([libssl is provided by OpenSSL; Debian package: libssl-dev])
    else
	have_tls="yes"
	tls_lib="OpenSSL"
	tls_CFLAGS="$libssl_CFLAGS"
	tls_LIBS="$libssl_LIBS"
	AC_DEFINE([HAVE_LIBSSL], [1], [Define to 1 if libssl is available])
    fi
fi
if test "$have_tls" = "yes"; then
    AC_DEFINE([HAVE_TLS], [1], [Define to 1 to build with TLS/SSL support])
elif test "$want_tls" = "yes"; then
    AC_MSG_WARN([Neither GnuTLS nor OpenSSL found, disabling TLS/SSL support])
fi
AM_CONDITIONAL([HAVE_TLS], [test "$have_tls" = "yes"])
AC_SUBST([tls_CFLAGS])
AC_SUBST([tls_LIBS])

dnl GNU SASL
AC_ARG_WITH([libgsasl], [AS_HELP_STRING([--with-libgsasl],
	[Use GNU SASL authentication library.])],
    [libgsasl=$withval], [libgsasl=yes])
if test "$libgsasl" != "no"; then
    PKG_CHECK_MODULES([libgsasl], [libgsasl >= 0.0], [HAVE_LIBGSASL=1], [HAVE_LIBGSASL=0])
    if test "$HAVE_LIBGSASL" != "1"; then
	AC_MSG_WARN([library libgsasl not found:])
	AC_MSG_WARN([$libgsasl_PKG_ERRORS])
	AC_MSG_WARN([libgsasl is provided by GNU SASL; Debian package: libgsasl7-dev])
	libgsasl="no"
    else
	libgsasl="yes"
	AC_DEFINE([HAVE_LIBGSASL], [1], [Define to 1 if libgsasl is available])
    fi
fi
AM_CONDITIONAL([HAVE_LIBGSASL], [test "$libgsasl" = "yes"])

dnl Check if getaddrinfo() has IDN support (and we want to use it)
AC_ARG_ENABLE([gai-idn],
    [AS_HELP_STRING([--enable-gai-idn], [Use IDN support from getaddrinfo if available. Enabled by default.])],
    [if test "$enableval" = "yes"; then want_gai_idn="yes"; else want_gai_idn="no"; fi], [want_gai_idn="yes"])
have_gai_idn=no
if test "$want_gai_idn" = "yes"; then
    dnl TODO: in the future there may be getaddrinfo() implementations that
    dnl support IDN without requiring AI_IDN
    AC_CHECK_DECL([AI_IDN], [], [],
    [
     #include <sys/types.h>
     #include <sys/socket.h>
     #include <netdb.h>
    ])
    if test "$ac_cv_have_decl_AI_IDN" = "yes"; then
	dnl AI_IDN is defined, now check if it is actually supported
	dnl (glibc without libidn will return EAI_BADFLAGS)
        AC_MSG_CHECKING([whether getaddrinfo accepts AI_IDN])
	AC_RUN_IFELSE(
            [AC_LANG_PROGRAM(
            [[
             #include <sys/types.h>
             #include <sys/socket.h>
	     #include <netdb.h>
            ]],
            [[
             struct addrinfo hints;
             struct addrinfo *res;
             int r;
             hints.ai_flags = AI_IDN;
             hints.ai_family = PF_UNSPEC;
             hints.ai_socktype = SOCK_STREAM;
             hints.ai_protocol = 0;
             hints.ai_addrlen = 0;
             hints.ai_addr = 0;
             hints.ai_canonname = 0;
             hints.ai_next = 0;
             r = getaddrinfo("localhost", "1234", &hints, &res);
             freeaddrinfo(res);
             return (r == EAI_BADFLAGS ? 1 : 0);
	    ]])],
            [have_gai_idn="yes"],
	    [have_gai_idn="no"],
	    [have_gai_idn="assuming yes"])
        AC_MSG_RESULT([$have_gai_idn])
        if test "$have_gai_idn" = "assuming yes"; then
            AC_MSG_NOTICE([if this assumption is wrong, use --disable-gai-idn])
            have_gai_idn="yes"
        fi
        if test "$have_gai_idn" = "yes"; then
            AC_DEFINE([HAVE_GAI_IDN], [1], [Define to 1 if getaddrinfo supports IDN])
        fi
    fi
fi

dnl Check if the TLS library has IDN support
have_tls_idn=no
if test "$tls_lib" = "GnuTLS"; then
    AC_MSG_CHECKING([whether GnuTLS has builtin IDN support])
    CFLAGS_BAK="$CFLAGS"
    CFLAGS="$CFLAGS $tls_CFLAGS"
    AC_COMPILE_IFELSE(
        [AC_LANG_PROGRAM([[
         #include <gnutls/gnutls.h>
         #if GNUTLS_VERSION_NUMBER < 0x030400
          error: GnuTLS does not have builtin IDN support
         #endif]],
        [[int x = 0;]])],
        [have_tls_idn="yes"], [])
    CFLAGS="$CFLAGS_BAK"
    AC_MSG_RESULT([$have_tls_idn])
fi

dnl Do we need libidn for IDN support?
AC_MSG_CHECKING([whether libidn is needed for IDN support])
want_libidn=no
if test "$have_gai_idn" = "no"; then
    want_libidn=yes
elif test "$have_tls" = "yes" -a "$have_tls_idn" = "no"; then
    want_libidn=yes
fi
AC_MSG_RESULT([$want_libidn])

dnl GNU Libidn
AC_ARG_WITH([libidn], [AS_HELP_STRING([--with-libidn],
	[Support IDN (needs GNU Libidn)])],
    [libidn=$withval], [libidn=yes])
if test "$want_libidn" = "no"; then
    libidn=no
fi
if test "$libidn" != "no"; then
    PKG_CHECK_MODULES([libidn], [libidn >= 0.0], [HAVE_LIBIDN=1], [HAVE_LIBIDN=0])
    if test "$HAVE_LIBIDN" != "1"; then
	AC_MSG_WARN([library libidn not found:])
	AC_MSG_WARN([$libidn_PKG_ERRORS])
	AC_MSG_WARN([libidn is provided by GNU Libidn; Debian package: libidn11-dev])
	libidn="no"
    else
	libidn="yes"
	AC_DEFINE([HAVE_LIBIDN], [1], [Define to 1 if libidn is available])
    fi
fi

dnl libsecret support (requires pkg-config).
AC_ARG_WITH([libsecret], [AS_HELP_STRING([--with-libsecret],
	[Support libsecret (GNOME password management)])],
    [libsecret=$withval],[libsecret=yes])
if test "$libsecret" != "no"; then
    PKG_CHECK_MODULES([libsecret], [libsecret-1], [HAVE_LIBSECRET=1], [HAVE_LIBSECRET=0])
    if test "$HAVE_LIBSECRET" != "1"; then
	AC_MSG_WARN([library libsecret not found:])
	AC_MSG_WARN([$libsecret_PKG_ERRORS])
	AC_MSG_WARN([libsecret is provided by Gnome; Debian package: libsecret-1-dev])
	libsecret="no"
    else
	libsecret="yes"
	AC_DEFINE([HAVE_LIBSECRET], [1], [Define to 1 if libsecret is available])
    fi
fi

dnl MacOS X Keychain Services (Security Framework)
AC_ARG_WITH([macosx-keyring], [AS_HELP_STRING([--with-macosx-keyring],
	[Support Mac OS X Keyring])],
    [macosx_keyring=$withval],[macosx_keyring=yes])
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
	AC_DEFINE([HAVE_MACOSXKEYRING], [1],
	    [Define to 1 if you have the MacOS X Keychain Services API.])
	LIBS="$LIBS -Wl,-framework -Wl,Security"
    else
	macosx_keyring=no
    fi
fi

dnl Global #defines for all source files
AH_VERBATIM([W32_NATIVE],
[/* Define to 1 if the native W32 API should be used. */
#if (defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__
#define W32_NATIVE 1
#endif])

dnl End.
AC_CONFIG_FILES([Makefile src/Makefile po/Makefile.in doc/Makefile scripts/Makefile])
AC_OUTPUT

echo
echo "Install prefix ......... : $prefix"
echo "TLS/SSL support ........ : $have_tls (Library: $tls_lib)"
echo "GNU SASL support ....... : $libgsasl"
if test "$want_libidn" = "no"; then
    echo "IDN support ............ : yes (no library required)"
elif test "$libidn" = "yes"; then
    echo "IDN support ............ : yes (via GNU Libidn)"
else
    echo "IDN support ............ : no"
fi
echo "NLS support ............ : $USE_NLS"
echo "Libsecret support (GNOME): $libsecret"
echo "MacOS X Keychain support : $macosx_keyring"
