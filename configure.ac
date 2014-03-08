dnl configure.ac
dnl Process this file with autoconf to produce a configure script.
#
# This file is part of msmtp, an SMTP client.
#
# Copyright (C) 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014
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
AC_INIT([msmtp], [1.4.32], [marlam@marlam.de], [msmtp], [http://msmtp.sourceforge.net/])
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

dnl Headers and functions
AC_CHECK_HEADERS([sysexits.h netdb.h arpa/inet.h sys/socket.h sys/wait.h])
AC_CHECK_FUNCS([fmemopen fseeko fseeko64 getpass getservbyname link mkstemp sigaction strndup syslog vasprintf])
AC_SEARCH_LIBS([nanosleep], [rt posix4])
AC_SEARCH_LIBS([socket], [socket])

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
AC_ARG_WITH([ssl], [AS_HELP_STRING([--with-ssl=[gnutls|openssl|no]],
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

dnl GNU Libidn
AC_ARG_WITH([libidn], [AS_HELP_STRING([--with-libidn],
	[Support IDN (needs GNU Libidn)])],
    [libidn=$withval], [libidn=yes])
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

dnl gnome-keyring support (requires pkg-config).
AC_ARG_WITH([gnome-keyring], [AS_HELP_STRING([--with-gnome-keyring],
	[Support GNOME Keyring])],
    [gnome_keyring=$withval],[gnome_keyring=yes])
if test "$gnome_keyring" != "no"; then
    PKG_CHECK_MODULES([libgnome_keyring], [gnome-keyring-1], [HAVE_GNOME_KEYRING=1], [HAVE_GNOME_KEYRING=0])
    if test "$HAVE_GNOME_KEYRING" != "1"; then
	AC_MSG_WARN([library libgnome-keyring not found:])
	AC_MSG_WARN([$libgnome_keyring_PKG_ERRORS])
	AC_MSG_WARN([libgnome-keyring is provided by Gnome; Debian package: libgnome-keyring-dev])
	gnome_keyring="no"
    else
	gnome_keyring="yes"
	AC_DEFINE([HAVE_GNOME_KEYRING], [1], [Define to 1 if libgnome-keyring is available])
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
echo "GNU Libidn support ..... : $libidn"
echo "NLS support ............ : $USE_NLS"
echo "GNOME Keyring support .. : $gnome_keyring"
echo "MacOS X Keychain support : $macosx_keyring"
