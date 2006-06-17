# sys_select_h.m4 serial 1
dnl Copyright (C) 2006 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

dnl Adapted from sys_socket_h.m4, written by Simon Josefsson.

AC_DEFUN([gl_HEADER_SYS_SELECT],
[
  AC_CHECK_HEADERS_ONCE([sys/select.h])
  if test $ac_cv_header_sys_select_h = yes; then
    SYS_SELECT_H=''
  else
    dnl We cannot use AC_CHECK_HEADERS_ONCE here, because that would make
    dnl the check for this header unconditional; yet cygwin reports
    dnl that the header is present but cannot be compiled (since on
    dnl cygwin, all socket information should come from the standard header
    dnl files).
    AC_CHECK_HEADERS([winsock2.h])
    SYS_SELECT_H='sys/select.h'
  fi
  AC_SUBST(SYS_SELECT_H)
])
