/* Provide a sys/select header file for systems lacking it (read: mingw32).
   Copyright (C) 2006 Free Software Foundation, Inc.
   Adapted from socket_.h, written by Simon Josefsson.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.  */

#ifndef _SYS_SELECT_H
#define _SYS_SELECT_H

/* This file is supposed to be used on platforms that lack
   sys/select.h.  It is intended to provide definitions and prototypes
   needed by an application.

   Currently only mingw32 is supported, which has the header file
   winsock2.h that declares select(). */

#if HAVE_WINSOCK2_H
# include <winsock2.h>
#endif

#endif /* _SYS_SELECT_H */
