/* Copyright (C) 2006 Free Software Foundation, Inc.

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

#ifndef _NANOSLEEP_H
#define _NANOSLEEP_H

#if HAVE_NANOSLEEP

/* Get nanosleep() declaration.  */
#include <time.h>

#else

int nanosleep (const struct timespec *req, struct timespec *rem);

#endif

#endif /* _NANOSLEEP_H */
