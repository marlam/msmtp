/*
 * xmalloc.h
 *
 * This file is part of msmtp, an SMTP client.
 *
 * Copyright (C) 2004, 2005, 2011
 * Martin Lambers <marlam@marlam.de>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef XALLOC_H
#define XALLOC_H

#include <stddef.h>

/*
 * These functions are replacements for malloc(), calloc(), realloc(), strdup(),
 * xasprintf() that always return valid pointers, never NULL.
 * If there's not enough memory available, they exit(EX_OSERR) instead.
 */

void *xmalloc(size_t size);
void *xcalloc(size_t n, size_t size);
void *xrealloc(void *ptr, size_t newsize);
char *xstrdup(const char *s);
char *xstrndup(const char *s, size_t n);

char *xasprintf(const char *format, ...)
#ifdef __GNUC__
__attribute__ ((format (printf, 1, 2)))
#endif
;

#endif
