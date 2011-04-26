/*
 * xmalloc.c
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdarg.h>

#include "xalloc.h"

extern void xalloc_die(void);


/*
 * xmalloc()
 */

void *xmalloc(size_t size)
{
    void *ptr;

    if (!(ptr = malloc(size)))
    {
        xalloc_die();
    }
    return ptr;
}

/*
 * xcalloc()
 */

void *xcalloc(size_t n, size_t size)
{
    void *ptr;

    if (!(ptr = calloc(n, size)))
    {
        xalloc_die();
    }
    return ptr;
}

/*
 * xrealloc()
 */

void *xrealloc(void *ptr, size_t newsize)
{
    if (!(ptr = realloc(ptr, newsize)))
    {
        xalloc_die();
    }
    return ptr;
}

/*
 * xstrdup()
 */

char *xstrdup(const char *s)
{
    char *p;

    if (!(p = strdup(s)))
    {
        xalloc_die();
    }
    return p;
}

/*
 * xstrndup()
 */

char *xstrndup(const char *s, size_t n)
{
#ifdef HAVE_STRNDUP
    char *p;

    if (!(p = strndup(s, n)))
    {
        xalloc_die();
    }
    return p;
#else
    size_t l = 0;
    char *p;

    while (s[l] != '\0' && l < n)
    {
        l++;
    }
    p = malloc(l + 1);
    memcpy(p, s, l);
    p[l] = '\0';
    return p;
#endif
}

/*
 * xasprintf()
 */

#ifndef HAVE_VASPRINTF
static int vasprintf(char **strp, const char *format, va_list args)
{
    /* vasprintf() is only missing on Windows nowadays.
     * This replacement function only works when the vsnprintf() function is available
     * and its return value is standards compliant. This is true for the MinGW version
     * of vsnprintf(), but not for Microsofts version (Visual Studio etc.)!
     */
    int length = vsnprintf(NULL, 0, format, args);
    if (length > INT_MAX - 1 || !(*strp = malloc(length + 1)))
    {
        return -1;
    }
    vsnprintf(*strp, length + 1, format, args);
    return length;
}
#endif

char *xasprintf(const char *format, ...)
{
    char *strp;
    int count;
    va_list args;

    va_start(args, format);
    count = vasprintf(&strp, format, args);
    if (count < 0)
    {
        xalloc_die();
    }
    va_end(args);

    return strp;
}
