/*
 * eval.c
 *
 * This file is part of msmtp, an SMTP client, and of mpop, a POP3 client.
 *
 * Copyright (C) 2019, 2020, 2021, 2022  Martin Lambers <marlam@marlam.de>
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
#include <errno.h>

#include "gettext.h"
#define _(string) gettext(string)

#include "xalloc.h"
#include "eval.h"


/*
 * eval()
 *
 * see eval.h
 */

#define LINEBUFSIZE 501
int eval(const char *arg, char **buf, char **errstr)
{
    FILE *f;
    size_t bufsize;
    size_t len;

    *buf = NULL;
    *errstr = NULL;
    errno = 0;
    bufsize = 1; /* Account for the null character. */

    if (!(f = popen(arg, "r")))
    {
        if (errno == 0)
        {
            errno = ENOMEM;
        }
        *errstr = xasprintf(_("cannot evaluate '%s': %s"), arg, strerror(errno));
        return 1;
    }

    do
    {
        bufsize += LINEBUFSIZE;
        *buf = xrealloc(*buf, bufsize);
        if (!fgets(&(*buf)[bufsize - LINEBUFSIZE - 1], LINEBUFSIZE + 1, f))
        {
            *errstr = xasprintf(_("cannot read output of '%s'"), arg);
            pclose(f);
            free(*buf);
            *buf = NULL;
            return 1;
        }
        len = strlen(*buf);
        if (len > 0 && (*buf)[len - 1] == '\n')
        {
            /* Read only the first line. */
            break;
        }
    }
    while (!feof(f));
    pclose(f);

    if (len > 0 && (*buf)[len - 1] == '\n')
    {
        (*buf)[len - 1] = '\0';
        if (len - 1 > 0 && (*buf)[len - 2] == '\r')
        {
            (*buf)[len - 2] = '\0';
        }
    }

    return 0;
}
