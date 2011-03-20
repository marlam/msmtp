/*
 * stream.c
 *
 * This file is part of msmtp, an SMTP client.
 *
 * Copyright (C) 2005, 2007
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

#include "gettext.h"
#define _(string) gettext(string)

#include "xalloc.h"
#include "stream.h"


/*
 * stream_gets()
 *
 * see stream.h
 */

int stream_gets(FILE *f, char *str, size_t size, size_t *len, char **errstr)
{
    char c;
    size_t i;

    i = 0;
    while (i + 1 < size)
    {
        if (fread(&c, sizeof(char), 1, f) == 1)
        {
            str[i++] = c;
            if (c == '\n')
            {
                break;
            }
        }
        else
        {
            if (ferror(f))
            {
                *errstr = xasprintf(_("input error"));
                return STREAM_EIO;
            }
            else /* EOF */
            {
                break;
            }
        }
    }
    str[i] = '\0';
    *len = i;
    return STREAM_EOK;
}
