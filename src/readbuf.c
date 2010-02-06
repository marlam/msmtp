/*
 * readbuf.c
 *
 * This file is part of msmtp, an SMTP client.
 *
 * Copyright (C) 2008
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

#include "readbuf.h"


/*
 * readbuf_init()
 *
 * see readbuf.h
 */

void readbuf_init(readbuf_t *readbuf)
{
    readbuf->count = 0;
    readbuf->ptr = readbuf->buf;
}


/*
 * readbuf_is_empty()
 *
 * see readbuf.h
 */

int readbuf_is_empty(const readbuf_t *readbuf)
{
    return (readbuf->count == 0);
}
