/*
 * readbuf.h
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

#ifndef READBUF_H
#define READBUF_H

typedef struct
{
    int count;
    char *ptr;
    char buf[4096];
} readbuf_t;

/*
 * readbuf_init()
 *
 * Initialize a readbuf_t for first use.
 */
void readbuf_init(readbuf_t *readbuf);

/*
 * readbuf_is_empty()
 *
 * Returns true if readbuf is empty, false otherwise.
 */
int readbuf_is_empty(const readbuf_t *readbuf);

#endif
