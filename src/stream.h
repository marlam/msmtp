/*
 * stream.h
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

#ifndef STREAM_H
#define STREAM_H

#include <stdio.h>


/*
 * If a function with an 'errstr' argument returns a value != STREAM_EOK,
 * '*errstr' either points to an allocates string containing an error
 * description or is NULL.
 * If such a function returns STREAM_EOK, 'errstr' will not be changed.
 */
#define STREAM_EOK              0       /* no error */
#define STREAM_EIO              1       /* Input/output error */

/*
 * stream_gets()
 *
 * Reads in at most one less than 'size' characters from 'f' and stores them
 * into the buffer pointed to by 'str'. Reading stops after an EOF or a newline.
 * If a newline is read, it is stored into the buffer. A '\0' is stored after
 * the last character in the buffer. The length of the resulting string (the
 * number of characters excluding the terminating '\0') will be stored in 'len'.
 * Used error codes: STREAM_EIO
 */
int stream_gets(FILE *f, char *str, size_t size, size_t *len, char **errstr);

#endif
