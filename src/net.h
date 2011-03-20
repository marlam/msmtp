/*
 * net.h
 *
 * This file is part of msmtp, an SMTP client.
 *
 * Copyright (C) 2000, 2003, 2004, 2005, 2006, 2007, 2008
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

#ifndef NET_H
#define NET_H

#include "readbuf.h"


/*
 * If a function with an 'errstr' argument returns a value != NET_EOK,
 * '*errstr' either points to an allocates string containing an error
 * description or is NULL.
 * If such a function returns NET_EOK, 'errstr' will not be changed.
 */
#define NET_EOK                 0       /* no error */
#define NET_ELIBFAILED          1       /* The underlying library failed */
#define NET_EHOSTNOTFOUND       2       /* Host not found */
#define NET_ESOCKET             3       /* Cannot create socket */
#define NET_ECONNECT            4       /* Cannot connect */
#define NET_EIO                 5       /* Input/output error */

/*
 * net_lib_init()
 *
 * Initializes the networking libraries. If this function returns
 * NET_ELIBFAILED, *errstr will always point to an error string.
 * Used error codes: NET_ELIBFAILED
 */
int net_lib_init(char **errstr);

/*
 * net_open_socket()
 *
 * Opens a TCP socket to 'hostname':'port'.
 * 'hostname' may be a host name or a network address.
 * 'timeout' is measured in secondes. If it is <= 0, no timeout will be set,
 * which means that the OS dependent default timeout value will be used.
 * The timeout will not only apply to the connection attempt but also to all
 * following read/write operations on the socket.
 * If 'canonical_name' is not NULL, a pointer to a string containing the
 * canonical hostname of the server will be stored in '*canonical_name', or NULL
 * if this information is not available.
 * If 'address' is not NULL, a pointer to a string containing the network
 * address of the server will be stored in '*address', or NULL if this
 * information is not available.
 * The strings must be deallocated when not used anymore.
 * The file descriptor is returned in 'fd'. It can be closed with close().
 *
 * Used error codes: NET_EHOSTNOTFOUND, NET_ESOCKET, NET_ECONNECT
 */
int net_open_socket(const char *hostname, int port, int timeout, int *fd,
        char **canonical_name, char **address, char **errstr);

/*
 * net_gets()
 *
 * Reads in at most one less than 'size' characters from 'fd' and stores them
 * into the buffer pointed to by 'str'. Reading stops after an EOF or a newline.
 * If a newline is read, it is stored into the buffer. A '\0' is stored after
 * the last character in the buffer. The length of the resulting string (the
 * number of characters excluding the terminating '\0') will be stored in 'len'.
 * 'readbuf' will be used as an input buffer and must of course be the same for
 * all read operations on 'fd'.
 * Used error codes: NET_EIO
 */
int net_gets(int fd, readbuf_t *readbuf,
        char *str, size_t size, size_t *len, char **errstr);

/*
 * net_puts()
 *
 * Writes 'len' characters from the string 's' to 'fd'.
 * Used error codes: NET_EIO
 */
int net_puts(int fd, const char *s, size_t len, char **errstr);

/*
 * net_close_socket()
 *
 * Closes a socket.
 */
void net_close_socket(int fd);

/*
 * net_get_canonical_hostname()
 *
 * Get a canonical name of this host. This means that the name is meaningful to
 * other hosts. Usually, it is the fully qualified domain name of this host.
 */
char *net_get_canonical_hostname(void);

/*
 * net_lib_deinit()
 *
 * Deinit networking library
 */
void net_lib_deinit(void);

#endif
