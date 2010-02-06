/*
 * net.c
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


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#ifdef HAVE_LIBIDN
# include <idna.h>
#endif

#include "sockets.h"

#include "gettext.h"
#include "xalloc.h"
#include "xvasprintf.h"

#include "readbuf.h"
#include "net.h"


/*
 * net_lib_init()
 *
 * see net.h
 */

int net_lib_init(char **errstr)
{
    if (gl_sockets_startup(SOCKETS_2_2) != 0)
    {
        *errstr = xasprintf("cannot initialize networking");
        return NET_ELIBFAILED;
    }
    return NET_EOK;
}


/*
 * net_connect()
 *
 * connect() with timeout.
 *
 * This function is equivalent to connect(), except that a connection attempt
 * times out after 'timeout' seconds instead of the OS dependant default value.
 * A 'timeout' <= 0 will be ignored.
 */

int net_connect(int fd, const struct sockaddr *serv_addr, socklen_t addrlen,
        int timeout)
{
#ifdef W32_NATIVE
    /* TODO: I don't know how to do this on Win32. Please send a patch. */
    return connect(fd, serv_addr, addrlen);
#else /* UNIX or DJGPP */

    int flags;
    struct timeval tv;
    fd_set rset;
    fd_set wset;
    int err;
    socklen_t optlen;

    if (timeout <= 0)
    {
        return connect(fd, serv_addr, addrlen);
    }
    else
    {
        /* make socket non-blocking */
        flags = fcntl(fd, F_GETFL, 0);
        if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
        {
            return -1;
        }

        /* start connect */
        if (connect(fd, serv_addr, addrlen) < 0)
        {
            if (errno != EINPROGRESS)
            {
                return -1;
            }

            tv.tv_sec = timeout;
            tv.tv_usec = 0;
            FD_ZERO(&rset);
            FD_ZERO(&wset);
            FD_SET(fd, &rset);
            FD_SET(fd, &wset);

            /* wait for connect() to finish */
            if ((err = select(fd + 1, &rset, &wset, NULL, &tv)) <= 0)
            {
                /* errno is already set if err < 0 */
                if (err == 0)
                {
                    errno = ETIMEDOUT;
                }
                return -1;
            }

            /* test for success, set errno */
            optlen = sizeof(int);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &optlen) < 0)
            {
                return -1;
            }
            if (err != 0)
            {
                errno = err;
                return -1;
            }
        }

        /* restore blocking mode */
        if (fcntl(fd, F_SETFL, flags) == -1)
        {
            return -1;
        }

        return 0;
    }
#endif /* UNIX */
}


/*
 * net_set_io_timeout()
 *
 * Sets a timeout for inout/output operations on the given socket.
 */

void net_set_io_timeout(int socket, int seconds)
{
    struct timeval tv;

    if (seconds > 0)
    {
        tv.tv_sec = seconds;
        tv.tv_usec = 0;
        (void)setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        (void)setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }
}


/*
 * open_socket()
 *
 * see net.h
 */

int net_open_socket(const char *hostname, int port, int timeout, int *ret_fd,
        char **canonical_name, char **address, char **errstr)
{
    int fd;
    char *port_string;
    struct addrinfo hints;
    struct addrinfo *res0;
    struct addrinfo *res;
    int error_code;
    int saved_errno;
    int cause;
    char nameinfo_buffer[NI_MAXHOST];
#ifdef HAVE_LIBIDN
    char *hostname_ascii;
#endif

    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;
    hints.ai_addrlen = 0;
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;
    port_string = xasprintf("%d", port);
#ifdef HAVE_LIBIDN
    if (idna_to_ascii_lz(hostname, &hostname_ascii, 0) != IDNA_SUCCESS)
    {
        hostname_ascii = xstrdup(hostname);
    }
    error_code = getaddrinfo(hostname_ascii, port_string, &hints, &res0);
    free(hostname_ascii);
#else
    error_code = getaddrinfo(hostname, port_string, &hints, &res0);
#endif
    free(port_string);
    if (error_code)
    {
        if (error_code == EAI_SYSTEM && errno == EINTR)
        {
            *errstr = xasprintf(_("operation aborted"));
        }
        else
        {
            *errstr = xasprintf(_("cannot locate host %s: %s"), hostname,
                    error_code == EAI_SYSTEM ? strerror(errno)
                    : gai_strerror(error_code));
        }
        return NET_EHOSTNOTFOUND;
    }

    fd = -1;
    cause = 0;
    for (res = res0; res; res = res->ai_next)
    {
        fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (fd < 0)
        {
            cause = 1;
            continue;
        }
        if (net_connect(fd, res->ai_addr, res->ai_addrlen, timeout) < 0)
        {
            cause = 2;
            saved_errno = errno;
            close(fd);
            errno = saved_errno;
            fd = -1;
            continue;
        }
        break;
    }

    if (fd >= 0)
    {
        if (canonical_name)
        {
            if (getnameinfo(res->ai_addr, res->ai_addrlen, nameinfo_buffer,
                        sizeof(nameinfo_buffer), NULL, 0, NI_NAMEREQD) == 0)
            {
                *canonical_name = xstrdup(nameinfo_buffer);
            }
            else
            {
                *canonical_name = NULL;
            }
        }
        if (address)
        {
            if (getnameinfo(res->ai_addr, res->ai_addrlen, nameinfo_buffer,
                        sizeof(nameinfo_buffer), NULL, 0, NI_NUMERICHOST) == 0)
            {
                *address = xstrdup(nameinfo_buffer);
            }
            else
            {
                *address = NULL;
            }
        }
    }

    freeaddrinfo(res0);

    if (fd < 0)
    {
        if (cause == 1)
        {
            *errstr = xasprintf(_("cannot create socket: %s"), strerror(errno));
            return NET_ESOCKET;
        }
        else /* cause == 2 */
        {
            if (errno == EINTR)
            {
                *errstr = xasprintf(_("operation aborted"));
            }
            else
            {
                *errstr = xasprintf(_("cannot connect to %s, port %d: %s"),
                        hostname, port, strerror(errno));
            }
            return NET_ECONNECT;
        }
    }

    net_set_io_timeout(fd, timeout);
    *ret_fd = fd;
    return NET_EOK;
}


/*
 * net_readbuf_read()
 *
 * Wraps read() to provide buffering for net_gets().
 */

int net_readbuf_read(int fd, readbuf_t *readbuf, char *ptr,
        char **errstr)
{
    if (readbuf->count <= 0)
    {
        readbuf->count = (int)recv(fd, readbuf->buf, sizeof(readbuf->buf), 0);
        if (readbuf->count < 0)
        {
            if (errno == EINTR)
            {
                *errstr = xasprintf(_("operation aborted"));
            }
            else if (errno == EAGAIN)
            {
                *errstr = xasprintf(_("network read error: %s"),
                        _("the operation timed out"));
            }
            else
            {
                *errstr = xasprintf(_("network read error: %s"),
                        strerror(errno));
            }
            return -1;
        }
        else if (readbuf->count == 0)
        {
            return 0;
        }
        readbuf->ptr = readbuf->buf;
    }
    readbuf->count--;
    *ptr = *((readbuf->ptr)++);
    return 1;
}


/*
 * net_gets()
 *
 * see net.h
 */

int net_gets(int fd, readbuf_t *readbuf,
        char *str, size_t size, size_t *len, char **errstr)
{
    char c;
    size_t i;
    int ret;

    i = 0;
    while (i + 1 < size)
    {
        if ((ret = net_readbuf_read(fd, readbuf, &c, errstr)) == 1)
        {
            str[i++] = c;
            if (c == '\n')
            {
                break;
            }
        }
        else if (ret == 0)
        {
            break;
        }
        else
        {
            return NET_EIO;
        }
    }
    str[i] = '\0';
    *len = i;
    return NET_EOK;
}


/*
 * net_puts()
 *
 * see net.h
 */

int net_puts(int fd, const char *s, size_t len, char **errstr)
{
    ssize_t ret;

    if (len < 1)
    {
        return NET_EOK;
    }
    if ((ret = send(fd, s, len, 0)) < 0)
    {
        if (errno == EINTR)
        {
            *errstr = xasprintf(_("operation aborted"));
        }
        else if (errno == EAGAIN)
        {
            *errstr = xasprintf(_("network write error: %s"),
                    _("the operation timed out"));
        }
        else
        {
            *errstr = xasprintf(_("network write error: %s"),
                    strerror(errno));
        }
        return NET_EIO;
    }
    else if ((size_t)ret == len)
    {
        return NET_EOK;
    }
    else /* 0 <= error_code < len */
    {
        *errstr = xasprintf(_("network write error"));
        return NET_EIO;
    }
}


/*
 * net_get_canonical_hostname()
 *
 * see net.h
 */

char *net_get_canonical_hostname(void)
{
    char hostname[256];
    char *canonname = NULL;
    struct addrinfo hints;
    struct addrinfo *res0;

    if (gethostname(hostname, 256) == 0)
    {
        /* Make sure the hostname is NUL-terminated. */
        hostname[255] = '\0';
        hints.ai_family = PF_UNSPEC;
        hints.ai_socktype = 0;
        hints.ai_flags = AI_CANONNAME;
        hints.ai_protocol = 0;
        hints.ai_addrlen = 0;
        hints.ai_canonname = NULL;
        hints.ai_addr = NULL;
        hints.ai_next = NULL;
        if (getaddrinfo(hostname, NULL, &hints, &res0) == 0)
        {
            if (res0->ai_canonname)
            {
                canonname = xstrdup(res0->ai_canonname);
            }
            freeaddrinfo(res0);
        }
    }

    if (!canonname)
    {
        canonname = xstrdup("localhost");
    }

    return canonname;
}


/*
 * net_lib_deinit()
 *
 * see net.h
 */

void net_lib_deinit(void)
{
    (void)gl_sockets_cleanup();
}
