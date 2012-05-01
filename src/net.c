/*
 * net.c
 *
 * This file is part of msmtp, an SMTP client.
 *
 * Copyright (C) 2000, 2003, 2004, 2005, 2006, 2007, 2008, 2012
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
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif
#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif
#ifdef W32_NATIVE
# define WIN32_LEAN_AND_MEAN    /* do not include more than necessary */
# define _WIN32_WINNT 0x0502    /* Windows XP SP2 or later */
# include <winsock2.h>
# include <ws2tcpip.h>
#endif

#ifdef HAVE_LIBIDN
# include <idna.h>
#endif

#include "gettext.h"
#define _(string) gettext(string)

#include "xalloc.h"
#include "readbuf.h"
#include "net.h"


/*
 * [Windows only] wsa_strerror()
 *
 * This function translates WSA error codes to strings.
 * It should translate all codes that could be caused by the Windows socket
 * functions used in this file:
 * WSAStartup, getaddrinfo() or gethostbyname(), socket(), connect(),
 * recv(), send()
 */

#ifdef W32_NATIVE
const char *wsa_strerror(int error_code)
{
    switch (error_code)
    {
        case WSA_NOT_ENOUGH_MEMORY:
            return _("not enough memory");

        case WSAEINTR:
            return _("operation aborted");

        case WSAEINVAL:
            return _("invalid argument");

        case WSATYPE_NOT_FOUND:
            return _("class type not found");

        case WSAENETDOWN:
            return _("the network subsystem has failed");

        case WSAHOST_NOT_FOUND:
            return _("host not found (authoritative)");

        case WSATRY_AGAIN:
            return _("host not found (nonauthoritative) or server failure");

        case WSANO_RECOVERY:
            return _("nonrecoverable error");

        case WSANO_DATA:
            return _("valid name, but no data record of requested type");

        case WSAEAFNOSUPPORT:
            return _("address family not supported");

        case WSAEMFILE:
            return _("no socket descriptors available");

        case WSAENOBUFS:
            return _("no buffer space available");

        case WSAEPROTONOSUPPORT:
            return _("protocol not supported");

        case WSAEPROTOTYPE:
            return _("wrong protocol type for this socket");

        case WSAESOCKTNOSUPPORT:
            return _("socket type is not supported in this address family");

        case WSAEADDRNOTAVAIL:
            return _("remote address is not valid");

        case WSAECONNREFUSED:
            return _("connection refused");

        case WSAENETUNREACH:
            return _("network unreachable");

        case WSAETIMEDOUT:
            return _("timeout");

        case WSAENOTCONN:
            return _("socket not connected");

        case WSAESHUTDOWN:
            return _("the socket was shut down");

        case WSAEHOSTUNREACH:
            return _("host unreachable");

        case WSAECONNRESET:
            return _("connection reset by peer");

        case WSASYSNOTREADY:
            return _("the underlying network subsystem is not ready");

        case WSAVERNOTSUPPORTED:
            return _("the requested version is not available");

        case WSAEINPROGRESS:
            return _("a blocking operation is in progress");

        case WSAEPROCLIM:
            return _("limit on the number of tasks has been reached");

        case WSAEFAULT:
            return _("invalid request");

        default:
            return _("unknown error");
    }
}
#endif /* W32_NATIVE */


/*
 * net_lib_init()
 *
 * see net.h
 */

int net_lib_init(char **errstr)
{
#ifdef W32_NATIVE
    WORD wVersionRequested;
    WSADATA wsaData;
    int error_code;

    wVersionRequested = MAKEWORD(2, 0);
    if ((error_code = WSAStartup(wVersionRequested, &wsaData)) != 0)
    {
        *errstr = xasprintf("%s", wsa_strerror(error_code));
        return NET_ELIBFAILED;
    }
    else
    {
        return NET_EOK;
    }
#else /* noone else needs this... */
    (void)errstr;
    return NET_EOK;
#endif
}


/*
 * net_close_socket()
 *
 * This function is needed because Windows cannot just close() a socket.
 *
 * see net.h
 */

void net_close_socket(int fd)
{
#ifdef W32_NATIVE
    (void)closesocket(fd);
#else
    (void)close(fd);
#endif
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
#ifdef W32_NATIVE
    DWORD milliseconds;

    if (seconds > 0)
    {
        milliseconds = seconds * 1000;
        (void)setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &milliseconds, sizeof(int));
        (void)setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &milliseconds, sizeof(int));
    }
#else /* UNIX or DJGPP */
    struct timeval tv;

    if (seconds > 0)
    {
        tv.tv_sec = seconds;
        tv.tv_usec = 0;
        (void)setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        (void)setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }
#endif
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
    int failure_errno;
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
#ifdef W32_NATIVE
        *errstr = xasprintf(_("cannot locate host %s: %s"),
                hostname, wsa_strerror(WSAGetLastError()));
#else
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
#endif
        return NET_EHOSTNOTFOUND;
    }

    fd = -1;
    cause = 0;
    failure_errno = 0;
    for (res = res0; res; res = res->ai_next)
    {
        fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (fd < 0)
        {
            cause = 1;
#ifdef W32_NATIVE
            failure_errno = WSAGetLastError();
#else
            failure_errno = errno;
#endif
            continue;
        }
        if (net_connect(fd, res->ai_addr, res->ai_addrlen, timeout) < 0)
        {
            cause = 2;
#ifdef W32_NATIVE
            if (WSAGetLastError() != WSAENETUNREACH)
            {
                failure_errno = WSAGetLastError();
            }
#else
            if (errno != ENETUNREACH)
            {
                failure_errno = errno;
            }
#endif
            close(fd);
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
            *errstr = xasprintf(_("cannot create socket: %s"),
#ifdef W32_NATIVE
                    wsa_strerror(failure_errno)
#else
                    strerror(failure_errno)
#endif
                    );
            return NET_ESOCKET;
        }
        else /* cause == 2 */
        {
#ifdef W32_NATIVE
            if (failure_errno == 0)
            {
                failure_errno = WSAENETUNREACH;
            }
            *errstr = xasprintf(_("cannot connect to %s, port %d: %s"),
                    hostname, port, wsa_strerror(failure_errno));
#else
            if (failure_errno == EINTR)
            {
                *errstr = xasprintf(_("operation aborted"));
            }
            else
            {
                if (failure_errno == 0)
                {
                    failure_errno = ENETUNREACH;
                }
                *errstr = xasprintf(_("cannot connect to %s, port %d: %s"),
                        hostname, port, strerror(failure_errno));
            }
#endif
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
#ifdef W32_NATIVE

    int e;

    if (readbuf->count <= 0)
    {
        readbuf->count = recv(fd, readbuf->buf, sizeof(readbuf->buf), 0);
        if (readbuf->count < 0)
        {
            e = WSAGetLastError();
            if (e == WSAEWOULDBLOCK)
            {
                *errstr = xasprintf(_("network read error: %s"),
                        _("the operation timed out"));
            }
            else
            {
                *errstr = xasprintf(_("network read error: %s"),
                        wsa_strerror(e));
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

#else /* !W32_NATIVE */

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

#endif
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
#ifdef W32_NATIVE

    int e, ret;

    if (len < 1)
    {
        return NET_EOK;
    }
    if ((ret = send(fd, s, len, 0)) < 0)
    {
        e = WSAGetLastError();
        if (e == WSAEWOULDBLOCK)
        {
            *errstr = xasprintf(_("network write error: %s"),
                    _("the operation timed out"));
        }
        else
        {
            *errstr = xasprintf(_("network write error: %s"),
                    wsa_strerror(e));
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

#else /* !W32_NATIVE */

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

#endif
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
#ifdef W32_NATIVE
    (void)WSACleanup();
#endif
}
