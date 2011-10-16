/*
 * smtp.c
 *
 * This file is part of msmtp, an SMTP client.
 *
 * Copyright (C) 2000, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011
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
#include <limits.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>

#ifdef HAVE_LIBGSASL
# include <gsasl.h>
#else
# include "base64.h"
# include "md5-apps.h"
#endif

#include "gettext.h"
#define _(string) gettext(string)

#include "xalloc.h"
#include "list.h"
#include "readbuf.h"
#include "net.h"
#include "smtp.h"
#include "stream.h"
#ifdef HAVE_TLS
#include "tls.h"
#endif /* HAVE_TLS */


/* This defines the maximum number of lines in a multiline server reply.
 * This limit exists to prevent an extremely long reply from eating
 * all the memory.
 * The longest server reply we have to expect is the repsonse to the EHLO
 * command. We should have enough lines for every SMTP extension known today
 * plus more lines for future extensions.
 */
#define SMTP_MAXLINES 50

/* This defines the length of the *input* buffer for SMTP messages.
 * According to RFC 2821, SMTP commands and SMTP messages may contain
 * at most 512 characters including CRLF, thus the *minimum* size is
 * 512 characters.
 */
#define SMTP_BUFSIZE 1024

/* This defines the length of the *output* buffer for SMTP commands, without
 * CRLF. According to RFC 2821, SMTP commands may contain at most 512
 * characters including CRLF, thus the maximum size should be 510 characters.
 * But this is not sufficient for some authentication mechanisms, notably
 * GSSAPI, so this value must be higher.
 */
#define SMTP_MAXCMDLEN 4094

/* The maximum length of the SMTP command pipeline (the maximum number of
 * commands that are sent at once, before starting to read the replies). This
 * number should be large enough to keep the benefits of pipelining (saved round
 * trips), and small enough to avoid problems (exceeding the TCP window size).
 * A value of 1 disables pipelining.
 */
#define SMTP_PIPELINE_LIMIT 100

/* This is the buffer length for copying the mail to the SMTP server.
 * According to RFC 2822, a line in a mail can contain at most 998
 * characters + CRLF. Plus one character for '\0' = 1001 characters.
 * All lines should fit in a buffer of this size.
 * However, this length is not a limit; smtp_send_mail() will accept
 * arbitrary long lines.
 */
#define MAIL_BUFSIZE 1024


/*
 * smtp_new()
 *
 * see smtp.h
 */

smtp_server_t smtp_new(FILE *debug, int protocol)
{
    smtp_server_t srv;

    srv.fd = -1;
#ifdef HAVE_TLS
    tls_clear(&srv.tls);
#endif /* HAVE_TLS */
    readbuf_init(&(srv.readbuf));
    srv.protocol = protocol;
    srv.cap.flags = 0;
    srv.cap.size = 0;
    srv.debug = debug;
    return srv;
}


/*
 * smtp_connect()
 *
 * see smtp.h
 */

int smtp_connect(smtp_server_t *srv, const char *host, int port, int timeout,
        char **server_canonical_name, char **server_address,
        char **errstr)
{
    return net_open_socket(host, port, timeout, &srv->fd,
            server_canonical_name, server_address, errstr);
}


/*
 * smtp_get_msg()
 *
 * This function gets a message from the SMTP server 'srv'.
 * In case of success, 'msg' will contain a pointer to a newly created list,
 * and each member of this list will contain one line of the message as an
 * allocated string. The list will contain at least one line. Each line will
 * be at least 4 characters long: The three digit status code plus a ' ' or '-'.
 * Each line will be at most SMTP_BUFSIZE characters long, including '\0'.
 * The return code will be EOK.
 * In case of failure, 'msg' will be NULL, and one of the following error codes
 * will be returned: SMTP_EIO, SMTP_EPROTO
 */

int smtp_get_msg(smtp_server_t *srv, list_t **msg, char **errstr)
{
    list_t *l;
    list_t *lp;
    char line[SMTP_BUFSIZE];
    int counter;
    size_t len;

    *msg = NULL;
    l = list_new();
    lp = l;

    counter = 0;
    do
    {
#ifdef HAVE_TLS
        if (tls_is_active(&srv->tls))
        {
            if (tls_gets(&srv->tls, &(srv->readbuf),
                        line, SMTP_BUFSIZE, &len, errstr) != TLS_EOK)
            {
                list_xfree(l, free);
                return SMTP_EIO;
            }
        }
        else
        {
#endif /* HAVE_TLS */
            if (net_gets(srv->fd, &(srv->readbuf),
                        line, SMTP_BUFSIZE, &len, errstr) != NET_EOK)
            {
                list_xfree(l, free);
                return SMTP_EIO;
            }
#ifdef HAVE_TLS
        }
#endif /* HAVE_TLS */
        if (len < 4
                || !(isdigit((unsigned char)line[0])
                    && isdigit((unsigned char)line[1])
                    && isdigit((unsigned char)line[2])
                    && (line[3] == ' ' || line[3] == '-'))
                || line[len - 1] != '\n')
        {
            list_xfree(l, free);
            /* The string is not necessarily a reply (it may be the initial OK
             * message), but this is the term used in the RFCs.
             * An empty reply is a special case of an invalid reply - this
             * differentiation may help the user. */
            if (counter == 0 && len == 0)
            {
                *errstr = xasprintf(_("the server sent an empty reply"));
            }
            else
            {
                *errstr = xasprintf(_("the server sent an invalid reply"));
            }
            return SMTP_EPROTO;
        }
        if (srv->debug)
        {
            fputs("<-- ", srv->debug);
            fwrite(line, sizeof(char), len, srv->debug);
        }
        /* kill CRLF */
        line[--len] = '\0';
        if (line[len - 1] == '\r')
        {
            line[--len] = '\0';
        }
        list_insert(lp, xstrdup(line));
        counter++;
        lp = lp->next;
    }
    while (line[3] == '-' && counter <= SMTP_MAXLINES);

    if (counter > SMTP_MAXLINES)
    {
        list_xfree(l, free);
        *errstr = xasprintf(_("Rejecting server reply that is longer "
                    "than %d lines. Increase SMTP_MAXLINES."), SMTP_MAXLINES);
        return SMTP_EPROTO;
    }

    *msg = l;
    return SMTP_EOK;
}


/*
 * smtp_msg_status()
 *
 * see smtp.h
 */

int smtp_msg_status(list_t *msg)
{
    /* we know that *msg is valid; there's no need to check for errors */
    return atoi(msg->next->data);
}


/*
 * smtp_put()
 *
 * This function writes 'len' characters from 's' to the SMTP server 'srv'.
 * Used error codes: SMTP_EIO
 */

int smtp_put(smtp_server_t *srv, const char *s, size_t len, char **errstr)
{
    int e = 0;

#ifdef HAVE_TLS
    if (tls_is_active(&srv->tls))
    {
        e = (tls_puts(&srv->tls, s, len, errstr) != TLS_EOK);
    }
    else
    {
#endif /* HAVE_TLS */
        e = (net_puts(srv->fd, s, len, errstr) != NET_EOK);
#ifdef HAVE_TLS
    }
#endif /* HAVE_TLS */
    if (e)
    {
        return SMTP_EIO;
    }
    if (srv->debug)
    {
        fputs("--> ", srv->debug);
        fwrite(s, sizeof(char), len, srv->debug);
    }

    return SMTP_EOK;
}


/*
 * smtp_send_cmd()
 *
 * This function writes a string to the SMTP server 'srv'. The string may not
 * be longer than SMTP_MAXCMDLEN characters (see above). TCP CRLF ('\r\n') will
 * be appended to the string. Use this function to send SMTP commands (not mail
 * data) to the SMTP server.
 * Used error codes: SMTP_EIO, SMTP_EINVAL
 */

/* make gcc print format warnings for this function */
#ifdef __GNUC__
int smtp_send_cmd(smtp_server_t *srv, char **errstr, const char *format, ...)
    __attribute__ ((format (printf, 3, 4)));
#endif

int smtp_send_cmd(smtp_server_t *srv, char **errstr, const char *format, ...)
{
    char line[SMTP_MAXCMDLEN + 3];
    int count;
    va_list args;

    va_start(args, format);
    count = vsnprintf(line, SMTP_MAXCMDLEN + 1, format, args);
    va_end(args);
    if (count >= SMTP_MAXCMDLEN + 1)
    {
        *errstr = xasprintf(_("Cannot send command because it is "
                "longer than %d characters. Increase SMTP_MAXCMDLEN."),
                SMTP_MAXCMDLEN);
        return SMTP_EINVAL;
    }
    line[count++] = '\r';
    line[count++] = '\n';
    line[count] = '\0';
    return smtp_put(srv, line, (size_t)count, errstr);
}


/*
 * smtp_get_greeting()
 *
 * see smtp.h
 */

int smtp_get_greeting(smtp_server_t *srv, list_t **errmsg, char **buf,
        char **errstr)
{
    int e;
    list_t *msg;

    *errmsg = NULL;
    if ((e = smtp_get_msg(srv, &msg, errstr)) != SMTP_EOK)
    {
        return e;
    }
    if (smtp_msg_status(msg) != 220)
    {
        *errmsg = msg;
        *errstr = xasprintf(_("cannot get initial OK message from server"));
        return SMTP_EPROTO;
    }
    if (buf)
    {
        *buf = xmalloc(
                (strlen((char *)msg->next->data + 4) + 1) * sizeof(char));
        strcpy(*buf, (char *)(msg->next->data) + 4);
    }
    list_xfree(msg, free);

    return SMTP_EOK;
}


/*
 * smtp_init()
 *
 * see smtp.h
 */

int smtp_init(smtp_server_t *srv, const char *ehlo_domain, list_t **errmsg,
        char **errstr)
{
    int e;
    list_t *ehlo_response;
    list_t *lp;
    char *s;
    char *p;
    size_t len;
    int i;

    srv->cap.flags = 0;

    *errmsg = NULL;
    if (srv->protocol == SMTP_PROTO_SMTP)
    {
        if ((e = smtp_send_cmd(srv, errstr, "EHLO %s", ehlo_domain))
                != SMTP_EOK)
        {
            return e;
        }
        if ((e = smtp_get_msg(srv, &ehlo_response, errstr)) != SMTP_EOK)
        {
            return e;
        }
        if (smtp_msg_status(ehlo_response) != 250)
        {
            /* fall back to HELO, for very old SMTP servers */
            list_xfree(ehlo_response, free);
            if ((e = smtp_send_cmd(srv, errstr, "HELO %s", ehlo_domain))
                    != SMTP_EOK)
            {
                return e;
            }
            if ((e = smtp_get_msg(srv, &ehlo_response, errstr)) != SMTP_EOK)
            {
                return e;
            }
            if (smtp_msg_status(ehlo_response) != 250)
            {
                *errmsg = ehlo_response;
                *errstr = xasprintf(_("SMTP server does not accept "
                            "EHLO or HELO commands"));
                return SMTP_EPROTO;
            }
            list_xfree(ehlo_response, free);
            /* srv->cap.flags is 0 */
            return SMTP_EOK;
        }
    }
    else /* protocol is LMTP */
    {
        if ((e = smtp_send_cmd(srv, errstr, "LHLO %s", ehlo_domain))
                != SMTP_EOK)
        {
            return e;
        }
        if ((e = smtp_get_msg(srv, &ehlo_response, errstr)) != SMTP_EOK)
        {
            return e;
        }
        if (smtp_msg_status(ehlo_response) != 250)
        {
            *errmsg = ehlo_response;
            *errstr = xasprintf(_("command %s failed"), "LHLO");
            return SMTP_EPROTO;
        }
    }

    lp = ehlo_response;
    while (!list_is_empty(lp))
    {
        lp = lp->next;
        s = lp->data;
        len = strlen(s);
        /* we know that len is >= 4 */
        /* make line uppercase */
        for (i = 4; (size_t)i < len; i++)
        {
            s[i] = toupper((unsigned char)s[i]);
        }
        /* search capabilities */
        if (strncmp(s + 4, "STARTTLS", 8) == 0)
        {
            srv->cap.flags |= SMTP_CAP_STARTTLS;
        }
        else if (strncmp(s + 4, "DSN", 3) == 0)
        {
            srv->cap.flags |= SMTP_CAP_DSN;
        }
        else if (strncmp(s + 4, "PIPELINING", 10) == 0)
        {
            srv->cap.flags |= SMTP_CAP_PIPELINING;
        }
        else if (strncmp(s + 4, "SIZE", 4) == 0)
        {
            /* If there's no number after the SIZE keyword, the server does not
             * tell us about a maximum message size. Treat that as if the SIZE
             * keyword was not seen. Also treat invalid numbers the same way.
             * The value 0 means there is no maximum.
             * See RFC 1653. */
            errno = 0;
            srv->cap.size = strtol(s + 8, &p, 10);
            if (!(*(s + 8) == '\0' || *p != '\0' || srv->cap.size < 0
                    || (srv->cap.size == LONG_MAX && errno == ERANGE)))
            {
                srv->cap.flags |= SMTP_CAP_SIZE;
            }
        }
        /* Accept "AUTH " as well as "AUTH=". There are still some broken
         * servers that use "AUTH=". */
        else if (strncmp(s + 4, "AUTH", 4) == 0
                && (*(s + 8) == ' ' || *(s + 8) == '='))
        {
            srv->cap.flags |= SMTP_CAP_AUTH;
            if (strstr(s + 9, "PLAIN"))
            {
                srv->cap.flags |= SMTP_CAP_AUTH_PLAIN;
            }
            if (strstr(s + 9, "CRAM-MD5"))
            {
                srv->cap.flags |= SMTP_CAP_AUTH_CRAM_MD5;
            }
            if (strstr(s + 9, "DIGEST-MD5"))
            {
                srv->cap.flags |= SMTP_CAP_AUTH_DIGEST_MD5;
            }
            if (strstr(s + 9, "SCRAM-SHA-1"))
            {
                srv->cap.flags |= SMTP_CAP_AUTH_SCRAM_SHA_1;
            }
            if (strstr(s + 9, "GSSAPI"))
            {
                srv->cap.flags |= SMTP_CAP_AUTH_GSSAPI;
            }
            if (strstr(s + 9, "EXTERNAL"))
            {
                srv->cap.flags |= SMTP_CAP_AUTH_EXTERNAL;
            }
            if (strstr(s + 9, "LOGIN"))
            {
                srv->cap.flags |= SMTP_CAP_AUTH_LOGIN;
            }
            if (strstr(s + 9, "NTLM"))
            {
                srv->cap.flags |= SMTP_CAP_AUTH_NTLM;
            }
        }
        else if (strncmp(s + 4, "ETRN", 4) == 0)
        {
            srv->cap.flags |= SMTP_CAP_ETRN;
        }
    }

    list_xfree(ehlo_response, free);
    return SMTP_EOK;
}


/*
 * smtp_tls_init()
 *
 * see smtp.h
 */

#ifdef HAVE_TLS
int smtp_tls_init(smtp_server_t *srv,
        const char *tls_key_file, const char *tls_cert_file,
        const char *tls_trust_file, const char *tls_crl_file,
        const unsigned char *tls_sha1_fingerprint,
        const unsigned char *tls_md5_fingerprint,
        int force_sslv3, int min_dh_prime_bits,
        const char *priorities, char **errstr)
{
    return tls_init(&srv->tls, tls_key_file, tls_cert_file,
            tls_trust_file, tls_crl_file,
            tls_sha1_fingerprint, tls_md5_fingerprint,
            force_sslv3, min_dh_prime_bits, priorities, errstr);
}
#endif /* HAVE_TLS */


/*
 * smtp_tls_starttls()
 *
 * see smtp.h
 */

#ifdef HAVE_TLS
int smtp_tls_starttls(smtp_server_t *srv, list_t **error_msg, char **errstr)
{
    int e;
    list_t *msg;

    *error_msg = NULL;
    if ((e = smtp_send_cmd(srv, errstr, "STARTTLS")) != SMTP_EOK)
    {
        return e;
    }
    if ((e = smtp_get_msg(srv, &msg, errstr)) != SMTP_EOK)
    {
        return e;
    }
    if (smtp_msg_status(msg) != 220)
    {
        *error_msg = msg;
        *errstr = xasprintf(_("command %s failed"), "STARTTLS");
        return SMTP_EPROTO;
    }
    if (!readbuf_is_empty(&(srv->readbuf)))
    {
        *errstr = xasprintf(_("command %s failed"), "STARTTLS");
        return SMTP_EPROTO;
    }
    list_xfree(msg, free);
    return SMTP_EOK;
}
#endif /* HAVE_TLS */


/*
 * smtp_tls()
 *
 * see smtp.h
 */

#ifdef HAVE_TLS
int smtp_tls(smtp_server_t *srv, const char *hostname, int tls_nocertcheck,
        tls_cert_info_t *tci, char **errstr)
{
    return tls_start(&srv->tls, srv->fd, hostname, tls_nocertcheck, tci,
            errstr);
}
#endif /* HAVE_TLS */


/*
 * smtp_auth_plain()
 *
 * Do SMTP authentication via AUTH PLAIN.
 * The SMTP server must support SMTP_CAP_AUTH_PLAIN
 * Used error codes: SMTP_EIO, SMTP_EPROTO, SMTP_EAUTHFAIL, SMTP_EINVAL
 */

#ifndef HAVE_LIBGSASL
int smtp_auth_plain(smtp_server_t *srv, const char *user, const char *password,
        list_t **error_msg, char **errstr)
{
    char *s;
    char *b64;
    size_t u_len;
    size_t p_len;
    size_t b64_len;
    list_t *msg;
    int e;
    int status;

    *error_msg = NULL;
    u_len = strlen(user);
    p_len = strlen(password);
    s = xmalloc((u_len + p_len + 3) * sizeof(char));
    s[0] = '\0';
    strcpy(s + 1, user);
    strcpy(s + u_len + 2, password);
    b64_len = BASE64_LENGTH(u_len + p_len + 2);
    b64 = xmalloc(b64_len + 1);
    base64_encode(s, u_len + p_len + 2, b64, b64_len + 1);
    free(s);

    if ((e = smtp_send_cmd(srv, errstr, "AUTH PLAIN %s", b64)) != SMTP_EOK)
    {
        free(b64);
        return e;
    }
    free(b64);
    if ((e = smtp_get_msg(srv, &msg, errstr)) != SMTP_EOK)
    {
        return e;
    }
    if ((status = smtp_msg_status(msg)) != 235)
    {
        *error_msg = msg;
        if (status == 504)
        {
            *errstr = xasprintf(_("command %s failed"), "AUTH PLAIN");
            return SMTP_EPROTO;
        }
        else
        {
            *errstr = xasprintf(_("authentication failed (method %s)"),
                    "PLAIN");
            return SMTP_EAUTHFAIL;
        }
    }
    list_xfree(msg, free);

    return SMTP_EOK;
}
#endif /* !HAVE_LIBGSASL */


/*
 * smtp_auth_login()
 *
 * Do SMTP authentication via AUTH LOGIN.
 * The SMTP server must support SMTP_CAP_AUTH_LOGIN
 * Used error codes: SMTP_EIO, SMTP_EPROTO, SMTP_EAUTHFAIL, SMTP_EINVAL
 */

#ifndef HAVE_LIBGSASL
int smtp_auth_login(smtp_server_t *srv, const char *user, const char *password,
        list_t **error_msg, char **errstr)
{
    int e;
    list_t *msg;
    char *b64;
    size_t b64_len;
    size_t u_len;
    size_t p_len;

    *error_msg = NULL;
    if ((e = smtp_send_cmd(srv, errstr, "AUTH LOGIN")) != SMTP_EOK)
    {
        return e;
    }
    if ((e = smtp_get_msg(srv, &msg, errstr)) != SMTP_EOK)
    {
        return e;
    }
    if (smtp_msg_status(msg) != 334)
    {
        *error_msg = msg;
        *errstr = xasprintf(_("command %s failed"), "AUTH LOGIN");
        return SMTP_EPROTO;
    }
    list_xfree(msg, free);
    u_len = strlen(user);
    b64_len = BASE64_LENGTH(u_len);
    b64 = xmalloc(b64_len + 1);
    base64_encode(user, u_len, b64, b64_len + 1);
    if ((e = smtp_send_cmd(srv, errstr, "%s", b64)) != SMTP_EOK)
    {
        free(b64);
        return e;
    }
    free(b64);
    if ((e = smtp_get_msg(srv, &msg, errstr)) != SMTP_EOK)
    {
        return e;
    }
    if (smtp_msg_status(msg) != 334)
    {
        *error_msg = msg;
        *errstr = xasprintf(_("authentication failed (method %s)"), "LOGIN");
        return SMTP_EAUTHFAIL;
    }
    list_xfree(msg, free);
    p_len = strlen(password);
    b64_len = BASE64_LENGTH(p_len);
    b64 = xmalloc(b64_len + 1);
    base64_encode(password, p_len, b64, b64_len + 1);
    if ((e = smtp_send_cmd(srv, errstr, "%s", b64)) != SMTP_EOK)
    {
        free(b64);
        return e;
    }
    free(b64);
    if ((e = smtp_get_msg(srv, &msg, errstr)) != SMTP_EOK)
    {
        return e;
    }
    if (smtp_msg_status(msg) != 235)
    {
        *error_msg = msg;
        *errstr = xasprintf(_("authentication failed (method %s)"), "LOGIN");
        return SMTP_EAUTHFAIL;
    }
    list_xfree(msg, free);

    return SMTP_EOK;
}
#endif /* !HAVE_LIBGSASL */


/*
 * smtp_auth_cram_md5()
 *
 * Do SMTP authentication via AUTH CRAM-MD5.
 * The SMTP server must support SMTP_CAP_AUTH_CRAM_MD5
 * Used error codes: SMTP_EIO, SMTP_EPROTO, SMTP_EAUTHFAIL, SMTP_EINVAL
 */

#ifndef HAVE_LIBGSASL
int smtp_auth_cram_md5(smtp_server_t *srv, const char *user,
        const char *password,
        list_t **error_msg, char **errstr)
{
    unsigned char digest[16];
    char hex[] = "0123456789abcdef";
    char *challenge;
    size_t challenge_len;
    char *b64;
    size_t b64_len;
    char *buf;
    char *p;
    size_t len;
    int i;
    list_t *msg;
    int e;

    *error_msg = NULL;
    if ((e = smtp_send_cmd(srv, errstr, "AUTH CRAM-MD5")) != SMTP_EOK)
    {
        return e;
    }
    if ((e = smtp_get_msg(srv, &msg, errstr)) != SMTP_EOK)
    {
        return e;
    }
    if (smtp_msg_status(msg) != 334)
    {
        *error_msg = msg;
        *errstr = xasprintf(_("command %s failed"), "AUTH CRAM-MD5");
        return SMTP_EPROTO;
    }
    /* we know the line is at least 4 characters long */
    challenge = (char *)(msg->next->data) + 4;
    challenge_len = strlen(challenge);
    len = 3 * (challenge_len / 4) + 2;
    b64 = xmalloc(len);
    if (!base64_decode(challenge, challenge_len, b64, &len))
    {
        list_xfree(msg, free);
        *errstr = xasprintf(_("authentication method CRAM-MD5: "
                    "server sent invalid challenge"));
        return SMTP_EPROTO;
    }
    list_xfree(msg, free);
    md5_hmac(password, strlen(password), b64, len, digest);
    free(b64);

    /* construct username + ' ' + digest_in_hex */
    len = strlen(user);
    buf = xmalloc((len + 1 + 32 + 1) * sizeof(char));
    strcpy(buf, user);
    p = buf + len;
    *p++ = ' ';
    for (i = 0; i < 16; i++)
    {
        p[2 * i] = hex[(digest[i] & 0xf0) >> 4];
        p[2 * i + 1] = hex[digest[i] & 0x0f];
    }
    p[32] = '\0';

    b64_len = BASE64_LENGTH(len + 33);
    b64 = xmalloc(b64_len + 1);
    base64_encode(buf, len + 33, b64, b64_len + 1);
    free(buf);
    if ((e = smtp_send_cmd(srv, errstr, "%s", b64)) != SMTP_EOK)
    {
        free(b64);
        return e;
    }
    free(b64);
    if ((e = smtp_get_msg(srv, &msg, errstr)) != SMTP_EOK)
    {
        return e;
    }
    if (smtp_msg_status(msg) != 235)
    {
        *error_msg = msg;
        *errstr = xasprintf(_("authentication failed (method %s)"), "CRAM-MD5");
        return SMTP_EAUTHFAIL;
    }
    list_xfree(msg, free);

    return SMTP_EOK;
}
#endif /* !HAVE_LIBGSASL */


/*
 * smtp_auth_external()
 *
 * Do SMTP authentication via AUTH EXTERNAL.
 * This means the actual authentication is done via TLS; we just send the user
 * name to ther server.
 * The SMTP server must support SMTP_CAP_AUTH_EXTERNAL
 * Used error codes: SMTP_EIO, SMTP_EPROTO, SMTP_EAUTHFAIL, SMTP_EINVAL
 */

#ifndef HAVE_LIBGSASL
int smtp_auth_external(smtp_server_t *srv, const char *user,
        list_t **error_msg, char **errstr)
{
    size_t u_len;
    size_t b64_len;
    char *b64;
    list_t *msg;
    int e;

    *error_msg = NULL;
    if ((e = smtp_send_cmd(srv, errstr, "AUTH EXTERNAL")) != SMTP_EOK)
    {
        return e;
    }
    if ((e = smtp_get_msg(srv, &msg, errstr)) != SMTP_EOK)
    {
        return e;
    }
    if (smtp_msg_status(msg) != 334)
    {
        *error_msg = msg;
        *errstr = xasprintf(_("command %s failed"), "AUTH EXTERNAL");
        return SMTP_EPROTO;
    }
    list_xfree(msg, free);
    u_len = strlen(user);
    b64_len = BASE64_LENGTH(u_len);
    b64 = xmalloc(b64_len + 1);
    base64_encode(user, u_len, b64, b64_len + 1);
    if ((e = smtp_send_cmd(srv, errstr, "%s", b64)) != SMTP_EOK)
    {
        free(b64);
        return e;
    }
    free(b64);
    if ((e = smtp_get_msg(srv, &msg, errstr)) != SMTP_EOK)
    {
        return e;
    }
    if (smtp_msg_status(msg) != 235)
    {
        *error_msg = msg;
        *errstr = xasprintf(_("authentication failed (method %s)"), "EXTERNAL");
        return SMTP_EAUTHFAIL;
    }
    list_xfree(msg, free);

    return SMTP_EOK;
}
#endif /* !HAVE_LIBGSASL */


/*
 * smtp_server_supports_authmech()
 *
 * see smtp.h
 */

int smtp_server_supports_authmech(smtp_server_t *srv, const char *mech)
{
    return (((srv->cap.flags & SMTP_CAP_AUTH_PLAIN)
                && strcmp(mech, "PLAIN") == 0)
            || ((srv->cap.flags & SMTP_CAP_AUTH_CRAM_MD5)
                && strcmp(mech, "CRAM-MD5") == 0)
            || ((srv->cap.flags & SMTP_CAP_AUTH_DIGEST_MD5)
                && strcmp(mech, "DIGEST-MD5") == 0)
            || ((srv->cap.flags & SMTP_CAP_AUTH_SCRAM_SHA_1)
                && strcmp(mech, "SCRAM-SHA-1") == 0)
            || ((srv->cap.flags & SMTP_CAP_AUTH_EXTERNAL)
                && strcmp(mech, "EXTERNAL") == 0)
            || ((srv->cap.flags & SMTP_CAP_AUTH_GSSAPI)
                && strcmp(mech, "GSSAPI") == 0)
            || ((srv->cap.flags & SMTP_CAP_AUTH_LOGIN)
                && strcmp(mech, "LOGIN") == 0)
            || ((srv->cap.flags & SMTP_CAP_AUTH_NTLM)
                && strcmp(mech, "NTLM") == 0));
}


/*
 * smtp_client_supports_authmech()
 *
 * see smtp.h
 */

int smtp_client_supports_authmech(const char *mech)
{
#ifdef HAVE_LIBGSASL

    int supported = 0;
    Gsasl *ctx;

    if (gsasl_init(&ctx) != GSASL_OK)
    {
        return 0;
    }
    supported = gsasl_client_support_p(ctx, mech);
    gsasl_done(ctx);
    return supported;

#else /* not HAVE_LIBGSASL */

    return (strcmp(mech, "CRAM-MD5") == 0
            || strcmp(mech, "PLAIN") == 0
            || strcmp(mech, "EXTERNAL") == 0
            || strcmp(mech, "LOGIN") == 0);

#endif /* not HAVE_LIBGSASL */
}


/*
 * smtp_auth()
 *
 * see smtp.h
 */

int smtp_auth(smtp_server_t *srv,
        const char *hostname,
        const char *user,
        const char *password,
        const char *ntlmdomain,
        const char *auth_mech,
        char *(*password_callback)(const char *hostname, const char *user),
        list_t **error_msg,
        char **errstr)
{
#ifdef HAVE_LIBGSASL
    int e;
    list_t *msg;
    Gsasl *ctx;
    Gsasl_session *sctx;
    char *input;
    char inbuf[SMTP_BUFSIZE];
    char *outbuf;
    int error_code;
    int auth_plain_special;
    char *callback_password = NULL;


    *error_msg = NULL;
    if (strcmp(auth_mech, "") != 0
            && !smtp_server_supports_authmech(srv, auth_mech))
    {
        *errstr = xasprintf(
                _("the server does not support authentication method %s"),
                auth_mech);
        return SMTP_EUNAVAIL;
    }
    if ((error_code = gsasl_init(&ctx)) != GSASL_OK)
    {
        *errstr = xasprintf(_("GNU SASL: %s"), gsasl_strerror(error_code));
        return SMTP_ELIBFAILED;
    }
    if (strcmp(auth_mech, "") != 0 && !gsasl_client_support_p(ctx, auth_mech))
    {
        gsasl_done(ctx);
        *errstr = xasprintf(
                _("GNU SASL: authentication method %s not supported"),
                auth_mech);
        return SMTP_ELIBFAILED;
    }
    if (strcmp(auth_mech, "") == 0)
    {
        /* Choose "best" authentication mechanism. */
        /* TODO: use gsasl_client_suggest_mechanism()? */
        if (gsasl_client_support_p(ctx, "GSSAPI")
                && (srv->cap.flags & SMTP_CAP_AUTH_GSSAPI))
        {
            auth_mech = "GSSAPI";
        }
        else if (gsasl_client_support_p(ctx, "SCRAM-SHA-1")
                && (srv->cap.flags & SMTP_CAP_AUTH_SCRAM_SHA_1))
        {
            auth_mech = "SCRAM-SHA-1";
        }
        else if (gsasl_client_support_p(ctx, "CRAM-MD5")
                && (srv->cap.flags & SMTP_CAP_AUTH_CRAM_MD5))
        {
            auth_mech = "CRAM-MD5";
        }
#ifdef HAVE_TLS
        else if (tls_is_active(&srv->tls))
        {
            if (gsasl_client_support_p(ctx, "PLAIN")
                    && (srv->cap.flags & SMTP_CAP_AUTH_PLAIN))
            {
                auth_mech = "PLAIN";
            }
            else if (gsasl_client_support_p(ctx, "DIGEST-MD5")
                    && (srv->cap.flags & SMTP_CAP_AUTH_DIGEST_MD5))
            {
                auth_mech = "DIGEST-MD5";
            }
            else if (gsasl_client_support_p(ctx, "LOGIN")
                    && (srv->cap.flags & SMTP_CAP_AUTH_LOGIN))
            {
                auth_mech = "LOGIN";
            }
            else if (gsasl_client_support_p(ctx, "NTLM")
                    && (srv->cap.flags & SMTP_CAP_AUTH_NTLM))
            {
                auth_mech = "NTLM";
            }
        }
#endif /* HAVE_TLS */
    }
    if (strcmp(auth_mech, "") == 0)
    {
        gsasl_done(ctx);
#ifdef HAVE_TLS
        if (!tls_is_active(&srv->tls))
        {
#endif /* HAVE_TLS */
            *errstr = xasprintf(_("cannot use a secure authentication method"));
#ifdef HAVE_TLS
        }
        else
        {
            *errstr = xasprintf(
                    _("cannot find a usable authentication method"));
        }
#endif /* not HAVE_TLS */
        return SMTP_EUNAVAIL;
    }

    /* Check availability of required authentication data */
    if (strcmp(auth_mech, "EXTERNAL") != 0)
    {
        /* GSSAPI, SCRAM-SHA-1, DIGEST-MD5, CRAM-MD5, PLAIN, LOGIN, NTLM all
         * need a user name */
        if (!user)
        {
            gsasl_done(ctx);
            *errstr = xasprintf(_("authentication method %s needs a user name"),
                    auth_mech);
            return SMTP_EUNAVAIL;
        }
        /* SCRAM-SHA-1, DIGEST-MD5, CRAM-MD5, PLAIN, LOGIN, NTLM all need a
         * password */
        if (strcmp(auth_mech, "GSSAPI") != 0 && !password)
        {
            if (!password_callback
                    || !(callback_password = password_callback(hostname, user)))
            {
                gsasl_done(ctx);
                *errstr = xasprintf(
                        _("authentication method %s needs a password"),
                        auth_mech);
                return SMTP_EUNAVAIL;
            }
            password = callback_password;
        }
    }

    if ((error_code = gsasl_client_start(ctx, auth_mech, &sctx)) != GSASL_OK)
    {
        gsasl_done(ctx);
        *errstr = xasprintf(_("GNU SASL: %s"), gsasl_strerror(error_code));
        return SMTP_ELIBFAILED;
    }

    /* Set the authentication properties */
    if (user)
    {
        gsasl_property_set(sctx, GSASL_AUTHID, user);
        /* GSASL_AUTHZID must not be set for DIGEST-MD5, because otherwise
         * authentication may fail (tested with postfix). Set it only for
         * EXTERNAL. */
        if (strcmp(auth_mech, "EXTERNAL") == 0)
        {
            gsasl_property_set(sctx, GSASL_AUTHZID, user);
        }
    }
    if (password)
    {
        gsasl_property_set(sctx, GSASL_PASSWORD, password);
    }
    free(callback_password);
    /* For DIGEST-MD5 and GSSAPI (and SCRAM-SHA-1?) */
    gsasl_property_set(sctx, GSASL_SERVICE, "smtp");
    if (hostname)
    {
        gsasl_property_set(sctx, GSASL_HOSTNAME, hostname);
    }
    /* For NTLM. Postfix does not care, MS IIS needs an arbitrary non-empty
     * string. */
    if (ntlmdomain)
    {
        gsasl_property_set(sctx, GSASL_REALM, ntlmdomain);
    }

    /* Bigg authentication loop */
    input = NULL;
    do
    {
        error_code = gsasl_step64(sctx, input, &outbuf);
        if (error_code != GSASL_OK && error_code != GSASL_NEEDS_MORE)
        {
            gsasl_finish(sctx);
            gsasl_done(ctx);
            *errstr = xasprintf(_("GNU SASL: %s"), gsasl_strerror(error_code));
            return SMTP_ELIBFAILED;
        }
        if (!input)
        {
            if (strcmp(auth_mech, "PLAIN") == 0 && outbuf[0])
            {
                /* AUTH PLAIN needs special treatment because it needs to send
                 * the authentication data together with the AUTH PLAIN command.
                 * At least smtp.web.de requires this, and I happen to use this
                 * server :) */
                auth_plain_special = 1;
                if ((e = smtp_send_cmd(srv, errstr,
                                "AUTH PLAIN %s", outbuf)) != SMTP_EOK)
                {
                    gsasl_finish(sctx);
                    gsasl_done(ctx);
                    free(outbuf);
                    return e;
                }
            }
            else
            {
                auth_plain_special = 0;
                if ((e = smtp_send_cmd(srv, errstr,
                                "AUTH %s", auth_mech)) != SMTP_EOK)
                {
                    gsasl_finish(sctx);
                    gsasl_done(ctx);
                    free(outbuf);
                    return e;
                }
            }
            if ((e = smtp_get_msg(srv, &msg, errstr)) != SMTP_EOK)
            {
                gsasl_finish(sctx);
                gsasl_done(ctx);
                free(outbuf);
                return e;
            }
            if (smtp_msg_status(msg) != 334 && smtp_msg_status(msg) != 235)
            {
                *error_msg = msg;
                gsasl_finish(sctx);
                gsasl_done(ctx);
                free(outbuf);
                *errstr = xasprintf(_("authentication failed (method %s)"),
                        auth_mech);
                return SMTP_EAUTHFAIL;
            }
            /* msg->next->data cannot be longer than SMTP_BUFSIZE-1 */
            strcpy(inbuf, msg->next->data);
            list_xfree(msg, free);
            input = inbuf + 4;
            if (auth_plain_special)
            {
                free(outbuf);
                continue;
            }
        }
        /* Some methods (at least CRAM-MD5) must not send an empty outbuf,
         * while others (SCRAM-SHA-1, GSSAPI) must. Confirmed
         * with mpop on 2011-01-17 with one POP3 server and the methods CRAM-MD5
         * and SCRAM-SHA-1. */
        if (outbuf[0]
                || strcmp(auth_mech, "SCRAM-SHA-1") == 0
                || strcmp(auth_mech, "GSSAPI") == 0)
        {
            if ((e = smtp_send_cmd(srv, errstr, "%s", outbuf)) != SMTP_EOK)
            {
                gsasl_finish(sctx);
                gsasl_done(ctx);
                free(outbuf);
                return e;
            }
            if ((e = smtp_get_msg(srv, &msg, errstr)) != SMTP_EOK)
            {
                gsasl_finish(sctx);
                gsasl_done(ctx);
                free(outbuf);
                return e;
            }
            if (smtp_msg_status(msg) != 334 && smtp_msg_status(msg) != 235)
            {
                *error_msg = msg;
                gsasl_finish(sctx);
                gsasl_done(ctx);
                free(outbuf);
                *errstr = xasprintf(_("authentication failed (method %s)"),
                        auth_mech);
                return SMTP_EAUTHFAIL;
            }
            /* msg->next->data cannot be longer than SMTP_BUFSIZE-1 */
            strcpy(inbuf, msg->next->data);
            list_xfree(msg, free);
            input = inbuf + 4;
        }
        free(outbuf);
    }
    while (error_code == GSASL_NEEDS_MORE);
    if (error_code != GSASL_OK)
    {
        gsasl_finish(sctx);
        gsasl_done(ctx);
        *errstr = xasprintf(_("authentication failed: %s (method %s)"),
                gsasl_strerror(error_code), auth_mech);
        return SMTP_EAUTHFAIL;
    }
    gsasl_finish(sctx);
    gsasl_done(ctx);
    /* For DIGEST-MD5, we need to send an empty answer to the last 334
     * response before we get 235. */
    if (strcmp(auth_mech, "DIGEST-MD5") == 0 && strncmp(inbuf, "235 ", 4) != 0)
    {
        if ((e = smtp_send_cmd(srv, errstr, "")) != SMTP_EOK)
        {
            return e;
        }
        if ((e = smtp_get_msg(srv, &msg, errstr)) != SMTP_EOK)
        {
            return e;
        }
        if (smtp_msg_status(msg) != 235)
        {
            *error_msg = msg;
            *errstr = xasprintf(_("authentication failed (method %s)"),
                    auth_mech);
            return SMTP_EAUTHFAIL;
        }
        list_xfree(msg, free);
    }
    return SMTP_EOK;

#else /* not HAVE_LIBGSASL */

    (void)ntlmdomain;

    char *callback_password = NULL;
    int e;


    *error_msg = NULL;
    if (strcmp(auth_mech, "") != 0
            && !smtp_server_supports_authmech(srv, auth_mech))
    {
        *errstr = xasprintf(
                _("the server does not support authentication method %s"),
                auth_mech);
        return SMTP_EUNAVAIL;
    }
    if (strcmp(auth_mech, "") == 0)
    {
        /* Choose "best" authentication mechanism. */
        if (srv->cap.flags & SMTP_CAP_AUTH_CRAM_MD5)
        {
            auth_mech = "CRAM-MD5";
        }
#ifdef HAVE_TLS
        else if (tls_is_active(&srv->tls))
        {
            if (srv->cap.flags & SMTP_CAP_AUTH_PLAIN)
            {
                auth_mech = "PLAIN";
            }
            else if (srv->cap.flags & SMTP_CAP_AUTH_LOGIN)
            {
                auth_mech = "LOGIN";
            }
        }
#endif /* HAVE_TLS */
    }
    if (strcmp(auth_mech, "") == 0)
    {
#ifdef HAVE_TLS
        if (!tls_is_active(&srv->tls))
        {
#endif /* HAVE_TLS */
            *errstr = xasprintf(_("cannot use a secure authentication method"));
#ifdef HAVE_TLS
        }
        else
        {
            *errstr = xasprintf(
                    _("cannot find a usable authentication method"));
        }
#endif /* not HAVE_TLS */
        return SMTP_EUNAVAIL;
    }

    if (strcmp(auth_mech, "EXTERNAL") != 0)
    {
        /* CRAMD-MD5, PLAIN, LOGIN all need a user name and a password */
        if (!user)
        {
            *errstr = xasprintf(_("authentication method %s needs a user name"),
                    auth_mech);
            return SMTP_EUNAVAIL;
        }
        if (!password)
        {
            if (!password_callback
                    || !(callback_password = password_callback(hostname, user)))
            {
                *errstr = xasprintf(
                        _("authentication method %s needs a password"),
                        auth_mech);
                return SMTP_EUNAVAIL;
            }
            password = callback_password;
        }
    }

    if (strcmp(auth_mech, "CRAM-MD5") == 0)
    {
        e = smtp_auth_cram_md5(srv, user, password, error_msg, errstr);
    }
    else if (strcmp(auth_mech, "PLAIN") == 0)
    {
        e = smtp_auth_plain(srv, user, password, error_msg, errstr);
    }
    else if (strcmp(auth_mech, "EXTERNAL") == 0)
    {
        e = smtp_auth_external(srv, user ? user : "", error_msg, errstr);
    }
    else if (strcmp(auth_mech, "LOGIN") == 0)
    {
        e = smtp_auth_login(srv, user, password, error_msg, errstr);
    }
    else
    {
        *errstr = xasprintf(_("authentication method %s not supported"),
                auth_mech);
        e = SMTP_ELIBFAILED;
    }
    free(callback_password);
    return e;

#endif /* not HAVE_LIBGSASL */
}


/*
 * smtp_send_envelope()
 *
 * see smtp.h
 */

int smtp_send_envelope(smtp_server_t *srv,
        const char *envelope_from,
        list_t *recipients,
        const char *dsn_notify,
        const char *dsn_return,
        list_t **error_msg,
        char **errstr)
{
    int e;
    list_t *msg;
    int mailfrom_cmd_was_sent = 0;
    int mailfrom_reply_was_rcvd = 0;
    list_t *rcpt_send = recipients;
    list_t *rcpt_recv = recipients;
    int data_cmd_was_sent = 0;
    int data_reply_was_rcvd = 0;
    int pipeline_limit = 1;
    int piped_commands = 0;
    int status;


    *error_msg = NULL;
    if (srv->cap.flags & SMTP_CAP_PIPELINING)
    {
        pipeline_limit = SMTP_PIPELINE_LIMIT;
    }

    /* Send the MAIL FROM, RCPT TO and DATA commands using pipelining. The
     * number of pipelined commands will never be greater than pipeline_limit
     * to avoid problems with the TCP window size (exceeding it can lead to
     * deadlocks). pipeline_limit == 1 disables pipelining. */
    while (!data_reply_was_rcvd)
    {
        while (!data_cmd_was_sent && piped_commands < pipeline_limit)
        {
            /* send */
            if (!mailfrom_cmd_was_sent)
            {
                if (dsn_return)
                {
                    e = smtp_send_cmd(srv, errstr, "MAIL FROM:<%s> RET=%s",
                            strcasecmp(envelope_from, "MAILER-DAEMON") == 0
                            ? "" : envelope_from, dsn_return);
                }
                else
                {
                    e = smtp_send_cmd(srv, errstr, "MAIL FROM:<%s>",
                            strcasecmp(envelope_from, "MAILER-DAEMON") == 0
                            ? "" : envelope_from);
                }
                if (e != SMTP_EOK)
                {
                    return e;
                }
                mailfrom_cmd_was_sent = 1;
            }
            else if (!list_is_empty(rcpt_send))
            {
                rcpt_send = rcpt_send->next;
                if (dsn_notify)
                {
                    e = smtp_send_cmd(srv, errstr, "RCPT TO:<%s> NOTIFY=%s",
                            (char *)(rcpt_send->data), dsn_notify);
                }
                else
                {
                    e = smtp_send_cmd(srv, errstr, "RCPT TO:<%s>",
                            (char *)(rcpt_send->data));
                }
                if (e != SMTP_EOK)
                {
                    return e;
                }
            }
            else
            {
                if ((e = smtp_send_cmd(srv, errstr, "DATA")) != SMTP_EOK)
                {
                    return e;
                }
                data_cmd_was_sent = 1;
            }
            piped_commands++;
        }
        while (piped_commands > 0)
        {
            /* receive */
            if (!mailfrom_reply_was_rcvd)
            {
                if ((e = smtp_get_msg(srv, &msg, errstr)) != SMTP_EOK)
                {
                    return e;
                }
                status = smtp_msg_status(msg);
                if (status != 250)
                {
                    *error_msg = msg;
                    *errstr = xasprintf(_("envelope from address %s not "
                                "accepted by the server"), envelope_from);
                    return (status >= 400 && status <= 499
                            ? SMTP_EUNAVAIL : SMTP_EINVAL);
                }
                list_xfree(msg, free);
                mailfrom_reply_was_rcvd = 1;
            }
            else if (!list_is_empty(rcpt_recv))
            {
                rcpt_recv = rcpt_recv->next;
                if ((e = smtp_get_msg(srv, &msg, errstr)) != SMTP_EOK)
                {
                    return e;
                }
                status = smtp_msg_status(msg);
                if (status != 250 && status != 251)
                {
                    *error_msg = msg;
                    *errstr = xasprintf(_("recipient address %s not "
                                "accepted by the server"),
                            (char *)(rcpt_recv->data));
                    return (status >= 400 && status <= 499
                            ? SMTP_EUNAVAIL : SMTP_EINVAL);
                }
                list_xfree(msg, free);
            }
            else
            {
                if ((e = smtp_get_msg(srv, &msg, errstr)) != SMTP_EOK)
                {
                    return e;
                }
                status = smtp_msg_status(msg);
                if (smtp_msg_status(msg) != 354)
                {
                    *error_msg = msg;
                    *errstr = xasprintf(
                            _("the server does not accept mail data"));
                    return (status >= 400 && status <= 499
                            ? SMTP_EUNAVAIL : SMTP_EINVAL);
                }
                list_xfree(msg, free);
                data_reply_was_rcvd = 1;
            }
            piped_commands--;
        }
    }

    return SMTP_EOK;
}


/*
 * smtp_send_mail()
 *
 * see smtp.h
 */

int smtp_send_mail(smtp_server_t *srv, FILE *mailf, int keep_bcc,
        long *mailsize, char **errstr)
{
    char bigbuffer[MAIL_BUFSIZE + 3];   /* buffer + leading dot + ending CRLF */
    char *buffer;
    size_t len;
    char *send_buf;
    size_t send_len;
    int in_header;
    int in_bcc;
    int line_starts;
    int line_continues;
    int e;

    bigbuffer[0] = '.';
    buffer = bigbuffer + 1;
    in_header = 1;
    in_bcc = 0;
    line_continues = 0;
    e = SMTP_EOK;
    for (;;)
    {
        if (stream_gets(mailf, buffer, MAIL_BUFSIZE, &len, errstr)
                != STREAM_EOK)
        {
            return SMTP_EIO;
        }
        if (len == 0)
        {
            break;
        }
        line_starts = !line_continues;
        if (len > 0 && buffer[len - 1] == '\n')
        {
            /* first case: we have a line end */
            buffer[--len] = '\0';
            if (len > 0 && buffer[len - 1] == '\r')
            {
                buffer[--len] = '\0';
            }
            line_continues = 0;
        }
        else if (len == MAIL_BUFSIZE - 1)
        {
            /* second case: the line continues */
            if (buffer[len - 1] == '\r')
            {
                /* We have CRLF that is divided by the buffer boundary. Since CR
                 * may not appear alone in a mail according to RFC2822, we
                 * know that the next buffer will be "\n\0", so it's safe to
                 * just delete the CR. */
                buffer[--len] = '\0';
            }
            line_continues = 1;
        }
        else
        {
            /* third case: this is the last line, and it lacks a newline
             * character */
            line_continues = 0;
        }
        if (!keep_bcc)
        {
            if (line_starts && in_header && buffer[0] == '\0')
            {
                in_header = 0;
            }
            if (in_header)
            {
                if (line_starts)
                {
                    if (!in_bcc)
                    {
                        if (strncasecmp(buffer, "Bcc:", 4) == 0)
                        {
                            in_bcc = 1;
                            /* remove Bcc header by ignoring this line */
                            continue;
                        }
                    }
                    else
                    {
                        /* continued header lines begin with "horizontal
                         * whitespace" (RFC 2822, section 2.2.3) */
                        if (buffer[0] == '\t' || buffer[0] == ' ')
                        {
                            /* remove Bcc header by ignoring this line */
                            continue;
                        }
                        else
                        {
                            in_bcc = 0;
                        }
                    }
                }
                else
                {
                    if (in_bcc)
                    {
                        /* remove Bcc header by ignoring this line */
                        continue;
                    }
                }
            }
        }
        send_buf = buffer;
        send_len = len;
        if (line_starts && buffer[0] == '.')
        {
            /* Quote the leading dot with another dot */
            send_buf = bigbuffer;
            send_len = len + 1;
        }
        if (!line_continues)
        {
            /* Append CRLF */
            buffer[len] = '\r';
            buffer[len + 1] = '\n';
            buffer[len + 2] = '\0';
            send_len += 2;
        }
        /* Update mailsize. Do not count a quote dot. Count CRLF as one
         * character. */
        *mailsize += (long)len + (line_continues ? 0 : 1);
        if ((e = smtp_put(srv, send_buf, send_len, errstr)) != SMTP_EOK)
        {
            return e;
        }
    }

    return SMTP_EOK;
}


/*
 * smtp_end_mail()
 *
 * see smtp.h
 */

int smtp_end_mail(smtp_server_t *srv, list_t **error_msg, char **errstr)
{
    int e;
    list_t *msg;

    *error_msg = NULL;
    if ((e = smtp_send_cmd(srv, errstr, ".")) != SMTP_EOK)
    {
        return e;
    }
    if ((e = smtp_get_msg(srv, &msg, errstr)) != SMTP_EOK)
    {
        return e;
    }
    *error_msg = msg;
    if (smtp_msg_status(msg) != 250)
    {
        *errstr = xasprintf(_("the server did not accept the mail"));
        return SMTP_EUNAVAIL;
    }
    else
    {
        return SMTP_EOK;
    }
}


/*
 * smtp_end_mail_lmtp()
 *
 * see smtp.h
 *
 */

void _smtp_free_list_of_lists(void *l)
{
    list_xfree((list_t *)l, free);
}

int smtp_end_mail_lmtp(smtp_server_t *srv,
        list_t *recipients,
        list_t **errstrs,
        list_t **error_msgs,
        char **errstr)
{
    int e;
    list_t *msg;
    list_t *lp_recipients;
    list_t *lp_errstrs;
    list_t *lp_error_msgs;
    int all_recipients_accepted;
    char *tmp;


    if ((e = smtp_send_cmd(srv, errstr, ".")) != SMTP_EOK)
    {
        *errstrs = NULL;
        *error_msgs = NULL;
        return e;
    }

    *errstrs = list_new();
    *error_msgs = list_new();
    lp_errstrs = *errstrs;
    lp_error_msgs = *error_msgs;
    lp_recipients = recipients;
    all_recipients_accepted = 1;
    while (!list_is_empty(lp_recipients))
    {
        lp_recipients = lp_recipients->next;
        if ((e = smtp_get_msg(srv, &msg, errstr)) != SMTP_EOK)
        {
            list_xfree(*errstrs, free);
            *errstrs = NULL;
            list_xfree(*error_msgs, _smtp_free_list_of_lists);
            *error_msgs = NULL;
            return e;
        }
        if (smtp_msg_status(msg) != 250)
        {
            all_recipients_accepted = 0;
            tmp = xasprintf(_("the server refuses to send the mail to %s"),
                    (char *)(lp_recipients->data));
            list_insert(lp_errstrs, tmp);
            list_insert(lp_error_msgs, msg);
        }
        else
        {
            list_xfree(msg, free);
            list_insert(lp_errstrs, NULL);
            list_insert(lp_error_msgs, NULL);
        }
        lp_errstrs = lp_errstrs->next;
        lp_error_msgs = lp_error_msgs->next;
    }

    if (all_recipients_accepted)
    {
        /* we can use list_free() here since all list entries are just NULL */
        list_free(*errstrs);
        *errstrs = NULL;
        list_free(*error_msgs);
        *error_msgs = NULL;
        return SMTP_EOK;
    }
    else
    {
        return SMTP_EUNAVAIL;
    }
}


/*
 * smtp_etrn()
 *
 * see smtp.h
 */

int smtp_etrn(smtp_server_t *srv, const char *etrn_argument,
        list_t **error_msg, char **errstr)
{
    int e;
    list_t *msg;

    *error_msg = NULL;
    if ((e = smtp_send_cmd(srv, errstr, "ETRN %s", etrn_argument)) != SMTP_EOK)
    {
        return e;
    }
    if ((e = smtp_get_msg(srv, &msg, errstr)) != SMTP_EOK)
    {
        return e;
    }
    switch (smtp_msg_status(msg))
    {
        case 250: /* OK, queuing for node <x> started */
        case 251: /* OK, no messages waiting for node <x> */
        case 252: /* OK, pending messages for node <x> started */
        case 253: /* OK, <n> pending messages for node <x> started */
            break;

        case 458: /* Unable to queue messages for node <x> */
        case 459: /* Node <x> not allowed: <reason> */
            *error_msg = msg;
            *errstr = xasprintf(
                    _("the server is unable to fulfill the request"));
            return SMTP_EUNAVAIL;
            break;

        case 500: /* Syntax Error */
        case 501: /* 501 Syntax Error in Parameters */
            *error_msg = msg;
            *errstr = xasprintf(
                    _("invalid argument for Remote Message Queue Starting"));
            return SMTP_EINVAL;
            break;

        default:
            *error_msg = msg;
            *errstr = xasprintf(_("command %s failed"), "ETRN");
            return SMTP_EPROTO;
            break;
    }
    list_xfree(msg, free);

    return SMTP_EOK;
}


/*
 * smtp_quit()
 *
 * see smtp.h
 */

int smtp_quit(smtp_server_t *srv, char **errstr)
{
    int e;
    list_t *msg;

    if ((e = smtp_send_cmd(srv, errstr, "QUIT")) == SMTP_EOK)
    {
        e = smtp_get_msg(srv, &msg, errstr);
    }
    if (msg)
    {
        list_xfree(msg, free);
    }
    return e;
}


/*
 * smtp_close()
 *
 * see smtp.h
 */

void smtp_close(smtp_server_t *srv)
{
#ifdef HAVE_TLS
    if (tls_is_active(&srv->tls))
    {
        tls_close(&srv->tls);
    }
#endif /* HAVE_TLS */
    net_close_socket(srv->fd);
}
