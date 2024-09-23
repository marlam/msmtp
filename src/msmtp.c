/*
 * msmtp.c
 *
 * This file is part of msmtp, an SMTP client.
 *
 * Copyright (C) 2000, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011,
 * 2012, 2013, 2014, 2015, 2016, 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024
 * Martin Lambers <marlam@marlam.de>
 * Martin Stenberg <martin@gnutiken.se> (passwordeval support)
 * Scott Shumate <sshumate@austin.rr.com> (aliases support)
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
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
extern char *optarg;
extern int optind;
#include <unistd.h>
#include <fcntl.h>
#ifdef ENABLE_NLS
# include <locale.h>
#endif
#ifdef HAVE_SYSLOG
# include <syslog.h>
#endif
#ifdef HAVE_SIGNAL
# include <signal.h>
#endif

#include "gettext.h"
#define _(string) gettext(string)

#include "xalloc.h"
#include "conf.h"
#include "list.h"
#include "net.h"
#include "smtp.h"
#include "tools.h"
#include "aliases.h"
#include "password.h"
#include "eval.h"
#include "msgid.h"
#ifdef HAVE_TLS
# include "mtls.h"
#endif /* HAVE_TLS */

/* Default file names. */
#ifdef W32_NATIVE
#define SYSCONFFILE     "msmtprc.txt"
#define USERCONFFILE    "msmtprc.txt"
#else /* UNIX */
#define SYSCONFFILE     "msmtprc"
#define USERCONFFILE    ".msmtprc"
#endif

/* The name of this program */
const char *prgname;


/*
 * Die if memory allocation fails
 */

void xalloc_die(void)
{
    /* TRANSLATORS: msmtp shares a lot of code and translatable strings with
       mpop <https://marlam.de/mpop>. */
    fprintf(stderr, _("%s: FATAL: %s\n"), prgname, strerror(ENOMEM));
    exit(EX_OSERR);
}


/*
 * msmtp_password_callback()
 *
 * This function will be called by smtp_auth() to get a password if none was
 * given.
 */

char *msmtp_password_callback(const char *hostname, const char *user)
{
    return password_get(hostname, user, password_service_smtp, 1, 1);
}


/*
 * msmtp_endsession()
 *
 * Quit an SMTP session and close the connection.
 * QUIT is only sent when the flag 'quit' is set.
 */

void msmtp_endsession(smtp_server_t *srv, int quit)
{
    char *tmp_errstr;

    if (quit)
    {
        tmp_errstr = NULL;
        (void)smtp_quit(srv, &tmp_errstr);
        free(tmp_errstr);
    }
    smtp_close(srv);
}


/*
 * msmtp_rmqs()
 *
 * Sends an ETRN request to the SMTP server specified in the account 'acc'.
 * If an error occurred, '*errstr' points to an allocated string that describes
 * the error or is NULL, and '*msg' may contain the offending message from the
 * SMTP server (or be NULL).
 */

int msmtp_rmqs(account_t *acc, int debug, const char *rmqs_argument,
        list_t **msg, char **errstr)
{
    smtp_server_t srv;
    int e;
#ifdef HAVE_TLS
    mtls_cert_info_t *tci = NULL;
    char *mtls_parameter_description = NULL;
#endif /* HAVE_TLS */

    *errstr = NULL;
    *msg = NULL;

    /* create a new smtp_server_t */
    srv = smtp_new(debug ? stdout : NULL, acc->protocol);

    /* connect */
    if ((e = smtp_connect(&srv, acc->socketname, acc->proxy_host, acc->proxy_port,
                    acc->host, acc->port, acc->source_ip, acc->timeout,
                    NULL, NULL, errstr)) != NET_EOK)
    {
        return net_exitcode(e);
    }

    /* prepare tls */
#ifdef HAVE_TLS
    if (acc->tls)
    {
        if ((e = smtp_tls_init(&srv,
                        acc->tls_key_file, acc->tls_cert_file, acc->password,
                        acc->tls_trust_file, acc->tls_crl_file,
                        acc->tls_sha256_fingerprint,
                        acc->tls_sha1_fingerprint, acc->tls_md5_fingerprint,
                        acc->tls_min_dh_prime_bits,
                        acc->tls_priorities,
                        acc->tls_host_override ? acc->tls_host_override : acc->host,
                        acc->tls_nocertcheck,
                        errstr)) != TLS_EOK)
        {
            return mtls_exitcode(e);
        }
    }
#endif /* HAVE_TLS */

    /* start tls for smtps servers */
#ifdef HAVE_TLS
    if (acc->tls && acc->tls_nostarttls)
    {
        if (debug)
        {
            tci = mtls_cert_info_new();
        }
        if ((e = smtp_tls(&srv, tci,
                        &mtls_parameter_description, errstr)) != TLS_EOK)
        {
            if (debug)
            {
                mtls_cert_info_free(tci);
                free(mtls_parameter_description);
            }
            msmtp_endsession(&srv, 0);
            return mtls_exitcode(e);
        }
        if (debug)
        {
            mtls_print_info(mtls_parameter_description, tci);
            mtls_cert_info_free(tci);
            free(mtls_parameter_description);
        }
    }
#endif /* HAVE_TLS */

    /* get greeting */
    if ((e = smtp_get_greeting(&srv, msg, NULL, errstr)) != SMTP_EOK)
    {
        msmtp_endsession(&srv, 0);
        return smtp_exitcode(e);
    }

    /* initialize session */
    if ((e = smtp_init(&srv, acc->domain, msg, errstr)) != SMTP_EOK)
    {
        msmtp_endsession(&srv, 0);
        return smtp_exitcode(e);
    }

    /* start tls for starttls servers */
#ifdef HAVE_TLS
    if (acc->tls && !acc->tls_nostarttls)
    {
        if (!(srv.cap.flags & SMTP_CAP_STARTTLS))
        {
            *errstr = xasprintf(_("the server does not support TLS "
                        "via the STARTTLS command"));
            msmtp_endsession(&srv, 1);
            return EX_UNAVAILABLE;
        }
        if ((e = smtp_tls_starttls(&srv, msg, errstr)) != SMTP_EOK)
        {
            msmtp_endsession(&srv, 0);
            return smtp_exitcode(e);
        }
        if (debug)
        {
            tci = mtls_cert_info_new();
        }
        if ((e = smtp_tls(&srv, tci,
                        &mtls_parameter_description, errstr)) != TLS_EOK)
        {
            if (debug)
            {
                mtls_cert_info_free(tci);
                free(mtls_parameter_description);
            }
            msmtp_endsession(&srv, 0);
            return mtls_exitcode(e);
        }
        if (debug)
        {
            mtls_print_info(mtls_parameter_description, tci);
            mtls_cert_info_free(tci);
            free(mtls_parameter_description);
        }
        /* initialize again */
        if ((e = smtp_init(&srv, acc->domain, msg, errstr)) != SMTP_EOK)
        {
            msmtp_endsession(&srv, 0);
            return smtp_exitcode(e);
        }
    }
#endif /* HAVE_TLS */

    if (!(srv.cap.flags & SMTP_CAP_ETRN))
    {
        *errstr = xasprintf(_("the server does not support "
                    "Remote Message Queue Starting"));
        msmtp_endsession(&srv, 1);
        return EX_UNAVAILABLE;
    }

    /* authenticate */
    if (acc->auth_mech)
    {
        if (!(srv.cap.flags & SMTP_CAP_AUTH))
        {
            *errstr = xasprintf(
                    _("the server does not support authentication"));
            msmtp_endsession(&srv, 1);
            return EX_UNAVAILABLE;
        }
        if ((e = smtp_auth(&srv, acc->host ? acc->host : acc->socketname,
                        acc->port, acc->username, acc->password,
                        acc->ntlmdomain, acc->auth_mech,
                        msmtp_password_callback, msg, errstr))
                != SMTP_EOK)
        {
            msmtp_endsession(&srv, 0);
            return smtp_exitcode(e);
        }
    }

    /* send the ETRN request */
    if ((e = smtp_etrn(&srv, rmqs_argument, msg, errstr)) != SMTP_EOK)
    {
        msmtp_endsession(&srv, 0);
        return smtp_exitcode(e);
    }

    /* end session */
    msmtp_endsession(&srv, 1);
    return EX_OK;
}


/*
 * msmtp_serverinfo()
 *
 * Prints information about the SMTP server specified in the account 'acc'.
 * If an error occurred, '*errstr' points to an allocated string that describes
 * the error or is NULL, and '*msg' may contain the offending message from the
 * SMTP server (or be NULL).
 */

int msmtp_serverinfo(account_t *acc, int debug, list_t **msg, char **errstr)
{
    smtp_server_t srv;
    char *server_canonical_name = NULL;
    char *server_address = NULL;
    char *server_greeting = NULL;
    int e;
#ifdef HAVE_TLS
    mtls_cert_info_t *tci = NULL;
    char *mtls_parameter_description = NULL;
#endif /* HAVE_TLS */

    *errstr = NULL;
    *msg = NULL;

    /* create a new smtp_server_t */
    srv = smtp_new(debug ? stdout : NULL, acc->protocol);

    /* connect */
    if ((e = smtp_connect(&srv, acc->socketname, acc->proxy_host, acc->proxy_port,
                    acc->host, acc->port, acc->source_ip, acc->timeout,
                    &server_canonical_name, &server_address, errstr))
            != NET_EOK)
    {
        e = net_exitcode(e);
        goto error_exit;
    }

    /* prepare tls */
#ifdef HAVE_TLS
    if (acc->tls)
    {
        tci = mtls_cert_info_new();
        if ((e = smtp_tls_init(&srv,
                        acc->tls_key_file, acc->tls_cert_file, acc->password,
                        acc->tls_trust_file, acc->tls_crl_file,
                        acc->tls_sha256_fingerprint,
                        acc->tls_sha1_fingerprint, acc->tls_md5_fingerprint,
                        acc->tls_min_dh_prime_bits,
                        acc->tls_priorities,
                        acc->tls_host_override ? acc->tls_host_override : acc->host,
                        acc->tls_nocertcheck,
                        errstr)) != TLS_EOK)
        {
            e = mtls_exitcode(e);
            goto error_exit;
        }
    }
#endif /* HAVE_TLS */

    /* start tls for smtps servers */
#ifdef HAVE_TLS
    if (acc->tls && acc->tls_nostarttls)
    {
        if ((e = smtp_tls(&srv, tci,
                        &mtls_parameter_description, errstr)) != TLS_EOK)
        {
            msmtp_endsession(&srv, 0);
            e = mtls_exitcode(e);
            goto error_exit;
        }
    }
#endif /* HAVE_TLS */

    /* get greeting */
    if ((e = smtp_get_greeting(&srv, msg, &server_greeting,
                    errstr)) != SMTP_EOK)
    {
        msmtp_endsession(&srv, 0);
        e = smtp_exitcode(e);
        goto error_exit;
    }

    /* initialize session */
    if ((e = smtp_init(&srv, acc->domain, msg, errstr)) != SMTP_EOK)
    {
        msmtp_endsession(&srv, 0);
        e = smtp_exitcode(e);
        goto error_exit;
    }

    /* start tls for starttls servers */
#ifdef HAVE_TLS
    if (acc->tls && !acc->tls_nostarttls)
    {
        if (!(srv.cap.flags & SMTP_CAP_STARTTLS))
        {
            *errstr = xasprintf(_("the server does not support TLS "
                        "via the STARTTLS command"));
            msmtp_endsession(&srv, 1);
            e = EX_UNAVAILABLE;
            goto error_exit;
        }
        if ((e = smtp_tls_starttls(&srv, msg, errstr)) != SMTP_EOK)
        {
            msmtp_endsession(&srv, 0);
            e = smtp_exitcode(e);
            goto error_exit;
        }
        if ((e = smtp_tls(&srv, tci,
                        &mtls_parameter_description, errstr)) != TLS_EOK)
        {
            msmtp_endsession(&srv, 0);
            e = mtls_exitcode(e);
            goto error_exit;
        }
        /* initialize again */
        if ((e = smtp_init(&srv, acc->domain, msg, errstr)) != SMTP_EOK)
        {
            msmtp_endsession(&srv, 0);
            e = smtp_exitcode(e);
            goto error_exit;
        }
    }
#endif /* HAVE_TLS */

    /* end session */
    msmtp_endsession(&srv, 1);

    /* print results */
    if (server_canonical_name && server_address)
    {
        printf(_("%s server at %s (%s [%s]), port %d:\n"),
                acc->protocol == SMTP_PROTO_SMTP ? "SMTP" : "LMTP",
                acc->host ? acc->host : acc->socketname,
                server_canonical_name, server_address, acc->port);
    }
    else if (server_canonical_name)
    {
        printf(_("%s server at %s (%s), port %d:\n"),
                acc->protocol == SMTP_PROTO_SMTP ? "SMTP" : "LMTP",
                acc->host ? acc->host : acc->socketname,
                server_canonical_name, acc->port);
    }
    else if (server_address)
    {
        printf(_("%s server at %s ([%s]), port %d:\n"),
                acc->protocol == SMTP_PROTO_SMTP ? "SMTP" : "LMTP",
                acc->host ? acc->host : acc->socketname,
                server_address, acc->port);
    }
    else
    {
        printf(_("%s server at %s, port %d:\n"),
                acc->protocol == SMTP_PROTO_SMTP ? "SMTP" : "LMTP",
                acc->host ? acc->host : acc->socketname,
                acc->port);
    }
    if (*server_greeting != '\0')
    {
        printf("    %s\n", sanitize_string(server_greeting));
    }
#ifdef HAVE_TLS
    if (acc->tls)
    {
        mtls_print_info(mtls_parameter_description, tci);
    }
#endif /* HAVE_TLS */
#ifdef HAVE_TLS
    if (srv.cap.flags == 0 && !(acc->tls && !acc->tls_nostarttls))
#else /* not HAVE_TLS */
    if (srv.cap.flags == 0)
#endif /* not HAVE_TLS */
    {
        printf(_("No special capabilities.\n"));
    }
    else
    {
        printf(_("Capabilities:\n"));
        if (srv.cap.flags & SMTP_CAP_SIZE)
        {
            printf("    SIZE %ld:\n        %s", srv.cap.size,
                    _("Maximum message size is "));
            if (srv.cap.size == 0)
            {
                printf(_("unlimited\n"));
            }
            else
            {
                printf(_("%ld bytes"), srv.cap.size);
                if (srv.cap.size > 1024 * 1024)
                {
                    printf(_(" = %.2f MiB"),
                            (float)srv.cap.size / (float)(1024 * 1024));
                }
                else if (srv.cap.size > 1024)
                {
                    printf(_(" = %.2f KiB"), (float)srv.cap.size / 1024.0f);
                }
                printf("\n");
            }
        }
        if (srv.cap.flags & SMTP_CAP_PIPELINING)
        {
            printf("    PIPELINING:\n        %s\n", _("Support for command "
                        "grouping for faster transmission"));
        }
        if (srv.cap.flags & SMTP_CAP_ETRN)
        {
            printf("    ETRN:\n        %s\n", _("Support for RMQS "
                        "(Remote Message Queue Starting)"));
        }
        if (srv.cap.flags & SMTP_CAP_DSN)
        {
            printf("    DSN:\n        %s\n", _("Support for "
                        "Delivery Status Notifications"));
        }
#ifdef HAVE_TLS
        if ((acc->tls && !acc->tls_nostarttls)
                || (srv.cap.flags & SMTP_CAP_STARTTLS))
#else /* not HAVE_TLS */
        if (srv.cap.flags & SMTP_CAP_STARTTLS)
#endif /* not HAVE_TLS */
        {
            printf("    STARTTLS:\n        %s\n", _("Support for "
                        "TLS encryption via the STARTTLS command"));
        }
        if (srv.cap.flags & SMTP_CAP_AUTH)
        {
            printf("    AUTH:\n        %s\n        ",
                    _("Supported authentication methods:"));
            if (srv.cap.flags & SMTP_CAP_AUTH_SCRAM_SHA_256_PLUS)
                printf("SCRAM-SHA-256-PLUS ");
            if (srv.cap.flags & SMTP_CAP_AUTH_SCRAM_SHA_1_PLUS)
                printf("SCRAM-SHA-1-PLUS ");
            if (srv.cap.flags & SMTP_CAP_AUTH_SCRAM_SHA_256)
                printf("SCRAM-SHA-256 ");
            if (srv.cap.flags & SMTP_CAP_AUTH_SCRAM_SHA_1)
                printf("SCRAM-SHA-1 ");
            if (srv.cap.flags & SMTP_CAP_AUTH_PLAIN)
                printf("PLAIN ");
            if (srv.cap.flags & SMTP_CAP_AUTH_GSSAPI)
                printf("GSSAPI ");
            if (srv.cap.flags & SMTP_CAP_AUTH_EXTERNAL)
                printf("EXTERNAL ");
            if (srv.cap.flags & SMTP_CAP_AUTH_OAUTHBEARER)
                printf("OAUTHBEARER ");
            if (srv.cap.flags & SMTP_CAP_AUTH_CRAM_MD5)
                printf("CRAM-MD5 ");
            if (srv.cap.flags & SMTP_CAP_AUTH_DIGEST_MD5)
                printf("DIGEST-MD5 ");
            if (srv.cap.flags & SMTP_CAP_AUTH_LOGIN)
                printf("LOGIN ");
            if (srv.cap.flags & SMTP_CAP_AUTH_NTLM)
                printf("NTLM ");
            if (srv.cap.flags & SMTP_CAP_AUTH_XOAUTH2)
                printf("XOAUTH2 ");
            printf("\n");
        }
#ifdef HAVE_TLS
        if ((srv.cap.flags & SMTP_CAP_STARTTLS) && !acc->tls)
#else /* not HAVE_TLS */
        if (srv.cap.flags & SMTP_CAP_STARTTLS)
#endif /* not HAVE_TLS */
        {
            printf(_("This server might advertise more or other "
                    "capabilities when TLS is active.\n"));
        }
    }

    e = EX_OK;

error_exit:
    free(server_canonical_name);
    free(server_address);
#ifdef HAVE_TLS
    if (tci)
    {
        mtls_cert_info_free(tci);
    }
    free(mtls_parameter_description);
#endif /* HAVE_TLS */
    free(server_greeting);
    return e;
}


/*
 * msmtp_read_headers()
 *
 * Copies the headers of the mail from 'mailf' to a temporary file 'tmpf',
 * including the blank line that separates the header from the body of the mail.
 *
 * If 'recipients' is not NULL: extracts all recipients from the To, Cc, and Bcc
 * headers and adds them to 'recipients'. If Resent-* headers are present, all
 * recipients from the Resent-To, Resent-Cc, Resent-Bcc headers in the first
 * block of Resent- headers are extracted instead.
 *
 * If 'from' is not NULL: extracts the address from the From header and stores
 * it in an allocated string. A pointer to this string is stored in 'from'.
 * If a Resent-From header is present (and appears before any From header), the
 * first sucher header is used instead.
 *
 * If 'have_date' is not NULL: set this flag to 1 if a Date header is present,
 * and to 0 otherwise.
 *
 * If 'have_msgid' is not NULL: set this flag to 1 if a Message-ID header is
 * present, and to 0 otherwise.
 *
 * See RFC2822, section 3 for the format of these headers.
 *
 * Return codes: EX_OK, EX_IOERR
 */

#define STATE_LINESTART_FRESH           0       /* a new line started; the
                                                   previous line was not a
                                                   recipient header */
#define STATE_LINESTART_AFTER_ADDRHDR   1       /* a new line started; the
                                                   previous line was a
                                                   recipient header */
#define STATE_OTHER_HDR                 2       /* a header we don't
                                                   care about */
#define STATE_DATE1                     3       /* we saw "^D" */
#define STATE_DATE2                     4       /* we saw "^Da" */
#define STATE_DATE3                     5       /* we saw "^Dat" */
#define STATE_DATE4                     6       /* we saw "^Date" */
#define STATE_MSGID1                    7       /* we saw "^M" */
#define STATE_MSGID2                    8       /* we saw "^Me" */
#define STATE_MSGID3                    9       /* we saw "^Mes" */
#define STATE_MSGID4                    10      /* we saw "^Mess" */
#define STATE_MSGID5                    11      /* we saw "^Messa" */
#define STATE_MSGID6                    12      /* we saw "^Messag" */
#define STATE_MSGID7                    13      /* we saw "^Message" */
#define STATE_MSGID8                    14      /* we saw "^Message-" */
#define STATE_MSGID9                    15      /* we saw "^Message-I" */
#define STATE_MSGID10                   16      /* we saw "^Message-ID" */
#define STATE_FROM1                     17      /* we saw "^F" */
#define STATE_FROM2                     18      /* we saw "^Fr" */
#define STATE_FROM3                     19      /* we saw "^Fro" */
#define STATE_TO                        20      /* we saw "^T" */
#define STATE_CC                        21      /* we saw "^C" */
#define STATE_BCC1                      22      /* we saw "^B" */
#define STATE_BCC2                      23      /* we saw "^Bc" */
#define STATE_ADDRHDR_ALMOST            24      /* we saw "^To", "^Cc"
                                                   or "^Bcc" */
#define STATE_RESENT                    25      /* we saw part of "^Resent-" */
#define STATE_ADDRHDR_DEFAULT           26      /* in_rcpt_hdr and in_rcpt
                                                   state our position */
#define STATE_ADDRHDR_DQUOTE            27      /* duoble quotes */
#define STATE_ADDRHDR_BRACKETS_START    28      /* entering <...> */
#define STATE_ADDRHDR_IN_BRACKETS       29      /* an address inside <> */
#define STATE_ADDRHDR_PARENTH_START     30      /* entering (...) */
#define STATE_ADDRHDR_IN_PARENTH        31      /* a comment inside () */
#define STATE_ADDRHDR_IN_ADDRESS        32      /* a bare address */
#define STATE_ADDRHDR_BACKQUOTE         33      /* we saw a '\\' */
#define STATE_HEADERS_END               34      /* we saw "^$", the blank line
                                                   between headers and body */

int msmtp_read_headers(FILE *mailf, FILE *tmpf,
        list_t *recipients,
        char **from,
        int *have_date,
        int *have_msgid,
        char **errstr)
{
    int c;
    int state = STATE_LINESTART_FRESH;
    int oldstate = STATE_LINESTART_FRESH;
    int backquote_savestate = STATE_LINESTART_FRESH;
    int parentheses_depth = 0;
    int parentheses_savestate = STATE_LINESTART_FRESH;
    int folded_rcpthdr_savestate = STATE_LINESTART_FRESH;
    int from_hdr = -1;          /* -1 = before, 0 = in, 1 = after first From: */
    int resent_index = -1;
    int resent_block = -1;      /* -1 = before, 0 = in, 1 = after first block */
    char *current_recipient = NULL;
    size_t current_recipient_len = 0;
    int forget_current_recipient = 0;
    int finish_current_recipient = 0;
    size_t bufsize = 0;
    /* The buffer that is filled with the current recipient grows by
     * 'bufsize_step' if the remaining space becomes too small. This value must
     * be at least 2. Wasted characters are at most (bufsize_step - 1). A value
     * of 10 means low wasted space and a low number of realloc()s per
     * recipient. */
    const size_t bufsize_step = 10;
    /* We need two recipient lists: one for normal To, Cc, Bcc headers, and one
     * for Resent-To, Resent-Cc, Resent-Bcc. The first list gathers adresses
     * from all To, Cc, Bcc headers that are found. The second list gathers
     * adresses only for the first block of Resent-* headers. If a Resent- block
     * was seen, then the first list is ignored, and only the second list is
     * appended to the recipient list given by the caller. */
    list_t *normal_recipients_list = NULL;
    list_t *normal_recipients = NULL;
    list_t *resent_recipients_list = NULL;
    list_t *resent_recipients = NULL;

    if (from)
    {
        *from = NULL;
    }
    if (have_date)
    {
        *have_date = 0;
    }
    if (have_msgid)
    {
        *have_msgid = 0;
    }
    if (recipients)
    {
        normal_recipients_list = list_new();
        normal_recipients = normal_recipients_list;
        resent_recipients_list = list_new();
        resent_recipients = resent_recipients_list;
    }

    for (;;)
    {
        c = fgetc(mailf);
        /* Convert CRLF to LF. According to RFC 2822, CRs may only occur in a
         * mail when they are followed by LF, so just ignoring CRs is ok. */
        if (c == '\r')
        {
            continue;
        }
        oldstate = state;
        if (c == EOF)
        {
            state = STATE_HEADERS_END;
            if (current_recipient)
                finish_current_recipient = 1;
        }
        else
        {
            switch (state)
            {
                case STATE_LINESTART_FRESH:
                    parentheses_depth = 0;
                    resent_index = -1;
                    if (have_date && (c == 'd' || c == 'D'))
                        state = STATE_DATE1;
                    else if (have_msgid && (c == 'm' || c == 'M'))
                        state = STATE_MSGID1;
                    else if (from && from_hdr < 0 && (c == 'f' || c == 'F'))
                        state = STATE_FROM1;
                    else if (recipients && (c == 't' || c == 'T'))
                        state = STATE_TO;
                    else if (recipients && (c == 'c' || c == 'C'))
                        state = STATE_CC;
                    else if (recipients && (c == 'b' || c == 'B'))
                        state = STATE_BCC1;
                    else if ((from || recipients) && resent_block <= 0
                            && (c == 'r' || c == 'R'))
                    {
                        resent_index = 0;
                        state = STATE_RESENT;
                    }
                    else if (c == '\n')
                        state = STATE_HEADERS_END;
                    else
                        state = STATE_OTHER_HDR;
                    break;

                case STATE_LINESTART_AFTER_ADDRHDR:
                    resent_index = -1;
                    if (c != ' ' && c != '\t')
                    {
                        if (current_recipient)
                            finish_current_recipient = 1;
                        else if (from_hdr == 0)
                            from_hdr = -1; /* the preceding From: header was empty */
                    }
                    if (c == ' ' || c == '\t')
                        state = folded_rcpthdr_savestate;
                    else if (have_date && (c == 'd' || c == 'D'))
                        state = STATE_DATE1;
                    else if (have_msgid && (c == 'm' || c == 'M'))
                        state = STATE_MSGID1;
                    else if (from && from_hdr < 0 && (c == 'f' || c == 'F'))
                        state = STATE_FROM1;
                    else if (recipients && (c == 't' || c == 'T'))
                        state = STATE_TO;
                    else if (recipients && (c == 'c' || c == 'C'))
                        state = STATE_CC;
                    else if (recipients && (c == 'b' || c == 'B'))
                        state = STATE_BCC1;
                    else if (recipients && resent_block <= 0
                        && (c == 'r' || c == 'R'))
                    {
                        resent_index = 0;
                        state = STATE_RESENT;
                    }
                    else if (c == '\n')
                        state = STATE_HEADERS_END;
                    else
                        state = STATE_OTHER_HDR;
                    break;

                case STATE_OTHER_HDR:
                    if (resent_block == 0 && resent_index != 6)
                        resent_block = 1;
                    if (c == '\n')
                        state = STATE_LINESTART_FRESH;
                    break;

                case STATE_RESENT:
                    if (resent_index == 0 && (c == 'e' || c == 'E'))
                        resent_index++;
                    else if (resent_index == 1 && (c == 's' || c == 'S'))
                        resent_index++;
                    else if (resent_index == 2 && (c == 'e' || c == 'E'))
                        resent_index++;
                    else if (resent_index == 3 && (c == 'n' || c == 'N'))
                        resent_index++;
                    else if (resent_index == 4 && (c == 't' || c == 'T'))
                        resent_index++;
                    else if (resent_index == 5 && c == '-')
                    {
                        if (resent_block == -1)
                            resent_block = 0;
                        resent_index++;
                    }
                    else if (resent_index == 6 && (c == 'f' || c == 'F'))
                        state = STATE_FROM1;
                    else if (resent_index == 6 && (c == 't' || c == 'T'))
                        state = STATE_TO;
                    else if (resent_index == 6 && (c == 'c' || c == 'C'))
                        state = STATE_CC;
                    else if (resent_index == 6 && (c == 'b' || c == 'B'))
                        state = STATE_BCC1;
                    else if (c == '\n')
                        state = STATE_LINESTART_FRESH;
                    else
                        state = STATE_OTHER_HDR;
                    break;

                case STATE_DATE1:
                    if (c == 'a' || c == 'A')
                        state = STATE_DATE2;
                    else if (c == '\n')
                        state = STATE_LINESTART_FRESH;
                    else
                        state = STATE_OTHER_HDR;
                    break;

                case STATE_DATE2:
                    if (c == 't' || c == 'T')
                        state = STATE_DATE3;
                    else if (c == '\n')
                        state = STATE_LINESTART_FRESH;
                    else
                        state = STATE_OTHER_HDR;
                    break;

                case STATE_DATE3:
                    if (c == 'e' || c == 'E')
                        state = STATE_DATE4;
                    else if (c == '\n')
                        state = STATE_LINESTART_FRESH;
                    else
                        state = STATE_OTHER_HDR;
                    break;

                case STATE_DATE4:
                    if (c == ':')
                    {
                        *have_date = 1;
                        state = STATE_OTHER_HDR;
                    }
                    else if (c == '\n')
                        state = STATE_LINESTART_FRESH;
                    else
                        state = STATE_OTHER_HDR;
                    break;

                case STATE_MSGID1:
                    if (c == 'e' || c == 'E')
                        state = STATE_MSGID2;
                    else if (c == '\n')
                        state = STATE_LINESTART_FRESH;
                    else
                        state = STATE_OTHER_HDR;
                    break;

                case STATE_MSGID2:
                    if (c == 's' || c == 'S')
                        state = STATE_MSGID3;
                    else if (c == '\n')
                        state = STATE_LINESTART_FRESH;
                    else
                        state = STATE_OTHER_HDR;
                    break;

                case STATE_MSGID3:
                    if (c == 's' || c == 'S')
                        state = STATE_MSGID4;
                    else if (c == '\n')
                        state = STATE_LINESTART_FRESH;
                    else
                        state = STATE_OTHER_HDR;
                    break;

                case STATE_MSGID4:
                    if (c == 'a' || c == 'A')
                        state = STATE_MSGID5;
                    else if (c == '\n')
                        state = STATE_LINESTART_FRESH;
                    else
                        state = STATE_OTHER_HDR;
                    break;

                case STATE_MSGID5:
                    if (c == 'g' || c == 'G')
                        state = STATE_MSGID6;
                    else if (c == '\n')
                        state = STATE_LINESTART_FRESH;
                    else
                        state = STATE_OTHER_HDR;
                    break;

                case STATE_MSGID6:
                    if (c == 'e' || c == 'E')
                        state = STATE_MSGID7;
                    else if (c == '\n')
                        state = STATE_LINESTART_FRESH;
                    else
                        state = STATE_OTHER_HDR;
                    break;

                case STATE_MSGID7:
                    if (c == '-')
                        state = STATE_MSGID8;
                    else if (c == '\n')
                        state = STATE_LINESTART_FRESH;
                    else
                        state = STATE_OTHER_HDR;
                    break;

                case STATE_MSGID8:
                    if (c == 'i' || c == 'I')
                        state = STATE_MSGID9;
                    else if (c == '\n')
                        state = STATE_LINESTART_FRESH;
                    else
                        state = STATE_OTHER_HDR;
                    break;

                case STATE_MSGID9:
                    if (c == 'd' || c == 'D')
                        state = STATE_MSGID10;
                    else if (c == '\n')
                        state = STATE_LINESTART_FRESH;
                    else
                        state = STATE_OTHER_HDR;
                    break;

                case STATE_MSGID10:
                    if (c == ':')
                    {
                        *have_msgid = 1;
                        state = STATE_OTHER_HDR;
                    }
                    else if (c == '\n')
                        state = STATE_LINESTART_FRESH;
                    else
                        state = STATE_OTHER_HDR;
                    break;

                case STATE_FROM1:
                    if (resent_block == 0 && resent_index != 6)
                        resent_block = 1;
                    if (c == 'r' || c == 'R')
                        state = STATE_FROM2;
                    else if (c == '\n')
                        state = STATE_LINESTART_FRESH;
                    else
                        state = STATE_OTHER_HDR;
                    break;

                case STATE_FROM2:
                    if (c == 'o' || c == 'O')
                        state = STATE_FROM3;
                    else if (c == '\n')
                        state = STATE_LINESTART_FRESH;
                    else
                        state = STATE_OTHER_HDR;
                    break;

                case STATE_FROM3:
                    if (c == 'm' || c == 'M')
                    {
                        from_hdr = 0;
                        state = STATE_ADDRHDR_ALMOST;
                    }
                    else if (c == '\n')
                        state = STATE_LINESTART_FRESH;
                    else
                        state = STATE_OTHER_HDR;
                    break;

                case STATE_TO:
                    if (resent_block == 0 && resent_index != 6)
                        resent_block = 1;
                    if (c == 'o' || c == 'O')
                        state = STATE_ADDRHDR_ALMOST;
                    else if (c == '\n')
                        state = STATE_LINESTART_FRESH;
                    else
                        state = STATE_OTHER_HDR;
                    break;

                case STATE_CC:
                    if (resent_block == 0 && resent_index != 6)
                        resent_block = 1;
                    if (c == 'c' || c == 'C')
                        state = STATE_ADDRHDR_ALMOST;
                    else if (c == '\n')
                        state = STATE_LINESTART_FRESH;
                    else
                        state = STATE_OTHER_HDR;
                    break;

                case STATE_BCC1:
                    if (resent_block == 0 && resent_index != 6)
                        resent_block = 1;
                    if (c == 'c' || c == 'C')
                        state = STATE_BCC2;
                    else if (c == '\n')
                        state = STATE_LINESTART_FRESH;
                    else
                        state = STATE_OTHER_HDR;
                    break;

                case STATE_BCC2:
                    if (c == 'c' || c == 'C')
                        state = STATE_ADDRHDR_ALMOST;
                    else if (c == '\n')
                        state = STATE_LINESTART_FRESH;
                    else
                        state = STATE_OTHER_HDR;
                    break;

                case STATE_ADDRHDR_ALMOST:
                    if (from_hdr == 0 && c != ':')
                        from_hdr = -1;
                    if (c == ':')
                        state = STATE_ADDRHDR_DEFAULT;
                    else if (c == '\n')
                        state = STATE_LINESTART_FRESH;
                    else
                        state = STATE_OTHER_HDR;
                    break;

                case STATE_ADDRHDR_DEFAULT:
                    if (c == '\n')
                    {
                        if (current_recipient)
                            finish_current_recipient = 1;
                        folded_rcpthdr_savestate = state;
                        state = STATE_LINESTART_AFTER_ADDRHDR;
                    }
                    else if (c == '\\')
                    {
                        backquote_savestate = state;
                        state = STATE_ADDRHDR_BACKQUOTE;
                    }
                    else if (c == '(')
                    {
                        parentheses_savestate = state;
                        state = STATE_ADDRHDR_PARENTH_START;
                    }
                    else if (c == '"')
                    {
                        if (current_recipient)
                            forget_current_recipient = 1;
                        state = STATE_ADDRHDR_DQUOTE;
                    }
                    else if (c == '<')
                    {
                        if (current_recipient)
                            forget_current_recipient = 1;
                        state = STATE_ADDRHDR_BRACKETS_START;
                    }
                    else if (c == ' ' || c == '\t')
                        ; /* keep state */
                    else if (c == ':')
                    {
                        if (current_recipient)
                            forget_current_recipient = 1;
                    }
                    else if (c == ';' || c == ',')
                    {
                        if (current_recipient)
                            finish_current_recipient = 1;
                    }
                    else
                    {
                        if (current_recipient)
                            forget_current_recipient = 1;
                        state = STATE_ADDRHDR_IN_ADDRESS;
                    }
                    break;

                case STATE_ADDRHDR_DQUOTE:
                    if (c == '\n')
                    {
                        folded_rcpthdr_savestate = state;
                        state = STATE_LINESTART_AFTER_ADDRHDR;
                    }
                    else if (c == '\\')
                    {
                        backquote_savestate = state;
                        state = STATE_ADDRHDR_BACKQUOTE;
                    }
                    else if (c == '"')
                        state = STATE_ADDRHDR_DEFAULT;
                    break;

                case STATE_ADDRHDR_BRACKETS_START:
                    if (c == '\n')
                    {
                        folded_rcpthdr_savestate = state;
                        state = STATE_LINESTART_AFTER_ADDRHDR;
                    }
                    else if (c == '(')
                    {
                        parentheses_savestate = state;
                        state = STATE_ADDRHDR_PARENTH_START;
                    }
                    else if (c == '>')
                        state = STATE_ADDRHDR_DEFAULT;
                    else
                        state = STATE_ADDRHDR_IN_BRACKETS;
                    break;

                case STATE_ADDRHDR_IN_BRACKETS:
                    if (c == '\n')
                    {
                        folded_rcpthdr_savestate = state;
                        state = STATE_LINESTART_AFTER_ADDRHDR;
                    }
                    else if (c == '\\')
                    {
                        backquote_savestate = state;
                        state = STATE_ADDRHDR_BACKQUOTE;
                    }
                    else if (c == '(')
                    {
                        parentheses_savestate = state;
                        state = STATE_ADDRHDR_PARENTH_START;
                    }
                    else if (c == '>')
                    {
                        finish_current_recipient = 1;
                        state = STATE_ADDRHDR_DEFAULT;
                    }
                    break;

                case STATE_ADDRHDR_PARENTH_START:
                    if (c == '\n')
                    {
                        folded_rcpthdr_savestate = state;
                        state = STATE_LINESTART_AFTER_ADDRHDR;
                    }
                    else if (c == ')')
                        state = parentheses_savestate;
                    else
                    {
                        parentheses_depth++;
                        state = STATE_ADDRHDR_IN_PARENTH;
                    }
                    break;

                case STATE_ADDRHDR_IN_PARENTH:
                    if (c == '\n')
                    {
                        folded_rcpthdr_savestate = state;
                        state = STATE_LINESTART_AFTER_ADDRHDR;
                    }
                    else if (c == '\\')
                    {
                        backquote_savestate = state;
                        state = STATE_ADDRHDR_BACKQUOTE;
                    }
                    else if (c == '(')
                        state = STATE_ADDRHDR_PARENTH_START;
                    else if (c == ')')
                    {
                        parentheses_depth--;
                        if (parentheses_depth == 0)
                            state = parentheses_savestate;
                    }
                    break;

                case STATE_ADDRHDR_IN_ADDRESS:
                    if (c == '\n')
                    {
                        folded_rcpthdr_savestate = STATE_ADDRHDR_DEFAULT;
                        state = STATE_LINESTART_AFTER_ADDRHDR;
                    }
                    else if (c == '\\')
                    {
                        backquote_savestate = state;
                        state = STATE_ADDRHDR_BACKQUOTE;
                    }
                    else if (c == '"')
                    {
                        forget_current_recipient = 1;
                        state = STATE_ADDRHDR_DQUOTE;
                    }
                    else if (c == '(')
                    {
                        parentheses_savestate = state;
                        state = STATE_ADDRHDR_PARENTH_START;
                    }
                    else if (c == '<')
                    {
                        forget_current_recipient = 1;
                        state = STATE_ADDRHDR_BRACKETS_START;
                    }
                    else if (c == ' ' || c == '\t')
                        state = STATE_ADDRHDR_DEFAULT;
                    else if (c == ':')
                    {
                        forget_current_recipient = 1;
                        state = STATE_ADDRHDR_DEFAULT;
                    }
                    else if (c == ',' || c == ';')
                    {
                        finish_current_recipient = 1;
                        state = STATE_ADDRHDR_DEFAULT;
                    }
                    break;

                case STATE_ADDRHDR_BACKQUOTE:
                    if (c == '\n')
                    {
                        folded_rcpthdr_savestate = STATE_ADDRHDR_DEFAULT;
                        state = STATE_LINESTART_AFTER_ADDRHDR;
                    }
                    else
                        state = backquote_savestate;
                    break;
            }
        }

        if (tmpf && c != EOF && fputc(c, tmpf) == EOF)
        {
            *errstr = xasprintf(_("cannot write mail headers to temporary "
                        "file: output error"));
            goto error_exit;
        }

        if (forget_current_recipient)
        {
            /* this was just junk */
            free(current_recipient);
            current_recipient = NULL;
            current_recipient_len = 0;
            bufsize = 0;
            forget_current_recipient = 0;
        }
        if (finish_current_recipient)
        {
            /* The current recipient just ended. Add it to the list */
            current_recipient[current_recipient_len] = '\0';
            if (from_hdr == 0)
            {
                *from = current_recipient;
                from_hdr = 1;
            }
            else if (recipients && resent_block == 0)
            {
                list_insert(resent_recipients, current_recipient);
                resent_recipients = resent_recipients->next;
            }
            else if (recipients)
            {
                list_insert(normal_recipients, current_recipient);
                normal_recipients = normal_recipients->next;
            }
            /* Reset for the next recipient */
            current_recipient = NULL;
            current_recipient_len = 0;
            bufsize = 0;
            finish_current_recipient = 0;
        }
        if ((state == STATE_ADDRHDR_IN_ADDRESS
                    || state == STATE_ADDRHDR_IN_BRACKETS)
                && oldstate != STATE_ADDRHDR_PARENTH_START
                && oldstate != STATE_ADDRHDR_IN_PARENTH
                && oldstate != STATE_LINESTART_AFTER_ADDRHDR)
        {
            /* Add this character to the current recipient */
            current_recipient_len++;
            if (bufsize < current_recipient_len + 1)
            {
                bufsize += bufsize_step;
                current_recipient = xrealloc(current_recipient,
                        bufsize * sizeof(char));
            }
            /* sanitize characters */
            if (!iscntrl((unsigned char)c) && !isspace((unsigned char)c))
            {
                current_recipient[current_recipient_len - 1] = (char)c;
            }
            else
            {
                current_recipient[current_recipient_len - 1] = '_';
            }
        }

        if (state == STATE_HEADERS_END)
        {
            break;
        }
    }

    /* Corner case: we saw a "From: " header without a recipient. */
    if (from_hdr == 0)
    {
        *from = xstrdup("");
    }

    if (recipients)
    {
        if (resent_block >= 0)
        {
            list_xfree(normal_recipients_list, free);
            resent_recipients = resent_recipients_list;
            while (!list_is_empty(resent_recipients))
            {
                resent_recipients = resent_recipients->next;
                list_insert(recipients, resent_recipients->data);
                recipients = recipients->next;
            }
            list_free(resent_recipients_list);
        }
        else
        {
            list_xfree(resent_recipients_list, free);
            normal_recipients = normal_recipients_list;
            while (!list_is_empty(normal_recipients))
            {
                normal_recipients = normal_recipients->next;
                list_insert(recipients, normal_recipients->data);
                recipients = recipients->next;
            }
            list_free(normal_recipients_list);
        }
        normal_recipients_list = NULL;
        resent_recipients_list = NULL;
    }

    if (ferror(mailf))
    {
        *errstr = xasprintf(_("input error while reading the mail"));
        goto error_exit;
    }

    return EX_OK;

error_exit:
    if (normal_recipients_list)
    {
        list_xfree(normal_recipients_list, free);
    }
    if (resent_recipients_list)
    {
        list_xfree(resent_recipients_list, free);
    }
    if (from)
    {
        free(*from);
        *from = NULL;
    }
    free(current_recipient);
    return EX_IOERR;
}


/*
 * msmtp_sendmail()
 *
 * Sends a mail. Returns a value from sysexits.h.
 * If an error occurred, '*errstr' points to an allocated string that describes
 * the error or is NULL, and '*msg' may contain the offending message from the
 * SMTP server (or be NULL).
 * In case of success, 'mailsize' contains the number of bytes of the mail
 * transferred to the SMTP server. In case of failure, its contents are
 * undefined.
 */

int msmtp_sendmail(account_t *acc, list_t *recipients,
        FILE *prepend_header_file, int prepend_header_contains_from,
        FILE *header_file, FILE *f,
        int debug, long *mailsize,
        list_t **lmtp_errstrs, list_t **lmtp_error_msgs,
        list_t **msg, char **errstr)
{
    smtp_server_t srv;
    int e;
#ifdef HAVE_TLS
    mtls_cert_info_t *tci = NULL;
    char *mtls_parameter_description = NULL;
#endif /* HAVE_TLS */

    *errstr = NULL;
    *msg = NULL;
    *lmtp_errstrs = NULL;
    *lmtp_error_msgs = NULL;

    /* create a new smtp_server_t */
    srv = smtp_new(debug ? stdout : NULL, acc->protocol);

    /* prepare tls */
#ifdef HAVE_TLS
    if (acc->tls)
    {
        if ((e = smtp_tls_init(&srv,
                        acc->tls_key_file, acc->tls_cert_file, acc->password,
                        acc->tls_trust_file, acc->tls_crl_file,
                        acc->tls_sha256_fingerprint,
                        acc->tls_sha1_fingerprint, acc->tls_md5_fingerprint,
                        acc->tls_min_dh_prime_bits,
                        acc->tls_priorities,
                        acc->tls_host_override ? acc->tls_host_override : acc->host,
                        acc->tls_nocertcheck,
                        errstr)) != TLS_EOK)
        {
            e = mtls_exitcode(e);
            return e;
        }
    }
#endif /* HAVE_TLS */

    /* connect */
    if ((e = smtp_connect(&srv, acc->socketname, acc->proxy_host, acc->proxy_port,
                    acc->host, acc->port, acc->source_ip, acc->timeout,
                    NULL, NULL, errstr)) != NET_EOK)
    {
        e = net_exitcode(e);
        return e;
    }

    /* start tls for smtps servers */
#ifdef HAVE_TLS
    if (acc->tls && acc->tls_nostarttls)
    {
        if (debug)
        {
            tci = mtls_cert_info_new();
        }
        if ((e = smtp_tls(&srv, tci,
                        &mtls_parameter_description, errstr)) != TLS_EOK)
        {
            if (debug)
            {
                mtls_cert_info_free(tci);
                free(mtls_parameter_description);
            }
            msmtp_endsession(&srv, 0);
            e = mtls_exitcode(e);
            return e;
        }
        if (debug)
        {
            mtls_print_info(mtls_parameter_description, tci);
            mtls_cert_info_free(tci);
            free(mtls_parameter_description);
        }
    }
#endif /* HAVE_TLS */

    /* get greeting */
    if ((e = smtp_get_greeting(&srv, msg, NULL, errstr)) != SMTP_EOK)
    {
        msmtp_endsession(&srv, 0);
        e = smtp_exitcode(e);
        return e;
    }

    /* initialize session */
    if ((e = smtp_init(&srv, acc->domain, msg, errstr)) != SMTP_EOK)
    {
        msmtp_endsession(&srv, 0);
        e = smtp_exitcode(e);
        return e;
    }

    /* start tls for starttls servers */
#ifdef HAVE_TLS
    if (acc->tls && !acc->tls_nostarttls)
    {
        if (!(srv.cap.flags & SMTP_CAP_STARTTLS))
        {
            *errstr = xasprintf(_("the server does not support TLS "
                        "via the STARTTLS command"));
            msmtp_endsession(&srv, 1);
            e = EX_UNAVAILABLE;
            return e;
        }
        if ((e = smtp_tls_starttls(&srv, msg, errstr)) != SMTP_EOK)
        {
            msmtp_endsession(&srv, 0);
            e = smtp_exitcode(e);
            return e;
        }
        if (debug)
        {
            tci = mtls_cert_info_new();
        }
        if ((e = smtp_tls(&srv, tci,
                        &mtls_parameter_description, errstr)) != TLS_EOK)
        {
            if (debug)
            {
                mtls_cert_info_free(tci);
                free(mtls_parameter_description);
            }
            msmtp_endsession(&srv, 0);
            e = mtls_exitcode(e);
            return e;
        }
        if (debug)
        {
            mtls_print_info(mtls_parameter_description, tci);
            mtls_cert_info_free(tci);
            free(mtls_parameter_description);
        }
        /* initialize again */
        if ((e = smtp_init(&srv, acc->domain, msg, errstr)) != SMTP_EOK)
        {
            msmtp_endsession(&srv, 0);
            e = smtp_exitcode(e);
            return e;
        }
    }
#endif /* HAVE_TLS */

    /* test for needed features */
    if ((acc->dsn_return || acc->dsn_notify) && !(srv.cap.flags & SMTP_CAP_DSN))
    {
        *errstr = xasprintf(_("the server does not support DSN"));
        msmtp_endsession(&srv, 1);
        e = EX_UNAVAILABLE;
        return e;
    }
    /* authenticate */
    if (acc->auth_mech)
    {
        if (!(srv.cap.flags & SMTP_CAP_AUTH))
        {
            *errstr = xasprintf(
                    _("the server does not support authentication"));
            msmtp_endsession(&srv, 1);
            e = EX_UNAVAILABLE;
            return e;
        }
        if ((e = smtp_auth(&srv, acc->host ? acc->host : acc->socketname,
                        acc->port, acc->username, acc->password,
                        acc->ntlmdomain, acc->auth_mech,
                        msmtp_password_callback, msg, errstr))
                != SMTP_EOK)
        {
            msmtp_endsession(&srv, 0);
            e = smtp_exitcode(e);
            return e;
        }
    }

    /* send the envelope */
    if ((e = smtp_send_envelope(&srv, acc->from, recipients,
                    acc->dsn_notify, acc->dsn_return, msg, errstr)) != SMTP_EOK)
    {
        msmtp_endsession(&srv, 0);
        e = smtp_exitcode(e);
        return e;
    }
    /* send header and body */
    *mailsize = 0;
    if (prepend_header_file)
    {
        /* first: prepended headers, if any */
        if ((e = smtp_send_mail(&srv, prepend_header_file,
                        1, 1, 1, 1, mailsize,
                        errstr)) != SMTP_EOK)
        {
            msmtp_endsession(&srv, 0);
            e = smtp_exitcode(e);
            return e;
        }
    }
    /* next: original mail headers */
    if ((e = smtp_send_mail(&srv, header_file,
                    !prepend_header_contains_from, /* keep_from */
                    !acc->undisclosed_recipients,  /* keep_to */
                    !acc->undisclosed_recipients,  /* keep_cc */
                    !acc->undisclosed_recipients
                    && !acc->remove_bcc_headers,   /* keep_bcc */
                    mailsize, errstr)) != SMTP_EOK)
    {
        msmtp_endsession(&srv, 0);
        e = smtp_exitcode(e);
        return e;
    }
    /* then: the body from the original file */
    if ((e = smtp_send_mail(&srv, f, 1, 1, 1, 1, mailsize, errstr)) != SMTP_EOK)
    {
        msmtp_endsession(&srv, 0);
        e = smtp_exitcode(e);
        return e;
    }
    /* end the mail */
    if (acc->protocol == SMTP_PROTO_SMTP)
    {
        e = smtp_end_mail(&srv, msg, errstr);
    }
    else
    {
        e = smtp_end_mail_lmtp(&srv, recipients,
                lmtp_errstrs, lmtp_error_msgs, errstr);
    }
    if (e != SMTP_EOK)
    {
        msmtp_endsession(&srv, 0);
        e = smtp_exitcode(e);
        return e;
    }

    /* end session */
    msmtp_endsession(&srv, 1);

    return EX_OK;
}


/*
 * print_error()
 *
 * Print an error message
 */

/* make gcc print format warnings for this function */
#ifdef __GNUC__
void print_error(const char *format, ...)
    __attribute__ ((format (printf, 1, 2)));
#endif

void print_error(const char *format, ...)
{
    va_list args;
    fprintf(stderr, "%s: ", prgname);
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, "\n");
}


/*
 * msmtp_configure()
 *
 * Tries autoconfiguration for the given mail address based on the methods
 * described in RFC 8314 (SRV records).
 * If successfull, this function will print a configuration file excerpt to
 * standard output and return EX_OK.
 * Otherwise, it will print an appropriate error message to standard error
 * and return an EX_* status.
 */

int msmtp_configure(const char *address, const char *conffile)
{
#ifdef HAVE_LIBRESOLV

    int e;

    char *local_part;
    char *domain_part;

    char *submissions_query;
    char *submission_query;

    char *hostname = NULL;
    int port = -1;
    int starttls = -1;

    char *tmpstr;

    split_mail_address(address, &local_part, &domain_part);
    if (!domain_part || domain_part[0] == '\0' || local_part[0] == '\0')
    {
        print_error(_("automatic configuration based on SRV records failed: %s"),
                _("invalid mail address"));
        free(local_part);
        free(domain_part);
        return EX_DATAERR;
    }

    submissions_query = net_get_srv_query(domain_part, "submissions");
    e = net_get_srv_record(submissions_query, &hostname, &port);
    if (e == NET_EOK) {
        starttls = 0;
    } else {
        submission_query = net_get_srv_query(domain_part, "submission");
        e = net_get_srv_record(submission_query, &hostname, &port);
        if (e == NET_EOK) {
            starttls = 1;
        } else {
            char *errstr = xasprintf(_("no SRV records for %s or %s"),
                    submissions_query, submission_query);
            print_error(_("automatic configuration based on SRV records failed: %s"),
                    errstr);
            free(errstr);
            free(submissions_query);
            free(submission_query);
            free(local_part);
            free(domain_part);
            return EX_NOHOST;
        }
        free(submission_query);
    }
    free(submissions_query);

    /* comment header */

    tmpstr = xasprintf(_("copy this to your configuration file %s"), conffile);
    printf("# - %s\n", tmpstr);
    free(tmpstr);
    if (!check_hostname_matches_domain(hostname, domain_part))
        printf("# - %s\n", _("warning: the host does not match the mail domain; please check"));
#if defined HAVE_LIBSECRET
    tmpstr = xasprintf("secret-tool store --label=msmtp host %s service smtp user %s", hostname, local_part);
    printf("# - %s\n#   %s\n", _("add your password to the key ring:"), tmpstr);
    free(tmpstr);
#elif defined HAVE_MACOSXKEYRING
    tmpstr = xasprintf("security add-internet-password -s %s -r smtp -a %s -w", hostname, local_part);
    printf("# - %s\n#   %s\n", _("add your password to the key ring:"), tmpstr);
    free(tmpstr);
#else
    printf("# - %s\n#   %s\n", _("encrypt your password:"), "gpg -e -o ~/.msmtp-password.gpg");
#endif

    /* account definition */
    printf("account %s\n", address);
    printf("host %s\n", hostname);
    printf("port %d\n", port);
    printf("tls on\n");
    printf("tls_starttls %s\n", starttls ? "on" : "off");
    printf("auth on\n");
    printf("user %s\n", local_part);
#if !defined HAVE_LIBSECRET && !defined HAVE_MACOSXKEYRING
    printf("passwordeval gpg --no-tty -q -d ~/.msmtp-password.gpg\n");
#endif
    printf("from %s\n", address);

    free(local_part);
    free(domain_part);
    free(hostname);
    return EX_OK;

#else

    print_error(_("automatic configuration based on SRV records failed: %s"),
            _("this system lacks libresolv"));
    return EX_UNAVAILABLE;

#endif
}


/*
 * msmtp_get_log_info()
 *
 * Gather log information for syslog or logfile and put it in a string:
 * - host=%s
 * - tls=on|off
 * - auth=on|off
 * - user=%s (only if auth == on and username != NULL)
 * - from=%s
 * - recipients=%s,%s,...
 * - mailsize=%s (only if exitcode == EX_OK)
 * - smtpstatus=%s (only if a smtp msg is available)
 * - smtpmsg='%s' (only if a smtp msg is available)
 * - errormsg='%s' (only if exitcode != EX_OK and an error msg is available)
 * - exitcode=%s
 * 'exitcode' must be one of the sysexits.h exitcodes.
 * This function cannot fail.
 */

char *msmtp_get_log_info(account_t *acc, list_t *recipients, long mailsize,
        list_t *errmsg, char *errstr, int exitcode)
{
    int i;
    size_t s;
    list_t *l;
    char *line;
    int n;
    char *p;
    char *tmp;
    /* temporary strings: */
    char *mailsize_str = NULL;
    const char *exitcode_str;
    char *smtpstatus_str = NULL;
    char *smtperrmsg_str = NULL;


    /* gather information */

    line = NULL;
    /* mailsize */
    if (exitcode == EX_OK)
    {
        mailsize_str = xasprintf("%ld", mailsize);
    }
    /* exitcode */
    exitcode_str = exitcode_to_string(exitcode);
    /* smtp status and smtp error message */
    if (errmsg)
    {
        smtpstatus_str = xasprintf("%d", smtp_msg_status(errmsg));
        l = errmsg;
        s = 0;
        while (!list_is_empty(l))
        {
            l = l->next;
            s += strlen(l->data) + 2;
        }
        s += 1;
        smtperrmsg_str = xmalloc(s * sizeof(char));
        smtperrmsg_str[0] = '\'';
        i = 1;
        l = errmsg;
        while (!list_is_empty(l))
        {
            l = l->next;
            p = sanitize_string(l->data);
            while (*p != '\0')
            {
                /* hide single quotes to make the info easy to parse */
                smtperrmsg_str[i] = (*p == '\'') ? '?' : *p;
                p++;
                i++;
            }
            smtperrmsg_str[i++] = '\\';
            smtperrmsg_str[i++] = 'n';
        }
        i -= 2;
        smtperrmsg_str[i++] = '\'';
        smtperrmsg_str[i++] = '\0';
    }

    /* calculate the length of the log line */

    s = 0;
    /* "host=%s " or "socket=%s " */
    if (acc->host)
        s += 5 + strlen(acc->host) + 1;
    else
        s += 7 + strlen(acc->socketname) + 1;
    /* "tls=on|off " */
    s += 4 + (acc->tls ? 2 : 3) + 1;
    /* "auth=on|off " */
    s += 5 + (acc->auth_mech ? 2 : 3) + 1;
    /* "user=%s " */
    if (acc->auth_mech && acc->username)
    {
        s += 5 + strlen(acc->username) + 1;
    }
    /* "from=%s " */
    s += 5 + strlen(acc->from) + 1;
    /* "recipients=%s,%s,... " */
    s += 11;
    l = recipients;
    while (!list_is_empty(l))
    {
        l = l->next;
        s += strlen(l->data) + 1;
    }
    /* "mailsize=%s " */
    if (exitcode == EX_OK)
    {
        s += 9 + strlen(mailsize_str) + 1;
    }
    /* "smtpstatus=%s smtpmsg=%s " */
    if (errmsg)
    {
        s += 11 + strlen(smtpstatus_str) + 1 + 8 + strlen(smtperrmsg_str) + 1;
    }
    /* "errormsg='%s' */
    if (exitcode != EX_OK && errstr[0] != '\0')
    {
        s += 10 + strlen(errstr) + 2;
    }
    /* "exitcode=%s" */
    s += 9 + strlen(exitcode_str);
    /* '\0' */
    s++;

    line = xmalloc(s * sizeof(char));

    /* build the log line */

    p = line;
    n = snprintf(p, s, "%s=%s tls=%s auth=%s ",
            acc->host ? "host" : "socket",
            acc->host ? acc->host : acc->socketname,
            (acc->tls ? "on" : "off"),
            (acc->auth_mech ? "on" : "off"));
    s -= n;
    p += n;
    if (acc->auth_mech && acc->username)
    {
        n = snprintf(p, s, "user=%s ", acc->username);
        s -= n;
        p += n;
    }
    n = snprintf(p, s, "from=%s recipients=", acc->from);
    s -= n;
    p += n;
    l = recipients;
    while (!list_is_empty(l))
    {
        l = l->next;
        n = snprintf(p, s, "%s,", (char *)(l->data));
        s -= n;
        p += n;
    }
    /* delete the last ',' */
    *(p - 1) = ' ';
    if (exitcode == EX_OK)
    {
        n = snprintf(p, s, "mailsize=%s ", mailsize_str);
        s -= n;
        p += n;
    }
    if (errmsg)
    {
        n = snprintf(p, s, "smtpstatus=%s smtpmsg=%s ",
                smtpstatus_str, smtperrmsg_str);
        s -= n;
        p += n;
    }
    if (exitcode != EX_OK && errstr[0] != '\0')
    {
        /* hide single quotes to make the info easy to parse */
        tmp = errstr;
        while (*tmp)
        {
            if (*tmp == '\'')
            {
                *tmp = '?';
            }
            tmp++;
        }
        n = snprintf(p, s, "errormsg='%s' ", sanitize_string(errstr));
        s -= n;
        p += n;
    }
    (void)snprintf(p, s, "exitcode=%s", exitcode_str);

    free(mailsize_str);
    free(smtpstatus_str);
    free(smtperrmsg_str);
    return line;
}


/*
 * msmtp_log_to_file()
 *
 * Append a log entry to 'logfile' with the following information:
 * - date/time in the format given by 'logfile_time_format' (may be NULL)
 * - the log line as delivered by msmtp_get_log_info
 */

void msmtp_log_to_file(const char *logfile, const char *logfile_time_format,
        const char *loginfo)
{
    FILE *f = NULL;
    time_t t;
    struct tm *tm;
    char *failure_reason;
    const char *time_fmt;
    char time_str[128];
    int e;

    /* get time */
    t = time(NULL); /* cannot fail */
    tm = localtime(&t); /* cannot fail */
    time_fmt = logfile_time_format ? logfile_time_format : "%b %d %H:%M:%S";
    if (strftime(time_str, sizeof(time_str), time_fmt, tm) == 0)
    {
        /* a return value of 0 is only an error with a non-empty time_fmt,
         * but we know it is non-empty since we cannot configure an empty
         * logfile_time_format in msmtp (it would be set to NULL). */
        failure_reason = xasprintf(_("invalid logfile_time_format"));
        goto log_failure;
    }

    /* write log to file */
    if (strcmp(logfile, "-") == 0)
    {
        f = stdout;
    }
    else
    {
        if (!(f = fopen(logfile, "a")))
        {
            failure_reason = xasprintf(_("cannot open: %s"), strerror(errno));
            goto log_failure;
        }
        if ((e = lock_file(f, TOOLS_LOCK_WRITE, 10)) != 0)
        {
            if (e == 1)
            {
                failure_reason = xasprintf(
                        _("cannot lock (tried for %d seconds): %s"),
                        10, strerror(errno));
            }
            else
            {
                failure_reason = xasprintf(_("cannot lock: %s"),
                        strerror(errno));
            }
            goto log_failure;
        }
    }
    if ((fputs(time_str, f) == EOF) || (fputc(' ', f) == EOF)
        || (fputs(loginfo, f) == EOF) || (fputc('\n', f) == EOF))
    {
        failure_reason = xstrdup(_("output error"));
        goto log_failure;
    }
    if (f != stdout && fclose(f) != 0)
    {
        failure_reason = xstrdup(strerror(errno));
        goto log_failure;
    }

    return;

    /* error exit target */
log_failure:
    if (f && f != stdout)
    {
        fclose(f);
    }
    print_error(_("cannot log to %s: %s"), logfile, failure_reason);
    free(failure_reason);
    if (loginfo)
    {
        print_error(_("log info was: %s"), loginfo);
    }
}


/*
 * msmtp_log_to_syslog()
 *
 * Log the information delivered by msmtp_get_log_info() to syslog
 * the facility_str must be one of "LOG_MAIL", "LOG_USER", "LOG_LOCAL0", ...
 * "LOG_LOCAL7"
 * If 'error' is set, LOG_ERR is used, else LOG_INFO is used.
 */

#ifdef HAVE_SYSLOG
void msmtp_log_to_syslog(const char *facility_str,
        const char *loginfo, int error)
{
    int facility;

    if (facility_str[4] == 'M')
    {
        facility = LOG_MAIL;
    }
    else if (facility_str[4] == 'U')
    {
        facility = LOG_USER;
    }
    else if (facility_str[9] == '0')
    {
        facility = LOG_LOCAL0;
    }
    else if (facility_str[9] == '1')
    {
        facility = LOG_LOCAL1;
    }
    else if (facility_str[9] == '2')
    {
        facility = LOG_LOCAL2;
    }
    else if (facility_str[9] == '3')
    {
        facility = LOG_LOCAL3;
    }
    else if (facility_str[9] == '4')
    {
        facility = LOG_LOCAL4;
    }
    else if (facility_str[9] == '5')
    {
        facility = LOG_LOCAL5;
    }
    else if (facility_str[9] == '6')
    {
        facility = LOG_LOCAL6;
    }
    else
    {
        facility = LOG_LOCAL7;
    }

    openlog(PACKAGE_NAME, 0, facility);
    syslog(error ? LOG_ERR : LOG_INFO, "%s", loginfo);
    closelog();
}
#endif /* HAVE_SYSLOG */


/*
 * msmtp_construct_env_from()
 *
 * OBSOLETE: triggered by auto_from, uses maildomain. both are replaced
 * with substitution patterns supported in from.
 *
 * Build an envelope from address for the current user.
 * If maildomain is not NULL and not the empty string, it will be the domain
 * part of the address. Otherwise, the address won't have a domain part.
 */

char *msmtp_construct_env_from(const char *maildomain)
{
    char *envelope_from;
    size_t len;

    envelope_from = get_username();
    if (maildomain && *maildomain != '\0')
    {
        len = strlen(envelope_from);
        envelope_from = xrealloc(envelope_from,
                ((len + 1 + strlen(maildomain) + 1) * sizeof(char)));
        envelope_from[len] = '@';
        strcpy(envelope_from + len + 1, maildomain);
    }
    return envelope_from;
}


/*
 * msmtp_print_version()
 *
 * Print --version information
 */

void msmtp_print_version(void)
{
    char *sysconfdir;
    char *sysconffile;
    char *userconffile;

    printf(_("%s version %s\n"), PACKAGE_NAME, VERSION);
    printf(_("Platform: %s\n"), PLATFORM);
    /* TLS/SSL support */
    printf(_("TLS/SSL library: %s\n"),
#ifdef HAVE_LIBGNUTLS
            "GnuTLS"
#elif defined (HAVE_LIBSSL)
            TLS_LIB
#elif defined (HAVE_LIBTLS)
            "libtls"
#else
            _("none")
#endif
          );
    /* Authentication support */
    printf(_("Authentication library: %s\n"
                "Supported authentication methods:\n"),
#ifdef HAVE_LIBGSASL
            _("GNU SASL; oauthbearer and xoauth2: built-in")
#else
            _("built-in")
#endif /* HAVE_LIBGSASL */
          );
    if (smtp_client_supports_authmech("SCRAM-SHA-256-PLUS"))
        printf("scram-sha-256-plus ");
    if (smtp_client_supports_authmech("SCRAM-SHA-1-PLUS"))
        printf("scram-sha-1-plus ");
    if (smtp_client_supports_authmech("SCRAM-SHA-256"))
        printf("scram-sha-256 ");
    if (smtp_client_supports_authmech("SCRAM-SHA-1"))
        printf("scram-sha-1 ");
    if (smtp_client_supports_authmech("PLAIN"))
        printf("plain ");
    if (smtp_client_supports_authmech("GSSAPI"))
        printf("gssapi ");
    if (smtp_client_supports_authmech("EXTERNAL"))
        printf("external ");
    if (smtp_client_supports_authmech("OAUTHBEARER"))
        printf("oauthbearer ");
    if (smtp_client_supports_authmech("CRAM-MD5"))
        printf("cram-md5 ");
    if (smtp_client_supports_authmech("DIGEST-MD5"))
        printf("digest-md5 ");
    if (smtp_client_supports_authmech("LOGIN"))
        printf("login ");
    if (smtp_client_supports_authmech("NTLM"))
        printf("ntlm ");
    if (smtp_client_supports_authmech("XOAUTH2"))
        printf("xoauth2 ");
    printf("\n");
    /* Internationalized Domain Names support */
    printf(_("IDN support: "));
#if defined(HAVE_LIBIDN) \
        || (defined(HAVE_GAI_IDN) && (!defined(HAVE_TLS) \
            || (defined(HAVE_LIBGNUTLS) && GNUTLS_VERSION_NUMBER >= 0x030400)))
    printf(_("enabled"));
#else
    printf(_("disabled"));
#endif
    printf("\n");
    /* Native language support */
    printf(_("NLS: "));
#ifdef ENABLE_NLS
    printf(_("enabled"));
    printf(_(", LOCALEDIR is %s"), LOCALEDIR);
#else
    printf(_("disabled"));
#endif
    printf("\n");
    printf(_("Keyring support: "));
#if !defined HAVE_LIBSECRET && !defined HAVE_MACOSXKEYRING
    printf(_("none"));
#else
# ifdef HAVE_LIBSECRET
    printf(_("Gnome "));
# endif
# ifdef HAVE_MACOSXKEYRING
    printf(_("MacOS "));
# endif
#endif
    printf("\n");
    sysconfdir = get_sysconfdir();
    sysconffile = get_filename(sysconfdir, SYSCONFFILE);
    printf(_("System configuration file name: %s\n"), sysconffile);
    free(sysconffile);
    free(sysconfdir);
    userconffile = get_userconfig(USERCONFFILE);
    printf(_("User configuration file name: %s\n"), userconffile);
    free(userconffile);
    printf("\n");
    printf(_("Copyright (C) %d Martin Lambers and others.\n"
                "This is free software.  You may redistribute copies of "
                    "it under the terms of\n"
                "the GNU General Public License "
                    "<http://www.gnu.org/licenses/gpl.html>.\n"
                "There is NO WARRANTY, to the extent permitted by law.\n"), 2024);
}


/*
 * msmtp_print_help()
 *
 * Print --help information
 */

void msmtp_print_help(void)
{
    printf(_("Usage:\n\n"));
    printf(_("Sendmail mode (default):\n"
             "  %s [option...] [--] recipient...\n"
             "  %s [option...] -t [--] [recipient...]\n"
             "  Read a mail from standard input and transmit it to an SMTP "
                "or LMTP server.\n"), prgname, prgname);
    printf(_("Configuration mode:\n"
             "  %s --configure=mailadress\n"
             "  Generate and print configuration for address.\n"), prgname);
    printf(_("Server information mode:\n"
             "  %s [option...] --serverinfo\n"
             "  Print information about a server.\n"), prgname);
    printf(_("Remote Message Queue Starting mode:\n"
             "  %s [option...] --rmqs=host|@domain|#queue\n"
             "  Send a Remote Message Queue Starting request to a server.\n\n"),
             prgname);
    printf(_("General options:\n"));
    printf(_("  --version                    print version\n"));
    printf(_("  --help                       print help\n"));
    printf(_("  -P, --pretend                print configuration info and exit\n"));
    printf(_("  -d, --debug                  print debugging information\n"));
    printf(_("Changing the mode of operation:\n"));
    printf(_("  --configure=mailaddress      generate and print configuration for address\n"));
    printf(_("  -S, --serverinfo             print information about the server\n"));
    printf(_("  --rmqs=host|@domain|#queue   send a Remote Message Queue Starting request\n"));
    printf(_("Configuration options:\n"));
    printf(_("  -C, --file=filename          set configuration file\n"));
    printf(_("  -a, --account=id             use the given account instead of the account\n"
             "                               named \"default\"; its settings may be changed\n"
             "                               with command-line options\n"));
    printf(_("  --host=hostname              set the server, use only command-line settings;\n"
             "                               do not use any configuration file data\n"));
    printf(_("  --port=number                set port number\n"));
    printf(_("  --source-ip=[IP]             set/unset source ip address to bind the socket to\n"));
    printf(_("  --proxy-host=[IP|hostname]   set/unset proxy\n"));
    printf(_("  --proxy-port=[number]        set/unset proxy port\n"));
    printf(_("  --socket=[socketname]        set/unset local socket to connect to\n"));
    printf(_("  --timeout=(off|seconds)      set/unset network timeout in seconds\n"));
    printf(_("  --protocol=(smtp|lmtp)       use the given sub protocol\n"));
    printf(_("  --domain=string              set the argument of EHLO or LHLO command\n"));
    printf(_("  --auth[=(on|off|method)]     enable/disable authentication and optionally\n"
             "                               choose the method\n"));
    printf(_("  --user=[username]            set/unset user name for authentication\n"));
    printf(_("  --passwordeval=[eval]        evaluate password for authentication\n"));
    printf(_("  --tls[=(on|off)]             enable/disable TLS encryption\n"));
    printf(_("  --tls-starttls[=(on|off)]    enable/disable STARTTLS for TLS\n"));
    printf(_("  --tls-trust-file=[file]      set/unset trust file for TLS\n"));
    printf(_("  --tls-crl-file=[file]        set/unset revocation file for TLS\n"));
    printf(_("  --tls-fingerprint=[f]        set/unset trusted certificate fingerprint for TLS\n"));
    printf(_("  --tls-certcheck[=(on|off)]   enable/disable server certificate checks for TLS\n"));
    printf(_("  --tls-key-file=[file]        set/unset private key file for TLS\n"));
    printf(_("  --tls-cert-file=[file]       set/unset private cert file for TLS\n"));
    printf(_("  --tls-priorities=[prios]     set/unset TLS priorities.\n"));
    printf(_("  --tls-host-override=[host]   set/unset override for TLS host verification.\n"));
    printf(_("  --tls-min-dh-prime-bits=[b]  set/unset minimum bit size of DH prime\n"));
    printf(_("Options specific to sendmail mode:\n"));
    printf(_("  --auto-from[=(on|off)]       enable/disable automatic envelope-from addresses\n"));
    printf(_("  -f, --from=address           set envelope from address\n"));
    printf(_("  --maildomain=[domain]        set the domain for automatic envelope from\n"
             "                               addresses\n"));
    printf(_("  -N, --dsn-notify=(off|cond)  set/unset DSN conditions\n"));
    printf(_("  -R, --dsn-return=(off|ret)   set/unset DSN amount\n"));
    printf(_("  -X, --logfile=[file]         set/unset log file\n"));
    printf(_("  --logfile-time-format=[fmt]  set/unset log file time format for strftime()\n"));
    printf(_("  --syslog[=(on|off|facility)] enable/disable/configure syslog logging\n"));
    printf(_("  -t, --read-recipients        read additional recipients from the mail\n"));
    printf(_("  --read-envelope-from         read envelope from address from the mail\n"));
    printf(_("  --aliases=[file]             set/unset aliases file\n"));
    printf(_("  --set-from-header[=(auto|on|off)] set From header handling\n"));
    printf(_("  --set-date-header[=(auto|off)] set Date header handling\n"));
    printf(_("  --set-msgid-header[=(auto|off)] set Message-ID header handling\n"));
    printf(_("  --remove-bcc-headers[=(on|off)] enable/disable removal of Bcc headers\n"));
    printf(_("  --undisclosed-recipients[=(on|off)] enable/disable replacement of To/Cc/Bcc\n"
             "                               with To: undisclosed-recipients:;\n"));
    printf(_("  --                           end of options\n"));
    printf(_("Accepted but ignored: -A, -B, -bm, -G, -h, -i, -L, -m, -n, -O, -o\n"));
    printf(_("\nReport bugs to <%s>.\n"), PACKAGE_BUGREPORT);
}


/*
 * msmtp_cmdline()
 *
 * Process the command line
 */

typedef struct
{
    /* the configuration */
    int print_version;
    int print_help;
    int print_conf;
    int debug;
    int pretend;
    int read_recipients;
    int read_envelope_from;
    /* mode of operation */
    int sendmail;
    int configure;
    char *configure_address;
    int serverinfo;
    int rmqs;
    char *rmqs_argument;
    /* account information from the command line */
    account_t *cmdline_account;
    const char *account_id;
    char *user_conffile;
    /* the list of recipients */
    list_t *recipients;
} msmtp_cmdline_conf_t;

/* long options without a corresponding short option */
#define LONGONLYOPT_VERSION                     (256 + 0)
#define LONGONLYOPT_HELP                        (256 + 1)
#define LONGONLYOPT_HOST                        (256 + 2)
#define LONGONLYOPT_PORT                        (256 + 3)
#define LONGONLYOPT_TIMEOUT                     (256 + 4)
#define LONGONLYOPT_AUTH                        (256 + 5)
#define LONGONLYOPT_USER                        (256 + 6)
#define LONGONLYOPT_PASSWORDEVAL                (256 + 7)
#define LONGONLYOPT_TLS                         (256 + 8)
#define LONGONLYOPT_TLS_STARTTLS                (256 + 9)
#define LONGONLYOPT_TLS_TRUST_FILE              (256 + 10)
#define LONGONLYOPT_TLS_CRL_FILE                (256 + 11)
#define LONGONLYOPT_TLS_FINGERPRINT             (256 + 12)
#define LONGONLYOPT_TLS_KEY_FILE                (256 + 13)
#define LONGONLYOPT_TLS_CERT_FILE               (256 + 14)
#define LONGONLYOPT_TLS_CERTCHECK               (256 + 15)
#define LONGONLYOPT_TLS_FORCE_SSLV3             (256 + 16)
#define LONGONLYOPT_TLS_MIN_DH_PRIME_BITS       (256 + 17)
#define LONGONLYOPT_TLS_PRIORITIES              (256 + 18)
#define LONGONLYOPT_TLS_HOST_OVERRIDE           (256 + 19)
#define LONGONLYOPT_PROTOCOL                    (256 + 20)
#define LONGONLYOPT_DOMAIN                      (256 + 21)
#define LONGONLYOPT_KEEPBCC                     (256 + 22)
#define LONGONLYOPT_RMQS                        (256 + 23)
#define LONGONLYOPT_SYSLOG                      (256 + 24)
#define LONGONLYOPT_MAILDOMAIN                  (256 + 25)
#define LONGONLYOPT_AUTO_FROM                   (256 + 26)
#define LONGONLYOPT_READ_ENVELOPE_FROM          (256 + 27)
#define LONGONLYOPT_ALIASES                     (256 + 28)
#define LONGONLYOPT_PROXY_HOST                  (256 + 29)
#define LONGONLYOPT_PROXY_PORT                  (256 + 30)
#define LONGONLYOPT_ADD_MISSING_FROM_HEADER     (256 + 31)
#define LONGONLYOPT_ADD_MISSING_DATE_HEADER     (256 + 32)
#define LONGONLYOPT_REMOVE_BCC_HEADERS          (256 + 33)
#define LONGONLYOPT_UNDISCLOSED_RECIPIENTS      (256 + 34)
#define LONGONLYOPT_SOURCE_IP                   (256 + 35)
#define LONGONLYOPT_LOGFILE_TIME_FORMAT         (256 + 36)
#define LONGONLYOPT_CONFIGURE                   (256 + 37)
#define LONGONLYOPT_SOCKET                      (256 + 38)
#define LONGONLYOPT_SET_FROM_HEADER             (256 + 39)
#define LONGONLYOPT_SET_DATE_HEADER             (256 + 40)
#define LONGONLYOPT_SET_MSGID_HEADER            (256 + 41)

int msmtp_cmdline(msmtp_cmdline_conf_t *conf, int argc, char *argv[])
{
    struct option options[] =
    {
        { "version", no_argument, 0, LONGONLYOPT_VERSION },
        { "help", no_argument, 0, LONGONLYOPT_HELP },
        { "configure", required_argument, 0, LONGONLYOPT_CONFIGURE },
        { "pretend", no_argument, 0, 'P' },
        /* accept an optional argument for sendmail compatibility: */
        { "debug", optional_argument, 0, 'd' },
        { "serverinfo", no_argument, 0, 'S' },
        { "rmqs", required_argument, 0, LONGONLYOPT_RMQS },
        { "file", required_argument, 0, 'C' },
        { "account", required_argument, 0, 'a' },
        { "host", required_argument, 0, LONGONLYOPT_HOST },
        { "port", required_argument, 0, LONGONLYOPT_PORT },
        { "timeout", required_argument, 0, LONGONLYOPT_TIMEOUT},
        /* for compatibility with versions <= 1.4.1: */
        { "connect-timeout", required_argument, 0, LONGONLYOPT_TIMEOUT},
        { "auto-from", optional_argument, 0, LONGONLYOPT_AUTO_FROM },
        { "from", required_argument, 0, 'f' },
        { "maildomain", required_argument, 0, LONGONLYOPT_MAILDOMAIN },
        { "auth", optional_argument, 0, LONGONLYOPT_AUTH },
        { "user", required_argument, 0, LONGONLYOPT_USER },
        { "passwordeval", required_argument, 0, LONGONLYOPT_PASSWORDEVAL },
        { "tls", optional_argument, 0, LONGONLYOPT_TLS },
        { "tls-starttls", optional_argument, 0, LONGONLYOPT_TLS_STARTTLS },
        { "tls-trust-file", required_argument, 0, LONGONLYOPT_TLS_TRUST_FILE },
        { "tls-crl-file", required_argument, 0, LONGONLYOPT_TLS_CRL_FILE },
        { "tls-fingerprint", required_argument, 0,
            LONGONLYOPT_TLS_FINGERPRINT },
        { "tls-key-file", required_argument, 0, LONGONLYOPT_TLS_KEY_FILE },
        { "tls-cert-file", required_argument, 0, LONGONLYOPT_TLS_CERT_FILE },
        { "tls-certcheck", optional_argument, 0, LONGONLYOPT_TLS_CERTCHECK },
        { "tls-force-sslv3", optional_argument, 0,
            LONGONLYOPT_TLS_FORCE_SSLV3 },
        { "tls-min-dh-prime-bits", required_argument, 0,
            LONGONLYOPT_TLS_MIN_DH_PRIME_BITS },
        { "tls-priorities", required_argument, 0, LONGONLYOPT_TLS_PRIORITIES },
        { "tls-host-override", required_argument, 0, LONGONLYOPT_TLS_HOST_OVERRIDE },
        { "dsn-notify", required_argument, 0, 'N' },
        { "dsn-return", required_argument, 0, 'R' },
        { "protocol", required_argument, 0, LONGONLYOPT_PROTOCOL },
        { "domain", required_argument, 0, LONGONLYOPT_DOMAIN },
        { "logfile", required_argument, 0, 'X' },
        { "logfile-time-format", required_argument, 0,
            LONGONLYOPT_LOGFILE_TIME_FORMAT },
        { "syslog", optional_argument, 0, LONGONLYOPT_SYSLOG },
        { "aliases", required_argument, 0, LONGONLYOPT_ALIASES },
        { "proxy-host", required_argument, 0, LONGONLYOPT_PROXY_HOST },
        { "proxy-port", required_argument, 0, LONGONLYOPT_PROXY_PORT },
        { "add-missing-from-header", optional_argument, 0,
            LONGONLYOPT_ADD_MISSING_FROM_HEADER },
        { "add-missing-date-header", optional_argument, 0,
            LONGONLYOPT_ADD_MISSING_DATE_HEADER },
        { "set-from-header", optional_argument, 0,
            LONGONLYOPT_SET_FROM_HEADER },
        { "set-date-header", optional_argument, 0,
            LONGONLYOPT_SET_DATE_HEADER },
        { "set-msgid-header", optional_argument, 0,
            LONGONLYOPT_SET_MSGID_HEADER },
        { "remove-bcc-headers", optional_argument, 0,
            LONGONLYOPT_REMOVE_BCC_HEADERS },
        { "undisclosed-recipients", optional_argument, 0,
            LONGONLYOPT_UNDISCLOSED_RECIPIENTS },
        { "source-ip", required_argument, 0, LONGONLYOPT_SOURCE_IP },
        { "socket", required_argument, 0, LONGONLYOPT_SOCKET },
        { "keepbcc", optional_argument, 0, LONGONLYOPT_KEEPBCC },
        { "read-recipients", no_argument, 0, 't' },
        { "read-envelope-from", no_argument, 0,
            LONGONLYOPT_READ_ENVELOPE_FROM },
        { 0, 0, 0, 0 }
    };
    int error_code;
    int c;
    int i;
    int rcptc;
    char **rcptv;
    FILE *tmpf = NULL;
    char *errstr;
#ifdef HAVE_FMEMOPEN
    size_t rcptf_size;
    void *rcptf_buf = NULL;
#endif

    /* the program name */
    prgname = get_prgname(argv[0]);
    /* the configuration */
    conf->print_version = 0;
    conf->print_help = 0;
    conf->print_conf = 0;
    conf->debug = 0;
    conf->pretend = 0;
    conf->read_recipients = 0;
    conf->read_envelope_from = 0;
    /* mode of operation */
    conf->sendmail = 1;
    conf->configure = 0;
    conf->configure_address = NULL;
    conf->serverinfo = 0;
    conf->rmqs = 0;
    conf->rmqs_argument = NULL;
    /* account information from the command line */
    conf->cmdline_account = account_new(NULL, NULL);
    conf->account_id = NULL;
    conf->user_conffile = NULL;
    /* the recipients */
    conf->recipients = NULL;

    /* process the command line */
    error_code = 0;
    for (;;)
    {
        c = getopt_long(argc, argv, "Pd::SC:a:f:N:R:X:tA:B:b:F:Gh:iL:mnO:o:v",
                options, NULL);
        if (c == -1)
        {
            break;
        }
        switch(c)
        {
            case LONGONLYOPT_VERSION:
                conf->print_version = 1;
                conf->sendmail = 0;
                conf->serverinfo = 0;
                break;

            case LONGONLYOPT_HELP:
                conf->print_help = 1;
                conf->sendmail = 0;
                conf->serverinfo = 0;
                break;

            case LONGONLYOPT_CONFIGURE:
                conf->configure = 1;
                free(conf->configure_address);
                conf->configure_address = xstrdup(optarg);
                conf->sendmail = 0;
                conf->serverinfo = 0;
                break;

            case 'P':
                conf->print_conf = 1;
                conf->pretend = 1;
                break;

            case 'v':
            case 'd':
                conf->print_conf = 1;
                conf->debug = 1;
                /* only care about the optional argument if it's "0.1", which is
                 * the only argument that's documented for sendmail: it prints
                 * version information */
                if (optarg && strcmp(optarg, "0.1") == 0)
                {
                    conf->print_version = 1;
                }
                break;

            case 'S':
                if (conf->rmqs)
                {
                    print_error(_("cannot use both --serverinfo and --rmqs"));
                    error_code = 1;
                }
                else
                {
                    conf->serverinfo = 1;
                    conf->sendmail = 0;
                    conf->rmqs = 0;
                }
                break;

            case LONGONLYOPT_RMQS:
                if (conf->serverinfo)
                {
                    print_error(_("cannot use both --serverinfo and --rmqs"));
                    error_code = 1;
                }
                else
                {
                    conf->rmqs = 1;
                    conf->rmqs_argument = optarg;
                    conf->sendmail = 0;
                    conf->serverinfo = 0;
                }
                break;

            case 'C':
                free(conf->user_conffile);
                conf->user_conffile = xstrdup(optarg);
                break;

            case 'a':
                if (conf->cmdline_account->host)
                {
                    print_error(_("cannot use both --host and --account"));
                    error_code = 1;
                }
                else
                {
                    conf->account_id = optarg;
                }
                break;

            case LONGONLYOPT_HOST:
                if (conf->account_id)
                {
                    print_error(_("cannot use both --host and --account"));
                    error_code = 1;
                }
                else
                {
                    free(conf->cmdline_account->host);
                    conf->cmdline_account->host = xstrdup(optarg);
                    conf->cmdline_account->mask |= ACC_HOST;
                }
                break;

            case LONGONLYOPT_PORT:
                conf->cmdline_account->port = get_pos_int(optarg);
                if (conf->cmdline_account->port < 1
                        || conf->cmdline_account->port > 65535)
                {
                    print_error(_("invalid argument %s for %s"),
                            optarg, "--port");
                    error_code = 1;
                }
                conf->cmdline_account->mask |= ACC_PORT;
                break;

            case LONGONLYOPT_TIMEOUT:
                if (is_off(optarg))
                {
                    conf->cmdline_account->timeout = 0;
                }
                else
                {
                    conf->cmdline_account->timeout =
                        get_pos_int(optarg);
                    if (conf->cmdline_account->timeout < 1)
                    {
                        print_error(_("invalid argument %s for %s"),
                                optarg, "--timeout");
                        error_code = 1;
                    }
                }
                conf->cmdline_account->mask |= ACC_TIMEOUT;
                break;

            case LONGONLYOPT_AUTO_FROM:
                if (!optarg || is_on(optarg))
                {
                    conf->cmdline_account->auto_from = 1;
                }
                else if (is_off(optarg))
                {
                    conf->cmdline_account->auto_from = 0;
                }
                else
                {
                    print_error(_("invalid argument %s for %s"),
                            optarg, "--auto-from");
                    error_code = 1;
                }
                conf->cmdline_account->mask |= ACC_AUTO_FROM;
                break;

            case 'f':
                if (conf->read_envelope_from)
                {
                    print_error(_("cannot use both --from and "
                                "--read-envelope-from"));
                    error_code = 1;
                }
                else
                {
                    free(conf->cmdline_account->from);
                    /* Accept '<>' to mean an empty from address, to fix Debian
                     * bug 612679. */
                    if (strcmp(optarg, "<>") == 0)
                    {
                        conf->cmdline_account->from = xstrdup("");
                    }
                    else
                    {
                        conf->cmdline_account->from = xstrdup(optarg);
                    }
                    conf->cmdline_account->mask |= ACC_FROM;
                }
                break;

            case LONGONLYOPT_MAILDOMAIN:
                free(conf->cmdline_account->maildomain);
                conf->cmdline_account->maildomain =
                    (*optarg == '\0') ? NULL : xstrdup(optarg);
                conf->cmdline_account->mask |= ACC_MAILDOMAIN;
                break;

            case LONGONLYOPT_AUTH:
                free(conf->cmdline_account->auth_mech);
                if (!optarg || is_on(optarg))
                {
                    conf->cmdline_account->auth_mech = xstrdup("");
                }
                else if (is_off(optarg))
                {
                    conf->cmdline_account->auth_mech = NULL;
                }
                else if (check_auth_arg(optarg) == 0)
                {
                    conf->cmdline_account->auth_mech = xstrdup(optarg);
                }
                else
                {
                    conf->cmdline_account->auth_mech = NULL;
                    print_error(_("invalid argument %s for %s"),
                            optarg, "--auth");
                    error_code = 1;
                }
                conf->cmdline_account->mask |= ACC_AUTH_MECH;
                break;

            case LONGONLYOPT_USER:
                free(conf->cmdline_account->username);
                conf->cmdline_account->username =
                    (*optarg == '\0') ? NULL : xstrdup(optarg);
                conf->cmdline_account->mask |= ACC_USERNAME;
                break;

            case LONGONLYOPT_PASSWORDEVAL:
                free(conf->cmdline_account->passwordeval);
                conf->cmdline_account->passwordeval =
                    (*optarg == '\0') ? NULL : xstrdup(optarg);
                conf->cmdline_account->mask |= ACC_PASSWORDEVAL;
                break;

            case LONGONLYOPT_TLS:
                if (!optarg || is_on(optarg))
                {
                    conf->cmdline_account->tls = 1;
                }
                else if (is_off(optarg))
                {
                    conf->cmdline_account->tls = 0;
                }
                else
                {
                    print_error(_("invalid argument %s for %s"),
                            optarg, "--tls");
                    error_code = 1;
                }
                conf->cmdline_account->mask |= ACC_TLS;
                break;

            case LONGONLYOPT_TLS_STARTTLS:
                if (!optarg || is_on(optarg))
                {
                    conf->cmdline_account->tls_nostarttls = 0;
                }
                else if (is_off(optarg))
                {
                    conf->cmdline_account->tls_nostarttls = 1;
                }
                else
                {
                    print_error(_("invalid argument %s for %s"),
                            optarg, "--tls-starttls");
                    error_code = 1;
                }
                conf->cmdline_account->mask |= ACC_TLS_NOSTARTTLS;
                break;

            case LONGONLYOPT_TLS_TRUST_FILE:
                free(conf->cmdline_account->tls_trust_file);
                if (*optarg)
                {
                    conf->cmdline_account->tls_trust_file =
                        expand_tilde(optarg);
                }
                else
                {
                    conf->cmdline_account->tls_trust_file = NULL;
                }
                conf->cmdline_account->mask |= ACC_TLS_TRUST_FILE;
                break;

            case LONGONLYOPT_TLS_CRL_FILE:
                free(conf->cmdline_account->tls_crl_file);
                if (*optarg)
                {
                    conf->cmdline_account->tls_crl_file =
                        expand_tilde(optarg);
                }
                else
                {
                    conf->cmdline_account->tls_crl_file = NULL;
                }
                conf->cmdline_account->mask |= ACC_TLS_CRL_FILE;
                break;

            case LONGONLYOPT_TLS_FINGERPRINT:
                free(conf->cmdline_account->tls_sha256_fingerprint);
                conf->cmdline_account->tls_sha256_fingerprint = NULL;
                free(conf->cmdline_account->tls_sha1_fingerprint);
                conf->cmdline_account->tls_sha1_fingerprint = NULL;
                free(conf->cmdline_account->tls_md5_fingerprint);
                conf->cmdline_account->tls_md5_fingerprint = NULL;
                if (*optarg)
                {
                    if (strlen(optarg) == 2 * 32 + 31)
                    {
                        conf->cmdline_account->tls_sha256_fingerprint =
                            get_fingerprint(optarg, 32);
                    }
                    else if (strlen(optarg) == 2 * 20 + 19)
                    {
                        conf->cmdline_account->tls_sha1_fingerprint =
                            get_fingerprint(optarg, 20);
                    }
                    else if (strlen(optarg) == 2 * 16 + 15)
                    {
                        conf->cmdline_account->tls_md5_fingerprint =
                            get_fingerprint(optarg, 16);
                    }
                    if (!conf->cmdline_account->tls_sha256_fingerprint
                            && !conf->cmdline_account->tls_sha1_fingerprint
                            && !conf->cmdline_account->tls_md5_fingerprint)
                    {
                        print_error(_("invalid argument %s for %s"),
                                optarg, "--tls-fingerprint");
                        error_code = 1;
                    }
                }
                conf->cmdline_account->mask |= ACC_TLS_FINGERPRINT;
                break;

            case LONGONLYOPT_TLS_KEY_FILE:
                free(conf->cmdline_account->tls_key_file);
                if (*optarg)
                {
                    conf->cmdline_account->tls_key_file = expand_tilde(optarg);
                }
                else
                {
                    conf->cmdline_account->tls_key_file = NULL;
                }
                conf->cmdline_account->mask |= ACC_TLS_KEY_FILE;
                break;

            case LONGONLYOPT_TLS_CERT_FILE:
                free(conf->cmdline_account->tls_cert_file);
                if (*optarg)
                {
                    conf->cmdline_account->tls_cert_file = expand_tilde(optarg);
                }
                else
                {
                    conf->cmdline_account->tls_cert_file = NULL;
                }
                conf->cmdline_account->mask |= ACC_TLS_CERT_FILE;
                break;

            case LONGONLYOPT_TLS_CERTCHECK:
                if (!optarg || is_on(optarg))
                {
                    conf->cmdline_account->tls_nocertcheck = 0;
                }
                else if (is_off(optarg))
                {
                    conf->cmdline_account->tls_nocertcheck = 1;
                }
                else
                {
                    print_error(_("invalid argument %s for %s"),
                            optarg, "--tls-certcheck");
                    error_code = 1;
                }
                conf->cmdline_account->mask |= ACC_TLS_NOCERTCHECK;
                break;

            case LONGONLYOPT_TLS_FORCE_SSLV3:
                /* silently ignored for compatibility with versions <= 1.4.32 */
                break;

            case LONGONLYOPT_TLS_MIN_DH_PRIME_BITS:
                if (*optarg == '\0')
                {
                    conf->cmdline_account->tls_min_dh_prime_bits = -1;
                }
                else
                {
                    conf->cmdline_account->tls_min_dh_prime_bits =
                        get_pos_int(optarg);
                    if (conf->cmdline_account->tls_min_dh_prime_bits < 1)
                    {
                        print_error(_("invalid argument %s for %s"),
                                optarg, "--tls-min-dh-prime-bits");
                        error_code = 1;
                    }
                }
                conf->cmdline_account->mask |= ACC_TLS_MIN_DH_PRIME_BITS;
                break;

            case LONGONLYOPT_TLS_PRIORITIES:
                free(conf->cmdline_account->tls_priorities);
                if (*optarg)
                {
                    conf->cmdline_account->tls_priorities = xstrdup(optarg);
                }
                else
                {
                    conf->cmdline_account->tls_priorities = NULL;
                }
                conf->cmdline_account->mask |= ACC_TLS_PRIORITIES;
                break;

            case LONGONLYOPT_TLS_HOST_OVERRIDE:
                free(conf->cmdline_account->tls_host_override);
                if (*optarg)
                {
                    conf->cmdline_account->tls_host_override = xstrdup(optarg);
                }
                else
                {
                    conf->cmdline_account->tls_host_override = NULL;
                }
                conf->cmdline_account->mask |= ACC_TLS_HOST_OVERRIDE;
                break;

            case 'N':
                free(conf->cmdline_account->dsn_notify);
                if (is_off(optarg))
                {
                    conf->cmdline_account->dsn_notify = NULL;
                }
                else if (check_dsn_notify_arg(optarg) == 0)
                {
                    conf->cmdline_account->dsn_notify = xstrdup(optarg);
                }
                else
                {
                    print_error(_("invalid argument %s for %s"),
                            optarg, "--dsn-notify");
                    error_code = 1;
                }
                conf->cmdline_account->mask |= ACC_DSN_NOTIFY;
                break;

            case 'R':
                /* be compatible to both sendmail and the dsn_notify command */
                free(conf->cmdline_account->dsn_return);
                if (is_off(optarg))
                {
                    conf->cmdline_account->dsn_return = NULL;
                }
                else if (strcmp(optarg, "hdrs") == 0
                        || strcmp(optarg, "headers") == 0)
                {
                    conf->cmdline_account->dsn_return = xstrdup("HDRS");
                }
                else if (strcmp(optarg, "full") == 0)
                {
                    conf->cmdline_account->dsn_return = xstrdup("FULL");
                }
                else
                {
                    print_error(_("invalid argument %s for %s"),
                            optarg, "--dsn-return");
                    error_code = 1;
                }
                conf->cmdline_account->mask |= ACC_DSN_RETURN;
                break;

            case LONGONLYOPT_PROTOCOL:
                conf->cmdline_account->mask |= ACC_PROTOCOL;
                if (strcmp(optarg, "smtp") == 0)
                {
                    conf->cmdline_account->protocol = SMTP_PROTO_SMTP;
                }
                else if (strcmp(optarg, "lmtp") == 0)
                {
                    conf->cmdline_account->protocol = SMTP_PROTO_LMTP;
                }
                else
                {
                    print_error(_("invalid argument %s for %s"),
                            optarg, "--protocol");
                    error_code = 1;
                }
                break;

            case LONGONLYOPT_DOMAIN:
                free(conf->cmdline_account->domain);
                conf->cmdline_account->domain = xstrdup(optarg);
                conf->cmdline_account->mask |= ACC_DOMAIN;
                break;

            case 'X':
                free(conf->cmdline_account->logfile);
                if (*optarg)
                {
                    conf->cmdline_account->logfile = expand_tilde(optarg);
                }
                else
                {
                    conf->cmdline_account->logfile = NULL;
                }
                conf->cmdline_account->mask |= ACC_LOGFILE;
                break;

            case LONGONLYOPT_LOGFILE_TIME_FORMAT:
                free(conf->cmdline_account->logfile_time_format);
                if (*optarg)
                {
                    conf->cmdline_account->logfile_time_format = xstrdup(optarg);
                }
                else
                {
                    conf->cmdline_account->logfile_time_format = NULL;
                }
                conf->cmdline_account->mask |= ACC_LOGFILE_TIME_FORMAT;
                break;

            case LONGONLYOPT_SYSLOG:
                free(conf->cmdline_account->syslog);
                if (!optarg || is_on(optarg))
                {
                    conf->cmdline_account->syslog =
                        get_default_syslog_facility();
                }
                else if (is_off(optarg))
                {
                    conf->cmdline_account->syslog = NULL;
                }
                else
                {
                    if (check_syslog_arg(optarg) != 0)
                    {
                        print_error(_("invalid argument %s for %s"),
                                optarg, "--syslog");
                        error_code = 1;
                    }
                    else
                    {
                        conf->cmdline_account->syslog = xstrdup(optarg);
                    }
                }
                conf->cmdline_account->mask |= ACC_SYSLOG;
                break;

            case LONGONLYOPT_ALIASES:
                free(conf->cmdline_account->aliases);
                if (*optarg)
                {
                    conf->cmdline_account->aliases = expand_tilde(optarg);
                }
                else
                {
                    conf->cmdline_account->aliases = NULL;
                }
                conf->cmdline_account->mask |= ACC_ALIASES;
                break;

            case LONGONLYOPT_PROXY_HOST:
                free(conf->cmdline_account->proxy_host);
                if (*optarg)
                {
                    conf->cmdline_account->proxy_host = xstrdup(optarg);
                }
                else
                {
                    conf->cmdline_account->proxy_host = NULL;
                }
                conf->cmdline_account->mask |= ACC_PROXY_HOST;
                break;

            case LONGONLYOPT_PROXY_PORT:
                if (*optarg)
                {
                    conf->cmdline_account->proxy_port = get_pos_int(optarg);
                    if (conf->cmdline_account->proxy_port < 1
                            || conf->cmdline_account->proxy_port > 65535)
                    {
                        print_error(_("invalid argument %s for %s"),
                                optarg, "--proxy-port");
                        error_code = 1;
                    }
                }
                else
                {
                    conf->cmdline_account->proxy_port = 0;
                }
                conf->cmdline_account->mask |= ACC_PROXY_PORT;
                break;

            case LONGONLYOPT_SET_FROM_HEADER:
                if (!optarg || is_auto(optarg))
                {
                    conf->cmdline_account->set_from_header = 2;
                }
                else if (is_on(optarg))
                {
                    conf->cmdline_account->set_from_header = 1;
                }
                else if (is_off(optarg))
                {
                    conf->cmdline_account->set_from_header = 0;
                }
                else
                {
                    print_error(_("invalid argument %s for %s"),
                            optarg, "--set-from-header");
                    error_code = 1;
                }
                conf->cmdline_account->mask |= ACC_SET_FROM_HEADER;
                break;

            case LONGONLYOPT_SET_DATE_HEADER:
                if (!optarg || is_auto(optarg))
                {
                    conf->cmdline_account->set_date_header = 2;
                }
                else if (is_off(optarg))
                {
                    conf->cmdline_account->set_date_header = 0;
                }
                else
                {
                    print_error(_("invalid argument %s for %s"),
                            optarg, "--set-date-header");
                    error_code = 1;
                }
                conf->cmdline_account->mask |= ACC_SET_DATE_HEADER;
                break;

            case LONGONLYOPT_SET_MSGID_HEADER:
                if (!optarg || is_auto(optarg))
                {
                    conf->cmdline_account->set_msgid_header = 2;
                }
                else if (is_off(optarg))
                {
                    conf->cmdline_account->set_msgid_header = 0;
                }
                else
                {
                    print_error(_("invalid argument %s for %s"),
                            optarg, "--set-msgid-header");
                    error_code = 1;
                }
                conf->cmdline_account->mask |= ACC_SET_MSGID_HEADER;
                break;

            case LONGONLYOPT_ADD_MISSING_FROM_HEADER:
                /* compatibility with < 1.8.8 */
                if (!optarg || is_on(optarg))
                {
                    conf->cmdline_account->set_from_header = 2;
                }
                else if (is_off(optarg))
                {
                    conf->cmdline_account->set_from_header = 0;
                }
                else
                {
                    print_error(_("invalid argument %s for %s"),
                            optarg, "--add-missing-from-header");
                    error_code = 1;
                }
                conf->cmdline_account->mask |= ACC_SET_FROM_HEADER;
                break;

            case LONGONLYOPT_ADD_MISSING_DATE_HEADER:
                /* compatibility with < 1.8.8 */
                if (!optarg || is_on(optarg))
                {
                    conf->cmdline_account->set_date_header = 2;
                }
                else if (is_off(optarg))
                {
                    conf->cmdline_account->set_date_header = 0;
                }
                else
                {
                    print_error(_("invalid argument %s for %s"),
                            optarg, "--add-missing-date-header");
                    error_code = 1;
                }
                conf->cmdline_account->mask |= ACC_SET_DATE_HEADER;
                break;

            case LONGONLYOPT_REMOVE_BCC_HEADERS:
                if (!optarg || is_on(optarg))
                {
                    conf->cmdline_account->remove_bcc_headers = 1;
                }
                else if (is_off(optarg))
                {
                    conf->cmdline_account->remove_bcc_headers = 0;
                }
                else
                {
                    print_error(_("invalid argument %s for %s"),
                            optarg, "--remove-bcc-headers");
                    error_code = 1;
                }
                conf->cmdline_account->mask |= ACC_REMOVE_BCC_HEADERS;
                break;

            case LONGONLYOPT_UNDISCLOSED_RECIPIENTS:
                if (!optarg || is_on(optarg))
                {
                    conf->cmdline_account->undisclosed_recipients = 1;
                }
                else if (is_off(optarg))
                {
                    conf->cmdline_account->undisclosed_recipients = 0;
                }
                else
                {
                    print_error(_("invalid argument %s for %s"),
                            optarg, "--undisclosed-recipients");
                    error_code = 1;
                }
                conf->cmdline_account->mask |= ACC_UNDISCLOSED_RECIPIENTS;
                break;

            case LONGONLYOPT_SOURCE_IP:
                free(conf->cmdline_account->source_ip);
                if (*optarg)
                {
                    conf->cmdline_account->source_ip = xstrdup(optarg);
                }
                else
                {
                    conf->cmdline_account->source_ip = NULL;
                }
                conf->cmdline_account->mask |= ACC_SOURCE_IP;
                break;

            case LONGONLYOPT_SOCKET:
                free(conf->cmdline_account->socketname);
                if (*optarg)
                {
                    conf->cmdline_account->socketname = xstrdup(optarg);
                }
                else
                {
                    conf->cmdline_account->socketname = NULL;
                }
                conf->cmdline_account->mask |= ACC_SOCKET;
                break;

            case 't':
                conf->read_recipients = 1;
                break;

            case LONGONLYOPT_READ_ENVELOPE_FROM:
                if (conf->cmdline_account->from)
                {
                    print_error(_("cannot use both --from and "
                                "--read-envelope-from"));
                    error_code = 1;
                }
                else
                {
                    conf->read_envelope_from = 1;
                    conf->cmdline_account->mask |= ACC_FROM;
                }
                break;

            case 'b':
                /* only m makes sense */
                if (strcmp(optarg, "m") != 0)
                {
                    print_error(_("unsupported operation mode b%s"), optarg);
                    error_code = 1;
                }
                break;

            case 'F':
                free(conf->cmdline_account->from_full_name);
                conf->cmdline_account->from_full_name = xstrdup(optarg);
                break;

            case LONGONLYOPT_KEEPBCC:
                /* compatibility with 1.4.x */
                if (!optarg || is_on(optarg))
                {
                    conf->cmdline_account->remove_bcc_headers = 0;
                }
                else if (is_off(optarg))
                {
                    conf->cmdline_account->remove_bcc_headers = 1;
                }
                else
                {
                    print_error(_("invalid argument %s for %s"),
                            optarg, "--keepbcc");
                    error_code = 1;
                }
                conf->cmdline_account->mask |= ACC_REMOVE_BCC_HEADERS;
                break;

            case 'A':
            case 'B':
            case 'G':
            case 'h':
            case 'i':
            case 'L':
            case 'm':
            case 'n':
            case 'O':
            case 'o':
                break;

            /* unknown option */
            default:
                error_code = 1;
                break;
        }
        if (error_code)
        {
            break;
        }
    }
    if (error_code)
    {
        return EX_USAGE;
    }

    /* The list of recipients.
     * Write these to a temporary mail header so that msmtp_read_headers() can
     * parse them. */
    conf->recipients = list_new();
    rcptc = argc - optind;
    rcptv = &(argv[optind]);
    if (rcptc > 0)
    {
#ifdef HAVE_FMEMOPEN
        rcptf_size = 2;     /* terminating "\n\0" */
        for (i = 0; i < rcptc; i++)
        {
            rcptf_size += 4 + strlen(rcptv[i]) + 1;
        }
        rcptf_buf = xmalloc(rcptf_size);
        tmpf = fmemopen(rcptf_buf, rcptf_size, "w+");
#else
        tmpf = tmpfile();
#endif
        if (!tmpf)
        {
            print_error(_("cannot create temporary file: %s"),
                    sanitize_string(strerror(errno)));
            error_code = EX_IOERR;
            goto error_exit;
        }
        for (i = 0; i < rcptc && error_code != EOF; i++)
        {
            error_code = fputs("To: ", tmpf);
            if (error_code != EOF)
            {
                error_code = fputs(rcptv[i], tmpf);
            }
            if (error_code != EOF)
            {
                error_code = fputc('\n', tmpf);
            }
        }
        if (error_code != EOF)
        {
            error_code = fputc('\n', tmpf);
        }
        if (error_code == EOF)
        {
            print_error(_("cannot write mail headers to temporary "
                        "file: output error"));
            error_code = EX_IOERR;
            goto error_exit;
        }
        if (fseeko(tmpf, 0, SEEK_SET) != 0)
        {
            print_error(_("cannot rewind temporary file: %s"),
                    sanitize_string(strerror(errno)));
            error_code = EX_IOERR;
            goto error_exit;
        }
        if ((error_code = msmtp_read_headers(tmpf, NULL,
                        list_last(conf->recipients), NULL, NULL, NULL,
                        &errstr))
                != EX_OK)
        {
            print_error("%s", sanitize_string(errstr));
            goto error_exit;
        }
    }
    error_code = EX_OK;

error_exit:
    if (tmpf)
    {
        fclose(tmpf);
    }
#ifdef HAVE_FMEMOPEN
    free(rcptf_buf);
#endif
    return error_code;
}


/*
 * msmtp_get_conffile_accounts()
 * Read the system and user configuration files and merge the data
 */

int msmtp_get_conffile_accounts(list_t **account_list,
        int print_info, const char *user_conffile,
        char **loaded_system_conffile, char **loaded_user_conffile)
{
    char *errstr;
    char *system_confdir;
    char *system_conffile;
    char *real_user_conffile;
    list_t *system_account_list;
    list_t *user_account_list;
    list_t *lps;
    list_t *lpu;
    int securitycheck;
    int e;


    *loaded_system_conffile = NULL;
    *loaded_user_conffile = NULL;

    /* Read the system configuration file.
     * It is not an error if system_conffile cannot be opened,
     * but it is an error is the file content is invalid */
    system_confdir = get_sysconfdir();
    system_conffile = get_filename(system_confdir, SYSCONFFILE);
    free(system_confdir);
    securitycheck = 0;
    if ((e = get_conf(system_conffile, securitycheck,
                    &system_account_list, &errstr)) != CONF_EOK)
    {
        if (e == CONF_ECANTOPEN)
        {
            if (print_info)
            {
                printf(_("ignoring system configuration file %s: %s\n"),
                        system_conffile, sanitize_string(errstr));
            }
        }
        else
        {
            print_error("%s: %s", system_conffile,
                    sanitize_string(errstr));
            return (e == CONF_EIO) ? EX_IOERR : EX_CONFIG;
        }
    }
    else
    {
        if (print_info)
        {
            printf(_("loaded system configuration file %s\n"), system_conffile);
        }
        *loaded_system_conffile = xstrdup(system_conffile);
    }
    free(system_conffile);

    /* Read the user configuration file.
     * It is not an error if user_conffile cannot be opened (unless it was
     * chosen with -C/--file), but it is an error is the file content is
     * invalid */
    if (user_conffile)
    {
        real_user_conffile = xstrdup(user_conffile);
    }
    else
    {
        real_user_conffile = get_userconfig(USERCONFFILE);
    }
#ifdef W32_NATIVE
    securitycheck = 1;
#else
    securitycheck = (geteuid() != 0);
#endif
    if ((e = get_conf(real_user_conffile, securitycheck,
                    &user_account_list, &errstr)) != CONF_EOK)
    {
        if (e == CONF_ECANTOPEN)
        {
            /* If the configuration file was set with -C/--file, it is an
             * error if we cannot open it */
            if (user_conffile)
            {
                print_error("%s: %s", real_user_conffile,
                        sanitize_string(errstr));
                return EX_IOERR;
            }
            /* otherwise, we can ignore it */
            if (print_info)
            {
                printf(_("ignoring user configuration file %s: %s\n"),
                        real_user_conffile, sanitize_string(errstr));
            }
        }
        else
        {
            print_error("%s: %s", real_user_conffile,
                    sanitize_string(errstr));
            return (e == CONF_EIO) ? EX_IOERR : EX_CONFIG;
        }
    }
    else
    {
        if (print_info)
        {
            printf(_("loaded user configuration file %s\n"),
                    real_user_conffile);
        }
        *loaded_user_conffile = xstrdup(real_user_conffile);
    }
    free(real_user_conffile);

    /* Merge system_account_list and user_account_list into account_list.
     * If an account exist in both files, only the one from the user conffile is
     * kept. It is important that the order of accounts is maintained, so that
     * --from can choose the *first* account with a matching envelope from
     * address. */
    if (*loaded_system_conffile && *loaded_user_conffile)
    {
        lpu = user_account_list;
        lps = system_account_list;
        while (!list_is_empty(lps))
        {
            lps = lps->next;
            if (!find_account(user_account_list, ((account_t *)lps->data)->id))
            {
                list_insert(lpu, account_copy(lps->data));
                lpu = lpu->next;
            }
        }
        *account_list = user_account_list;
        list_xfree(system_account_list, account_free);
    }
    else if (*loaded_system_conffile)
    {
        *account_list = system_account_list;
    }
    else if (*loaded_user_conffile)
    {
        *account_list = user_account_list;
    }
    else
    {
        *account_list = list_new();
    }

    return EX_OK;
}


/*
 * msmtp_print_conf
 *
 * Print configuration information, for example for --pretend
 */

void msmtp_print_conf(msmtp_cmdline_conf_t conf, account_t *account)
{
    char fingerprint_string[2 * 32 + 31 + 1];

    if (account->id && account->conffile)
    {
        printf(_("using account %s from %s\n"),
                account->id, account->conffile);
    }
    printf("host = %s\n",
            account->host ? account->host : _("(not set)"));
    printf("port = %d\n", account->port);
    printf("source ip = %s\n",
            account->source_ip ? account->source_ip : _("(not set)"));
    printf("proxy host = %s\n",
            account->proxy_host ? account->proxy_host : _("(not set)"));
    printf("proxy port = %d\n", account->proxy_port);
    printf("socket = %s\n",
            account->socketname ? account->socketname : _("(not set)"));
    printf("timeout = ");
    if (account->timeout <= 0)
    {
        printf(_("off\n"));
    }
    else
    {
        if (account->timeout > 1)
        {
            printf(_("%d seconds\n"), account->timeout);
        }
        else
        {
            printf(_("1 second\n"));
        }
    }
    printf("protocol = %s\n",
            account->protocol == SMTP_PROTO_SMTP ? "smtp" : "lmtp");
    printf("domain = %s\n", account->domain);
    printf("auth = ");
    if (!account->auth_mech)
    {
        printf(_("none\n"));
    }
    else if (account->auth_mech[0] == '\0')
    {
        printf(_("choose\n"));
    }
    else
    {
        printf("%s\n", account->auth_mech);
    }
    printf("user = %s\n",
            account->username ? account->username : _("(not set)"));
    printf("password = %s\n", account->password ? "*" : _("(not set)"));
    printf("passwordeval = %s\n",
            account->passwordeval ? account->passwordeval : _("(not set)"));
    printf("ntlmdomain = %s\n",
            account->ntlmdomain ? account->ntlmdomain : _("(not set)"));
    printf("tls = %s\n", account->tls ? _("on") : _("off"));
    printf("tls_starttls = %s\n", account->tls_nostarttls ? _("off") : _("on"));
    printf("tls_trust_file = %s\n",
            account->tls_trust_file ? account->tls_trust_file : _("(not set)"));
    printf("tls_crl_file = %s\n",
            account->tls_crl_file ? account->tls_crl_file : _("(not set)"));
    if (account->tls_sha256_fingerprint)
    {
        print_fingerprint(fingerprint_string,
                account->tls_sha256_fingerprint, 32);
    }
    else if (account->tls_sha1_fingerprint)
    {
        print_fingerprint(fingerprint_string,
                account->tls_sha1_fingerprint, 20);
    }
    else if (account->tls_md5_fingerprint)
    {
        print_fingerprint(fingerprint_string,
                account->tls_md5_fingerprint, 16);
    }
    printf("tls_fingerprint = %s\n",
            account->tls_sha256_fingerprint
            || account->tls_sha1_fingerprint || account->tls_md5_fingerprint
            ? fingerprint_string : _("(not set)"));
    printf("tls_key_file = %s\n",
            account->tls_key_file ? account->tls_key_file : _("(not set)"));
    printf("tls_cert_file = %s\n",
            account->tls_cert_file ? account->tls_cert_file : _("(not set)"));
    printf("tls_certcheck = %s\n",
            account->tls_nocertcheck ? _("off") : _("on"));
    printf("tls_min_dh_prime_bits = ");
    if (account->tls_min_dh_prime_bits >= 0)
    {
        printf("%d\n", account->tls_min_dh_prime_bits);
    }
    else
    {
        printf("%s\n", _("(not set)"));
    }
    printf("tls_priorities = %s\n",
            account->tls_priorities ? account->tls_priorities : _("(not set)"));
    printf("tls_host_override = %s\n",
            account->tls_host_override ? account->tls_host_override : _("(not set)"));
    if (conf.sendmail)
    {
        printf("auto_from = %s\n", account->auto_from ? _("on") : _("off"));
        printf("maildomain = %s\n",
                account->maildomain ? account->maildomain : _("(not set)"));
        printf("from = %s\n",
                account->from ? account->from : conf.read_envelope_from
                ? _("(read from mail)") : _("(not set)"));
        printf("from_full_name = %s\n",
                account->from_full_name ? account->from_full_name : _("(not set)"));
        printf("allow_from_override = %s\n",
                account->allow_from_override ? _("on") : _("off"));
        printf("set_from_header = %s\n",
                account->set_from_header == 2 ? _("auto")
                : account->set_from_header == 1 ? _("on") : _("off"));
        printf("set_date_header = %s\n",
                account->set_date_header == 2 ? _("auto")
                : _("off"));
        printf("remove_bcc_headers = %s\n",
                account->remove_bcc_headers ? _("on") : _("off"));
        printf("undisclosed_recipients = %s\n",
                account->undisclosed_recipients ? _("on") : _("off"));
        printf("dsn_notify = %s\n",
                account->dsn_notify ? account->dsn_notify : _("(not set)"));
        printf("dsn_return = %s\n",
                account->dsn_return ? account->dsn_return : _("(not set)"));
        printf("logfile = %s\n",
                account->logfile ? account->logfile : _("(not set)"));
        printf("logfile_time_format = %s\n",
                account->logfile_time_format ? account->logfile_time_format
                : _("(not set)"));
        printf("syslog = %s\n",
                account->syslog ? account->syslog : _("(not set)"));
        printf("aliases = %s\n",
                account->aliases ? account->aliases : _("(not set)"));
        if (conf.read_recipients)
        {
            printf(_("reading recipients from the command line "
                        "and the mail\n"));
        }
        else
        {
            printf(_("reading recipients from the command line\n"));
        }
    }
    if (conf.rmqs)
    {
        printf("RMQS argument = %s\n", conf.rmqs_argument);
    }
}


/*
 * The main function.
 * It returns values from sysexits.h (like sendmail does).
 */

int main(int argc, char *argv[])
{
    msmtp_cmdline_conf_t conf;
    /* account information from the configuration file(s) */
    list_t *account_list = NULL;
    char *loaded_system_conffile = NULL;
    char *loaded_user_conffile = NULL;
    /* environment variables */
    int allow_fallback_to_env;
    char *env_email;
    char *env_smtpserver;
    /* the account data that will be used */
    account_t *account = NULL;
    /* error handling */
    char *errstr;
    list_t *errmsg;
    int error_code;
    int e;
    list_t *lp;
    /* misc */
#ifdef HAVE_TLS
    int tls_lib_initialized = 0;
#endif
    int net_lib_initialized = 0;
    /* the size of a sent mail */
    long mailsize = 0;
    /* special LMTP error info */
    list_t *lmtp_errstrs;
    list_t *lmtp_error_msgs;
    list_t *lp_lmtp_errstrs;
    list_t *lp_lmtp_error_msgs;
    /* log information */
    char *log_info;
    /* needed to read the headers and extract addresses */
    FILE *header_tmpfile = NULL;
    FILE *prepend_header_tmpfile = NULL;
    int have_from_header = 0;
    int have_date_header = 0;
    int have_msgid_header = 0;


    /* Avoid the side effects of text mode interpretations on DOS systems. */
#if defined W32_NATIVE
    setmode(fileno(stdin), O_BINARY);
    _fmode = O_BINARY;
#endif

    errstr = NULL;
    errmsg = NULL;

    /* internationalization with gettext */
#ifdef ENABLE_NLS
    setlocale(LC_ALL, "");
    bindtextdomain(PACKAGE, LOCALEDIR);
    textdomain(PACKAGE);
#endif

    /* Avoid receiving SIGPIPE when writing to sockets that were closed by the
     * remote end; we handle write errors where they occur. */
#ifdef HAVE_SIGNAL
#ifdef SIGPIPE
    signal(SIGPIPE, SIG_IGN);
#endif
#endif

    /* the command line */
    if ((error_code = msmtp_cmdline(&conf, argc, argv)) != EX_OK)
    {
        goto exit;
    }

    if (conf.print_version)
    {
        msmtp_print_version();
    }
    if (conf.print_help)
    {
        msmtp_print_help();
    }

    if (conf.configure)
    {
        char *userconfigfile = conf.user_conffile ? xstrdup(conf.user_conffile) : get_userconfig(USERCONFFILE);
        error_code = msmtp_configure(conf.configure_address, userconfigfile);
        free(userconfigfile);
        free(conf.configure_address);
        goto exit;
    }

    if (conf.print_help || conf.print_version
            || (!conf.sendmail && !conf.serverinfo && !conf.rmqs
                && !conf.print_conf))
    {
        error_code = EX_OK;
        goto exit;
    }

    if ((conf.serverinfo || conf.rmqs) && !list_is_empty(conf.recipients))
    {
        print_error(_("too many arguments"));
        error_code = EX_USAGE;
        goto exit;
    }
    /* Read recipients and/or the envelope from address from the mail. */
    if (conf.sendmail)
    {
        char *envelope_from = NULL;
        if (!(header_tmpfile = tmpfile()))
        {
            print_error(_("cannot create temporary file: %s"),
                    sanitize_string(strerror(errno)));
            error_code = EX_IOERR;
            goto exit;
        }
        if ((error_code = msmtp_read_headers(stdin, header_tmpfile,
                        conf.read_recipients
                            ? list_last(conf.recipients) : NULL,
                        &envelope_from, &have_date_header, &have_msgid_header,
                        &errstr)) != EX_OK)
        {
            print_error("%s", sanitize_string(errstr));
            goto exit;
        }
        have_from_header = (envelope_from ? 1 : 0);
        if (conf.read_envelope_from)
        {
            conf.cmdline_account->from = envelope_from;
            if (conf.pretend || conf.debug)
            {
                printf(_("envelope from address extracted from mail: %s\n"),
                        conf.cmdline_account->from);
            }
        }
        if (fseeko(header_tmpfile, 0, SEEK_SET) != 0)
        {
            print_error(_("cannot rewind temporary file: %s"),
                    sanitize_string(strerror(errno)));
            error_code = EX_IOERR;
            goto exit;
        }
    }
    /* check the list of recipients */
    if (conf.sendmail && list_is_empty(conf.recipients) && !conf.pretend)
    {
        print_error(_("no recipients found"));
        error_code = EX_USAGE;
        goto exit;
    }

    /* get the account to be used, either from the conffile(s) or from the
     * command line */
    allow_fallback_to_env = 0;
    if (!conf.cmdline_account->host)
    {
        if ((error_code = msmtp_get_conffile_accounts(&account_list,
                        (conf.pretend || conf.debug), conf.user_conffile,
                        &loaded_system_conffile, &loaded_user_conffile))
                != EX_OK)
        {
            goto exit;
        }
        if (!conf.account_id)
        {
            if (conf.cmdline_account->from)
            {
                /* No account was chosen, but the envelope from address is
                 * given. Choose the right account with this address.
                 */
                account = account_copy(find_account_by_envelope_from(
                            account_list, conf.cmdline_account->from));
                if (account)
                {
                    if (conf.pretend || conf.debug)
                    {
                        printf(_("account chosen by "
                                    "envelope from address %s: %s\n"),
                                conf.cmdline_account->from, account->id);
                    }
                }
            }
            if (!account)
            {
                /* No envelope from address or no matching account.
                 * Use default if available, but allow fallback to environment
                 * variables. */
                conf.account_id = "default";
                if (conf.pretend || conf.debug)
                {
                    printf(_("falling back to default account\n"));
                }
                allow_fallback_to_env = 1;
            }
        }
        if (!account && !(account =
                    account_copy(find_account(account_list, conf.account_id))))
        {
            env_email = getenv("EMAIL");
            env_smtpserver = getenv("SMTPSERVER");
            if (allow_fallback_to_env
                    && (!conf.sendmail
                        || conf.cmdline_account->from || env_email)
                    && env_smtpserver)
            {
                if (conf.sendmail && !conf.cmdline_account->from)
                {
                    conf.cmdline_account->from = xstrdup(env_email);
                }
                conf.cmdline_account->host = xstrdup(env_smtpserver);
                account = account_copy(conf.cmdline_account);
                if (conf.pretend || conf.debug)
                {
                    printf(_("using environment variables "
                                "EMAIL and SMTPSERVER\n"));
                }
            }
            else
            {
                if (loaded_system_conffile && loaded_user_conffile)
                {
                    print_error(_("account %s not found in %s and %s"),
                            conf.account_id, loaded_system_conffile,
                            loaded_user_conffile);
                }
                else if (loaded_system_conffile)
                {
                    print_error(_("account %s not found in %s"),
                            conf.account_id, loaded_system_conffile);
                }
                else if (loaded_user_conffile)
                {
                    print_error(_("account %s not found in %s"),
                            conf.account_id, loaded_user_conffile);
                }
                else /* no conffile was read */
                {
                    print_error(_("account %s not found: "
                                "no configuration file available"),
                            conf.account_id);
                }
                error_code = EX_CONFIG;
                goto exit;
            }
        }
        /* Override the account with command line settings. Take special care
         * of the envelope-from address: only take it from the command line
         * if allow_from_override is set. */
        if (!account->allow_from_override)
        {
            conf.cmdline_account->mask &= ~ACC_FROM;
        }
        override_account(account, conf.cmdline_account);
    }
    else
    {
        account = account_copy(conf.cmdline_account);
        if (conf.pretend || conf.debug)
        {
            printf(_("using account specified on command line\n"));
        }
    }

    /* OK, we're using the settings in 'account'. Complete them and check
     * them. */
    if (account->auth_mech && !account->password && account->passwordeval)
    {
        if (eval(account->passwordeval, &account->password, &errstr) != 0)
        {
            print_error("%s", sanitize_string(errstr));
            error_code = EX_CONFIG;
            goto exit;
        }
    }
    if (account->port == 0)
    {
        if (account->protocol == SMTP_PROTO_SMTP)
        {
            if (account->tls && account->tls_nostarttls)
            {
                account->port = 465;
            }
            else
            {
                account->port = 25;
            }
        }
        else /* LMTP. Has no default port as of 2006-06-17. */
        {
        }
    }
    if (!account->tls_trust_file && !(account->mask & ACC_TLS_TRUST_FILE))
    {
        account->tls_trust_file = xstrdup("system");
    }
    if (account->proxy_host && account->proxy_port == 0)
    {
        account->proxy_port = 1080;
    }
    if (expand_domain(&(account->domain), &errstr) != CONF_EOK)
    {
        print_error("%s", sanitize_string(errstr));
        error_code = EX_CONFIG;
        goto exit;
    }
    if (conf.sendmail && account->from)
    {
        if (expand_from(&(account->from), &errstr) != CONF_EOK)
        {
            print_error("%s", sanitize_string(errstr));
            error_code = EX_CONFIG;
            goto exit;
        }
    }
    if (conf.sendmail && account->auto_from /* obsolete */)
    {
        free(account->from);
        account->from = msmtp_construct_env_from(account->maildomain);
    }
    if (check_account(account, (conf.sendmail && !conf.pretend),
                &errstr) != CONF_EOK)
    {
        if (account->id && account->conffile)
        {
            print_error(_("account %s from %s: %s"), account->id,
                    account->conffile, sanitize_string(errstr));
        }
        else
        {
            print_error("%s", sanitize_string(errstr));
        }
        error_code = EX_CONFIG;
        goto exit;
    }

    /* print configuration */
    if (conf.print_conf)
    {
        msmtp_print_conf(conf, account);
    }

    /* replace aliases */
    if (conf.sendmail && account->aliases)
    {
        if ((e = aliases_replace(account->aliases, conf.recipients,
                         &errstr)) != ALIASES_EOK)
        {
            print_error("%s: %s", account->aliases,
                    sanitize_string(errstr));
            error_code = EX_CONFIG;
            goto exit;
        }
    }

    /* stop if there's nothing to do */
    if (conf.pretend || (!conf.sendmail && !conf.serverinfo && !conf.rmqs))
    {
        error_code = EX_OK;
        goto exit;
    }

    /* initialize libraries */
#ifndef HAVE_SYSLOG
    if (conf.sendmail && account->syslog)
    {
        print_error(_("this platform does not support syslog logging"));
        error_code = EX_UNAVAILABLE;
        goto exit;
    }
#endif /* not HAVE_SYSLOG */
    if ((conf.sendmail || conf.rmqs) /* serverinfo does not use auth */
            && account->auth_mech && (strcmp(account->auth_mech, "") != 0)
            && !smtp_client_supports_authmech(account->auth_mech))
    {
        print_error(_("support for authentication method %s "
                    "is not compiled in"),
                account->auth_mech);
        error_code = EX_UNAVAILABLE;
        goto exit;
    }
    if ((e = net_lib_init(&errstr)) != NET_EOK)
    {
        print_error(_("cannot initialize networking: %s"),
                sanitize_string(errstr));
        error_code = EX_SOFTWARE;
        goto exit;
    }
    net_lib_initialized = 1;
    if (account->tls)
    {
#ifdef HAVE_TLS
        if ((e = mtls_lib_init(&errstr)) != TLS_EOK)
        {
            print_error(_("cannot initialize TLS library: %s"),
                    sanitize_string(errstr));
            error_code = EX_SOFTWARE;
            goto exit;
        }
        tls_lib_initialized = 1;
#else /* not HAVE_TLS */
        print_error(_("support for TLS is not compiled in"));
        error_code = EX_UNAVAILABLE;
        goto exit;
#endif /* not HAVE_TLS */
    }

    /* do the work */
    if (conf.sendmail)
    {
        int prepend_header_contains_from = 0;
        if (account->undisclosed_recipients
                || account->set_from_header == 1
                || (!have_from_header && account->set_from_header == 2)
                || (!have_date_header && account->set_date_header == 2)
                || (!have_msgid_header && account->set_msgid_header == 2))
        {
            if (!(prepend_header_tmpfile = tmpfile()))
            {
                print_error(_("cannot create temporary file: %s"),
                        sanitize_string(strerror(errno)));
                error_code = EX_IOERR;
                goto exit;
            }
        }
        if (account->set_from_header == 1
                || (!have_from_header && account->set_from_header == 2))
        {
            if (account->from_full_name)
            {
                fprintf(prepend_header_tmpfile, "From: %s <%s>\n",
                        account->from_full_name, account->from);
            }
            else
            {
                fprintf(prepend_header_tmpfile, "From: %s\n", account->from);
            }
            prepend_header_contains_from = 1;
        }
        if (account->undisclosed_recipients)
        {
            fputs("To: undisclosed-recipients:;\n", prepend_header_tmpfile);
        }
        if (!have_date_header && account->set_date_header == 2)
        {
            char rfc2822_timestamp[32];
            print_time_rfc2822(time(NULL), rfc2822_timestamp);
            fprintf(prepend_header_tmpfile, "Date: %s\n", rfc2822_timestamp);
        }
        if (!have_msgid_header && account->set_msgid_header == 2)
        {
            char *msgid = create_msgid(
                    account->host, account->domain, account->from);
            fprintf(prepend_header_tmpfile, "Message-ID: %s\n", msgid);
            free(msgid);
        }
        if (prepend_header_tmpfile
                && fseeko(prepend_header_tmpfile, 0, SEEK_SET) != 0)
        {
            print_error(_("cannot rewind temporary file: %s"),
                    sanitize_string(strerror(errno)));
            error_code = EX_IOERR;
            goto exit;
        }
        if ((error_code = msmtp_sendmail(account, conf.recipients,
                        prepend_header_tmpfile, prepend_header_contains_from,
                        header_tmpfile, stdin,
                        conf.debug, &mailsize,
                        &lmtp_errstrs, &lmtp_error_msgs,
                        &errmsg, &errstr)) != EX_OK)
        {
            if (account->protocol == SMTP_PROTO_LMTP && lmtp_errstrs)
            {
                lp_lmtp_errstrs = lmtp_errstrs;
                lp_lmtp_error_msgs = lmtp_error_msgs;
                while (!list_is_empty(lp_lmtp_errstrs))
                {
                    lp_lmtp_errstrs = lp_lmtp_errstrs->next;
                    lp_lmtp_error_msgs = lp_lmtp_error_msgs->next;
                    if (lp_lmtp_errstrs->data)
                    {
                        print_error("%s", sanitize_string(
                                    lp_lmtp_errstrs->data));
                        if ((lp = lp_lmtp_error_msgs->data))
                        {
                            while (!list_is_empty(lp))
                            {
                                lp = lp->next;
                                print_error(_("LMTP server message: %s"),
                                        sanitize_string(lp->data));
                            }
                            list_xfree(lp_lmtp_error_msgs->data, free);
                        }
                    }
                }
                list_xfree(lmtp_errstrs, free);
                list_free(lmtp_error_msgs);
                if (account->id && account->conffile)
                {
                    print_error(_("could not send mail to all recipients "
                                "(account %s from %s)"),
                            account->id, account->conffile);
                }
                else
                {
                    print_error(_("could not send mail to all recipients"));
                }
            }
            else
            {
                if (errstr)
                {
                    print_error("%s", sanitize_string(errstr));
                }
                if (errmsg)
                {
                    lp = errmsg;
                    while (!list_is_empty(lp))
                    {
                        lp = lp->next;
                        print_error(_("server message: %s"),
                                sanitize_string(lp->data));
                    }
                }
                if (account->id && account->conffile)
                {
                    print_error(_("could not send mail (account %s from %s)"),
                            account->id, account->conffile);
                }
                else
                {
                    print_error(_("could not send mail"));
                }
            }
        }
        if (account->logfile || account->syslog)
        {
            if (account->protocol == SMTP_PROTO_LMTP && lmtp_errstrs)
            {
                /* errstr is NULL; print short info to it */
                errstr = xasprintf(
                        _("delivery to one or more recipients failed"));
                /* we know that errmsg is NULL. that's ok. */
            }
            log_info = msmtp_get_log_info(account, conf.recipients, mailsize,
                    errmsg, errstr, error_code);
            if (account->logfile)
            {
                msmtp_log_to_file(account->logfile, account->logfile_time_format, log_info);
            }
#ifdef HAVE_SYSLOG
            if (account->syslog)
            {
                msmtp_log_to_syslog(account->syslog, log_info,
                        (error_code != EX_OK));
            }
#endif
            free(log_info);
        }
    }
    else if (conf.serverinfo)
    {
        if ((error_code = msmtp_serverinfo(account, conf.debug,
                        &errmsg, &errstr)) != EX_OK)
        {
            if (errstr)
            {
                print_error("%s", sanitize_string(errstr));
            }
            if (errmsg)
            {
                lp = errmsg;
                while (!list_is_empty(lp))
                {
                    lp = lp->next;
                    print_error(_("server message: %s"),
                            sanitize_string(lp->data));
                }
            }
        }
    }
    else /* rmqs */
    {
        if ((error_code = msmtp_rmqs(account, conf.debug, conf.rmqs_argument,
                        &errmsg, &errstr)) != EX_OK)
        {
            if (errstr)
            {
                print_error("%s", sanitize_string(errstr));
            }
            if (errmsg)
            {
                lp = errmsg;
                while (!list_is_empty(lp))
                {
                    lp = lp->next;
                    print_error(_("server message: %s"),
                            sanitize_string(lp->data));
                }
            }
        }
    }


exit:

    /* clean up */
    if (header_tmpfile)
    {
        fclose(header_tmpfile);
    }
    if (prepend_header_tmpfile)
    {
        fclose(prepend_header_tmpfile);
    }
    free(loaded_system_conffile);
    free(loaded_user_conffile);
#ifdef HAVE_TLS
    if (tls_lib_initialized)
    {
        mtls_lib_deinit();
    }
#endif /* HAVE_TLS */
    if (net_lib_initialized)
    {
        net_lib_deinit();
    }
    if (account_list)
    {
        list_xfree(account_list, account_free);
    }
    account_free(conf.cmdline_account);
    account_free(account);
    if (conf.recipients)
    {
        list_xfree(conf.recipients, free);
    }
    free(errstr);
    if (errmsg)
    {
        list_xfree(errmsg, free);
    }

    return error_code;
}
