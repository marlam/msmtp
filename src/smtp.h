/*
 * smtp.h
 *
 * This file is part of msmtp, an SMTP client.
 *
 * Copyright (C) 2000, 2003, 2004, 2005, 2006, 2008, 2010, 2012
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

#ifndef SMTP_H
#define SMTP_H

#include <stdio.h>

#include "list.h"
#include "readbuf.h"
#include "net.h"
#ifdef HAVE_TLS
# include "tls.h"
#endif /* HAVE_TLS */


/* SMTP errors */

/*
 * If a function with an 'errstr' argument returns a value != SMTP_EOK,
 * '*errstr' either points to an allocates string containing an error
 * description or is NULL.
 * If such a function returns SMTP_EOK, 'errstr' will not be changed.
 */
#define SMTP_EOK                0       /* no error */
#define SMTP_EIO                1       /* Input/output error */
#define SMTP_EPROTO             2       /* Protocol violation */
#define SMTP_EINVAL             3       /* Invalid input data */
#define SMTP_EUNAVAIL           4       /* Requested service unavailable */
#define SMTP_EAUTHFAIL          5       /* Authentication failed */
#define SMTP_ELIBFAILED         6       /* An underlying library failed */
#define SMTP_EINSECURE          7       /* The requested action would be
                                           insecure */

/* SMTP sub protocols */
#define SMTP_PROTO_SMTP         0       /* default: SMTP / ESMTP */
#define SMTP_PROTO_LMTP         1       /* LMTP, RFC 2033 */


/* SMTP capabilities */

#define SMTP_CAP_STARTTLS               (1 << 0)
#define SMTP_CAP_DSN                    (1 << 1)
#define SMTP_CAP_PIPELINING             (1 << 2)
#define SMTP_CAP_SIZE                   (1 << 3)
#define SMTP_CAP_AUTH                   (1 << 4)
#define SMTP_CAP_AUTH_PLAIN             (1 << 5)
#define SMTP_CAP_AUTH_LOGIN             (1 << 6)
#define SMTP_CAP_AUTH_CRAM_MD5          (1 << 7)
#define SMTP_CAP_AUTH_DIGEST_MD5        (1 << 8)
#define SMTP_CAP_AUTH_SCRAM_SHA_1       (1 << 9)
#define SMTP_CAP_AUTH_GSSAPI            (1 << 10)
#define SMTP_CAP_AUTH_EXTERNAL          (1 << 11)
#define SMTP_CAP_AUTH_NTLM              (1 << 12)
#define SMTP_CAP_ETRN                   (1 << 13)


/*
 * This structure describes the capabilities of an SMTP server.
 * 'flags' is a combination of the SMTP_CAP_* values above.
 * If (flags & SMTP_CAP_SIZE), 'size' contains the max size of a message that
 * the SMTP server will accept (0 means there is no limit).
 */
typedef struct
{
    int flags;
    long size;
} smtp_cap_t;

/*
 * This structure represents an SMTP server. Do not access it directly.
 */
typedef struct
{
    int fd;
#ifdef HAVE_TLS
    tls_t tls;
#endif /* HAVE_TLS */
    readbuf_t readbuf;
    int protocol;
    smtp_cap_t cap;
    FILE *debug;
} smtp_server_t;


/*
 * smtp_new()
 *
 * Create a new smtp_server_t. If 'debug' is not NULL, the complete
 * conversation with the SMTP server will be logged to the referenced file.
 * Beware: this log may contain user passwords.
 * 'protocol' must be one of the SMTP_PROTO_* constants.
 */
smtp_server_t smtp_new(FILE *debug, int protocol);

/*
 * smtp_connect()
 *
 * Connect to a SMTP server.
 * If 'server_canonical_name' is not NULL, a pointer to a string containing the
 * canonical hostname of the server will be stored in '*server_canonical_name',
 * or NULL if this information is not available.
 * If 'server_address' is not NULL, a pointer to a string containing the
 * network address of the server will be stored in '*server_address',
 * or NULL if this information is not available.
 * Both strings are allocated.
 * Used error codes: NET_EHOSTNOTFOUND, NET_ESOCKET, NET_ECONNECT
 * Success: NET_EOK
 */
int smtp_connect(smtp_server_t *srv, const char *host, int port, int timeout,
        char **server_canonical_name, char **server_address,
        char **errstr);

/*
 * smtp_msg_status()
 *
 * Returns the three digit status code of the SMTP server message 'msg', which
 * *must* be a valid SMTP server message.
 */
int smtp_msg_status(list_t *msg);

/*
 * smtp_get_greeting()
 *
 * Get the greeting message from the SMTP server.
 * If 'buf' is not NULL, it will contain a pointer to an allocated string
 * containing the identificatin string of the SMTP server (untrusted data!)
 * Used error codes: SMTP_EIO, SMTP_EPROTO
 */
int smtp_get_greeting(smtp_server_t *srv, list_t **errmsg, char **buf,
        char **errstr);

/*
 * smtp_init()
 *
 * Initialize an SMTP session with the connected SMTP server 'srv'
 * (via the SMTP EHLO/HELO command). This function must be used after
 * the server is connected and before any mail is send. It must also be used
 * (a second time) after TLS is started via the STARTTLS command.
 * This function determines the capabilities of the SMTP server.
 * 'ehlo_domain' is the parameter for the EHLO/HELO command. If you don't know
 * what to use, use "localhost".
 * 'error_msg' contains an error message from the SMTP server or NULL.
 * Used error codes: SMTP_EIO, SMTP_EPROTO, SMTP_EINVAL
 */
int smtp_init(smtp_server_t *srv, const char *ehlo_domain, list_t **msg,
        char **errstr);

/*
 * smtp_tls_init()
 *
 * Prepare TLS encryption. See tls_init() for a description of the arguments.
 * Used error codes: TLS_ELIBFAILED, TLS_EFILE
 * Success: TLS_EOK
 */
#ifdef HAVE_TLS
int smtp_tls_init(smtp_server_t *srv,
        const char *tls_key_file, const char *tls_cert_file,
        const char *tls_trust_file, const char *tls_crl_file,
        const unsigned char *tls_sha1_fingerprint,
        const unsigned char *tls_md5_fingerprint,
        int force_sslv3, int min_dh_prime_bits,
        const char *priorities, char **errstr);
#endif /* HAVE_TLS */

/*
 * smtp_tls_starttls()
 *
 * Announce the start of TLS encryption with an initialized SMTP server,
 * using the STARTTLS command.
 * Use this function after smtp_init(). The SMTP server must have the
 * SMTP_CAP_STARTTLS capability.
 * Call smtp_tls() afterwards. Finally, call smtp_init() again (the SMTP server
 * might advertise different capabilities when TLS is active, for example plain
 * text authentication mechanisms).
 * 'error_msg' contains the error message from the SMTP server or NULL.
 * Used error codes: SMTP_EIO, SMTP_EPROTO, SMTP_EINVAL
 */
#ifdef HAVE_TLS
int smtp_tls_starttls(smtp_server_t *srv, list_t **error_msg, char **errstr);
#endif /* HAVE_TLS */

/*
 * smtp_tls()
 *
 * Start TLS with a connected SMTP server.
 * Use this function either after smtp_connect() for SMTP servers
 * that use TLS without the STARTTLS command (service smtps; default port 465),
 * or after smtp_tls_starttls() for SMTP servers that support the STARTTLS
 * command.
 * See tls_start() for a description of the arguments.
 * Used error codes: TLS_ELIBFAILED, TLS_ECERT, TLS_EHANDSHAKE
 * Success: TLS_EOK
 */
#ifdef HAVE_TLS
int smtp_tls(smtp_server_t *srv, const char *hostname, int tls_nocertcheck,
        tls_cert_info_t *tci, char **errstr);
#endif /* HAVE_TLS */

/*
 * smtp_client_supports_authmech()
 *
 * Returns 1 if the authentication mechanism is supported by the underlying
 * authentication code and 0 otherwise.
 */
int smtp_client_supports_authmech(const char *mech);

/*
 * smtp_server_supports_authmech()
 *
 * Returns 1 if the authentication mechanism is supported by the SMTP server
 * and 0 otherwise.
 */
int smtp_server_supports_authmech(smtp_server_t *srv, const char *mech);

/*
 * smtp_auth()
 *
 * Authentication.
 * Use smtp_client_supports_authmech() and smtp_server_supports_authmech()
 * to find out which authentication mechanisms are available.
 * The special value "" for 'auth_mech' causes the function to choose the best
 * authentication method supported by the server, unless TLS is incative and the
 * method sends plain text passwords. In this case, the function fails with
 * SMTP_EINSECURE.
 * The hostname is the name of the SMTP server. It may be needed for
 * authentication.
 * The ntlmdomain may be NULL (even if you use NTLM authentication).
 * If 'password' is NULL, but the authentication method needs a password,
 * the 'password_callback' function is called (if 'password_callback' is not
 * NULL). It is expected to return a * password in an allocated buffer or NULL
 * (if it fails).
 * 'error_msg' contains the error message from the SMTP server or NULL.
 * Used error codes: SMTP_EIO, SMTP_EINVAL, SMTP_EPROTO, SMTP_EAUTHFAIL,
 * SMTP_ELIBFAILED, SMTP_EINSECURE, SMTP_EUNAVAIL
 */
int smtp_auth(smtp_server_t *srv,
        const char *hostname,
        const char *user,
        const char *password,
        const char *ntlmdomain,
        const char *auth_mech,
        char *(*password_callback)(const char *hostname, const char *user),
        list_t **error_msg,
        char **errstr);

/*
 * smtp_envelope()
 *
 * Sends the mail envelope (sender, recipients, ...)
 * The mail data must be sent immediately afterwards with smtp_send_mail()
 * envelope_from:       The envelope from address
 * recipients:          The list of recipients
 * dsn_notify:          Delivery Status Notification request string (see man
 *                      page) or NULL. The SMTP server must support
 *                      SMTP_CAP_DSN.
 * dsn_return:          Either "HDRS", "FULL" or NULL. The SMTP server must
 *                      support SMTP_CAP_DSN.
 * error_msg:           If an error occurs, this will contain the SMTP server
 *                      message (or NULL)
 * Used error codes: SMTP_EIO, SMTP_EPROTO, SMTP_EINVAL, SMTP_EUNAVAIL
 */
int smtp_send_envelope(smtp_server_t *srv,
        const char *envelope_from,
        list_t *recipients,
        const char *dsn_notify,
        const char *dsn_return,
        list_t **error_msg,
        char **errstr);

/*
 * smtp_send_mail()
 *
 * Sends a mail via the SMTP server 'srv'.
 * You can use this function more than once to send the mail in chunks.
 * When you're done, call smtp_end_mail().
 * keep_bcc:    Set this flag in one of the following situation:
 *              1. The mail data contains a Bcc header that you want to keep
 *                 (highly unlikely)
 *              2. The mail data contains no headers at all. This prevents
 *                 accidental removal of mail body contents.
 *              The default (unset) is to expect headers in the mail data and
 *              remove the Bcc header.
 * mailf:       The file containing the mail
 * mailsize:    This counter will be increased by the number of bytes
 *              of the mail (as transferred to the SMTP server) in case
 *              of successful delivery; the contents are undefined in
 *              case of failure).
 * error_msg:   If an error occurs, this will contain the SMTP server
 *              message (or NULL)
 * Used error codes: SMTP_EIO
 */
int smtp_send_mail(smtp_server_t *srv, FILE *mailf, int keep_bcc,
        long *mailsize, char **errstr);

/*
 * smtp_end_mail()
 *
 * Sends a single dot on a line to the SMTP server, signalling that the
 * transmission of mail data is complete.
 * This function only works for the SMTP protocol; for LMTP, use
 * smtp_end_mail_lmtp() instead.
 * Unlike other functions, this function always returns the SMTP server's
 * message, unless the return code is SMTP_EIO.
 * Used error codes: SMTP_EIO, SMTP_EUNAVAIL
 */
int smtp_end_mail(smtp_server_t *srv, list_t **msg, char **errstr);

/*
 * smtp_end_mail_lmtp()
 *
 * This function only works for the LMTP protocol; for SMTP, use
 * smtp_end_mail() instead.
 *
 * It sends a single dot on a line to the SMTP server, signalling that the
 * transmission of mail data is complete.
 *
 * The server sends one reply per recipient (therefore 'recipients' must be
 * the same list that was given to smtp_send_envelope()).
 *
 * If all of these replies are positive, SMTP_EOK will be returned.
 * If an IO error occured, SMTP_EIO will be returned (as always).
 * In both cases, 'errstrs' and 'error_msgs' will be NULL.
 *
 * If one or more of the replies are negative, SMTP_EUNAVAIL will be returned,
 * and 'errstrs' and 'error_msgs' will contain one entry for each entry in the
 * 'recipients' list. If the corresponding recipient caused a positive reply,
 * both the 'errstrs' and 'error_msgs' entries will be NULL; if it caused a
 * negative reply, the 'errstrs' entry will contain an error message and the
 * 'error_msgs' entry will contain the negative reply.
 *
 * Used error codes: SMTP_EIO, SMTP_EUNAVAIL
 */
int smtp_end_mail_lmtp(smtp_server_t *srv,
        list_t *recipients,
        list_t **errstrs,
        list_t **error_msgs,
        char **errstr);

/*
 * smtp_etrn()
 *
 * Send a Remote Message Queue Starting request to the SMTP server via the ETRN
 * command (RFC 1985).
 * Used error codes: SMTP_EIO, SMTP_EINVAL, SMTP_EUNAVAIL, SMTP_EPROTO
 */
int smtp_etrn(smtp_server_t *srv, const char *etrn_argument,
        list_t **msg, char **errstr);

/*
 * smtp_quit()
 *
 * Sends the QUIT command to the SMTP server 'srv' to end the current session.
 * Use smtp_close() after this function.
 * Used error codes: SMTP_EIO, SMTP_EPROTO, SMTP_EINVAL
 */
int smtp_quit(smtp_server_t *srv, char **errstr);

/*
 * smtp_close()
 *
 * Closes the connection to the SMTP server 'srv'.
 * 'srv' is unusable afterwards; reinitialize it with smtp_new() if you want
 * to reuse it.
 */
void smtp_close(smtp_server_t *srv);

#endif
