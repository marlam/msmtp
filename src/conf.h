/*
 * conf.h
 *
 * This file is part of msmtp, an SMTP client.
 *
 * Copyright (C) 2000, 2003, 2004, 2005, 2006, 2007, 2008, 2010, 2011, 2014,
 * 2016
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

#ifndef CONF_H
#define CONF_H

#include "list.h"

/*
 * If a function with an 'errstr' argument returns a value != CONF_EOK,
 * '*errstr' either points to an allocates string containing an error
 * description or is NULL.
 * If such a function returns CONF_EOK, 'errstr' will not be changed.
 */
#define CONF_EOK        0       /* no error */
#define CONF_ECANTOPEN  1       /* Cannot open file */
#define CONF_EIO        2       /* Input/output error */
#define CONF_EPARSE     3       /* Parse error */
#define CONF_ESYNTAX    4       /* Syntax error */
#define CONF_EINSECURE  5       /* Insecure permissions */

/*
 * An account
 */

#define ACC_HOST                        (1LL << 0LL)
#define ACC_PORT                        (1LL << 1LL)
#define ACC_TIMEOUT                     (1LL << 2LL)
#define ACC_PROTOCOL                    (1LL << 3LL)
#define ACC_AUTO_FROM                   (1LL << 4LL)
#define ACC_FROM                        (1LL << 5LL)
#define ACC_DOMAIN                      (1LL << 6LL)
#define ACC_MAILDOMAIN                  (1LL << 7LL)
#define ACC_DSN_RETURN                  (1LL << 8LL)
#define ACC_DSN_NOTIFY                  (1LL << 9LL)
#define ACC_AUTH_MECH                   (1LL << 10LL)
#define ACC_USERNAME                    (1LL << 11LL)
#define ACC_PASSWORD                    (1LL << 12LL)
#define ACC_PASSWORDEVAL                (1LL << 13LL)
#define ACC_NTLMDOMAIN                  (1LL << 14LL)
#define ACC_TLS                         (1LL << 15LL)
#define ACC_TLS_NOSTARTTLS              (1LL << 16LL)
#define ACC_TLS_KEY_FILE                (1LL << 17LL)
#define ACC_TLS_CERT_FILE               (1LL << 18LL)
#define ACC_TLS_TRUST_FILE              (1LL << 19LL)
#define ACC_TLS_CRL_FILE                (1LL << 20LL)
#define ACC_TLS_FINGERPRINT             (1LL << 21LL)
#define ACC_TLS_NOCERTCHECK             (1LL << 22LL)
#define ACC_TLS_MIN_DH_PRIME_BITS       (1LL << 23LL)
#define ACC_TLS_PRIORITIES              (1LL << 24LL)
#define ACC_LOGFILE                     (1LL << 25LL)
#define ACC_SYSLOG                      (1LL << 26LL)
#define ACC_ALIASES                     (1LL << 27LL)
#define ACC_PROXY_HOST                  (1LL << 28LL)
#define ACC_PROXY_PORT                  (1LL << 29LL)
#define ACC_ADD_MISSING_FROM_HEADER     (1LL << 30LL)
#define ACC_ADD_MISSING_DATE_HEADER     (1LL << 31LL)
#define ACC_REMOVE_BCC_HEADERS          (1LL << 32LL)

typedef struct
{
    /* identification */
    char *id;                   /* name of this account */
    char *conffile;             /* name of the configuration file of this
                                   account or NULL for command line */
    long long mask;             /* combination of the above ACC_* flags.
                                   Shows which settings were changed */
    /* SMTP server */
    char *host;                 /* hostname of SMTP server */
    int port;                   /* port number */
    int timeout;                /* network timeout in seconds */
    /* SMTP settings */
    int protocol;               /* which SMTP sub protocol? */
    char *domain;               /* argument to EHLO command */
    int auto_from;              /* automatic envelope-from addresses? */
    char *from;                 /* envelope from address */
    char *maildomain;           /* the domain part of generated envelope from
                                   addresses */
    char *dsn_return;           /* DSN return request */
    char *dsn_notify;           /* DSN notify request */
    /* Authentication */
    char *auth_mech;            /* authentication mechanism */
    char *username;             /* username for authentication */
    char *password;             /* password for authentication */
    char *passwordeval;         /* command for password evaluation */
    char *ntlmdomain;           /* domain for NTLM authentication */
    /* TLS / SSL */
    int tls;                    /* flag: use TLS? */
    char *tls_key_file;         /* file in PEM format */
    char *tls_cert_file;        /* file in PEM format */
    char *tls_trust_file;       /* file in PEM format */
    char *tls_crl_file;         /* file in PEM format */
    unsigned char *tls_sha256_fingerprint; /* certificate fingerprint */
    unsigned char *tls_sha1_fingerprint;   /* certificate fingerprint */
    unsigned char *tls_md5_fingerprint;    /* certificate fingerprint */
    int tls_nostarttls;         /* flag: start TLS immediatly
                                   (without STARTTLS command)? */
    int tls_nocertcheck;        /* flag: do not check certificate? */
    int tls_min_dh_prime_bits;  /* parameter; -1 for default */
    char *tls_priorities;       /* parameter; NULL for default */
    /* logging */
    char *logfile;              /* NULL or logfile */
    char *syslog;               /* NULL or syslog facility */
    char *aliases;              /* NULL or aliases file */
    /* proxy */
    char *proxy_host;           /* NULL or proxy hostname */
    int proxy_port;             /* port number; 0 for default */
    /* header modifications */
    int add_missing_from_header;/* add From header if it is missing? */
    int add_missing_date_header;/* add Date header if it is missing? */
    int remove_bcc_headers;     /* remove the Bcc headers from the mail? */
} account_t;


/*
 * account_new()
 *
 * Create a new account_t. Built-in default values are filled in, except for
 * settings whose default values are not yet known. This currently only affects
 * the port.
 * Must be freed with account_free().
 * Both arguments may be NULL.
 */
account_t *account_new(const char *conffile, const char *id);

/*
 * account_copy()
 *
 * Create a new account which is a copy of 'acc'.
 * If 'acc' is NULL, NULL is returned.
 */
account_t *account_copy(account_t *acc);

/*
 * account_free()
 *
 * Free an account_t.
 */
void account_free(void *a);

/*
 * find_account()
 *
 * Find an account in a list of accounts by its id.
 * Returns the account or NULL.
 */
account_t *find_account(list_t *acc_list, const char *id);

/*
 * find_account_by_envelope_from()
 *
 * Find an account in a list of accounts by its envelope from address.
 * Returns the *first* account that matches or NULL.
 */
account_t *find_account_by_envelope_from(list_t *acc_list, const char *from);

/*
 * is_on(), is_off()
 *
 * Check whether the given string is "on" or "off"
 */
int is_on(char *s);
int is_off(char *s);

/*
 * get_pos_int()
 *
 * Gets a positive integer. Returns -1 on error.
 */
int get_pos_int(const char *arg);

/*
 * get_fingerprint()
 *
 * Gets a fingerprint of the given length and returns it in an allocated array.
 * Returns NULL on error.
 */
unsigned char *get_fingerprint(const char *arg, size_t len);

/*
 * check_auth_arg()
 *
 * checks if the given string is a proper argument to the auth command.
 * If so, the string is converted to uppercase and 0 is returned. Otherwise, 1
 * is returned.
 * Note that you have to check whether the arg is "off" separately, because
 * that value results in NULL.
 */
int check_auth_arg(char *arg);

/*
 * check_dsn_notify_arg()
 *
 * checks if the given string is a proper argument to the dsn_notify command.
 * If so, the string is converted to uppercase and 0 is returned. Otherwise, 1
 * is returned.
 * Note that you have to check whether the arg is "off" separately, because that
 * value results in NULL.
 */
int check_dsn_notify_arg(char *arg);

/*
 * check_syslog_arg()
 *
 * checks if the given string is a proper argument to the syslog command.
 * If so, the string is converted to uppercase and 0 is returned. Otherwise, 1
 * is returned.
 * Note that you have to check whether the arg is "on" or "off" or ""
 * separately.
 */
int check_syslog_arg(const char *arg);

/*
 * get_default_syslog_facility()
 *
 * Returns a pointer to an allocated string containing the default syslog
 * facility.
 */
char *get_default_syslog_facility(void);

/*
 * override_account()
 *
 * Override 'acc1' with 'acc2': those settings of acc2 whose flag is set in
 * acc2->mask override the corresponding settings of acc1.
 * The flags from acc2->mask will also be set in acc1->mask.
 */
void override_account(account_t *acc1, account_t *acc2);

/*
 * check_account()
 *
 * Check an account_t. 'sendmail_mode' must indicate whether msmtp works
 * in sendmail mode, because some checks depend on this.
 * If this function returns CONF_ESYNTAX, *errstr will always point to an
 * error string.
 * Used error codes: CONF_ESYNTAX
 */
int check_account(account_t *acc, int sendmail_mode, char **errstr);

/*
 * get_password_eval()
 *
 * Evaluates command in 'arg' and stores result in 'buf' (which is allocated).
 * Returns CONF_EIO if command exectution failed, otherwise CONF_EOK. On error,
 * *errstr will contain an error string.
 */
int get_password_eval(const char *arg, char **buf, char **errstr);

/*
 * get_conf()
 *
 * Read 'conffile' and store all account data in 'acc_list'.
 * If 'securitycheck' is set, the file must not have more permissions than 0600,
 * must be a regular file and owned by the current user.
 * Used error codes: CONF_ECANTOPEN, CONF_EIO, CONF_EPARSE, CONF_ESYNTAX
 */
int get_conf(const char *conffile, int securitycheck, list_t **acc_list,
        char **errstr);

#endif
