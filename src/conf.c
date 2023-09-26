/*
 * conf.c
 *
 * This file is part of msmtp, an SMTP client.
 *
 * Copyright (C) 2000, 2003, 2004, 2005, 2006, 2007, 2008, 2010, 2011, 2012,
 * 2014, 2015, 2016, 2018, 2019, 2020, 2021, 2022, 2023
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

#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#ifdef HAVE_FNMATCH_H
# include <fnmatch.h>
#endif

#include "gettext.h"
#define _(string) gettext(string)

#include "list.h"
#include "smtp.h"
#include "tools.h"
#include "net.h"
#include "xalloc.h"
#include "eval.h"
#include "conf.h"

/* buffer size for configuration file lines */
#define LINEBUFSIZE 501


/*
 * account_new()
 *
 * see conf.h
 */

account_t *account_new(const char *conffile, const char *id)
{
    account_t *a;
    a = xmalloc(sizeof(account_t));
    a->id = id ? xstrdup(id) : NULL;
    a->conffile = conffile ? xstrdup(conffile) : NULL;
    a->mask = 0LL;
    a->host = NULL;
    a->port = 0;                /* this must be set later */
    a->timeout = 0;
    a->protocol = SMTP_PROTO_SMTP;
    a->domain = xstrdup("localhost");
    a->allow_from_override = 1;
    a->auto_from = 0;
    a->from = NULL;
    a->from_full_name = NULL;
    a->maildomain = NULL;
    a->dsn_return = NULL;
    a->dsn_notify = NULL;
    a->auth_mech = NULL;
    a->username = NULL;
    a->password = NULL;
    a->passwordeval = NULL;
    a->ntlmdomain = NULL;
    a->tls = 0;
    a->tls_nostarttls = 0;
    a->tls_key_file = NULL;
    a->tls_cert_file = NULL;
    a->tls_trust_file = NULL;
    a->tls_crl_file = NULL;
    a->tls_sha256_fingerprint = NULL;
    a->tls_sha1_fingerprint = NULL;
    a->tls_md5_fingerprint = NULL;
    a->tls_nocertcheck = 0;
    a->tls_min_dh_prime_bits = -1;
    a->tls_priorities = NULL;
    a->tls_host_override = NULL;
    a->logfile = NULL;
    a->logfile_time_format = NULL;
    a->syslog = NULL;
    a->aliases = NULL;
    a->proxy_host = NULL;
    a->proxy_port = 0;
    a->set_from_header = 2;
    a->set_date_header = 2;
    a->set_msgid_header = 2;
    a->remove_bcc_headers = 1;
    a->undisclosed_recipients = 0;
    a->source_ip = NULL;
    a->socketname = NULL;
    return a;
}


/*
 * account_copy()
 *
 * see conf.h
 */

account_t *account_copy(account_t *acc)
{
    account_t *a = NULL;

    if (acc)
    {
        a = xmalloc(sizeof(account_t));
        a->id = acc->id ? xstrdup(acc->id) : NULL;
        a->conffile = acc->conffile ? xstrdup(acc->conffile) : NULL;
        a->mask = acc->mask;
        a->host = acc->host ? xstrdup(acc->host) : NULL;
        a->port = acc->port;
        a->timeout = acc->timeout;
        a->protocol = acc->protocol;
        a->domain = acc->domain ? xstrdup(acc->domain) : NULL;
        a->allow_from_override = acc->allow_from_override;
        a->auto_from = acc->auto_from;
        a->from = acc->from ? xstrdup(acc->from) : NULL;
        a->from_full_name = acc->from_full_name ? xstrdup(acc->from_full_name) : NULL;
        a->maildomain = acc->maildomain ? xstrdup(acc->maildomain) : NULL;
        a->dsn_return = acc->dsn_return ? xstrdup(acc->dsn_return) : NULL;
        a->dsn_notify = acc->dsn_notify ? xstrdup(acc->dsn_notify) : NULL;
        a->auth_mech = acc->auth_mech ? xstrdup(acc->auth_mech) : NULL;
        a->username = acc->username ? xstrdup(acc->username) : NULL;
        a->password = acc->password ? xstrdup(acc->password) : NULL;
        a->passwordeval = acc->passwordeval ? xstrdup(acc->passwordeval) : NULL;
        a->ntlmdomain = acc->ntlmdomain ? xstrdup(acc->ntlmdomain) : NULL;
        a->tls = acc->tls;
        a->tls_nostarttls = acc->tls_nostarttls;
        a->tls_key_file = acc->tls_key_file ? xstrdup(acc->tls_key_file) : NULL;
        a->tls_cert_file =
            acc->tls_cert_file ? xstrdup(acc->tls_cert_file) : NULL;
        a->tls_trust_file =
            acc->tls_trust_file ? xstrdup(acc->tls_trust_file) : NULL;
        a->tls_crl_file =
            acc->tls_crl_file ? xstrdup(acc->tls_crl_file) : NULL;
        if (acc->tls_sha256_fingerprint)
        {
            a->tls_sha256_fingerprint = xmalloc(32);
            memcpy(a->tls_sha256_fingerprint, acc->tls_sha256_fingerprint, 32);
        }
        else
        {
            a->tls_sha256_fingerprint = NULL;
        }
        if (acc->tls_sha1_fingerprint)
        {
            a->tls_sha1_fingerprint = xmalloc(20);
            memcpy(a->tls_sha1_fingerprint, acc->tls_sha1_fingerprint, 20);
        }
        else
        {
            a->tls_sha1_fingerprint = NULL;
        }
        if (acc->tls_md5_fingerprint)
        {
            a->tls_md5_fingerprint = xmalloc(16);
            memcpy(a->tls_md5_fingerprint, acc->tls_md5_fingerprint, 16);
        }
        else
        {
            a->tls_md5_fingerprint = NULL;
        }
        a->tls_nocertcheck = acc->tls_nocertcheck;
        a->tls_min_dh_prime_bits = acc->tls_min_dh_prime_bits;
        a->tls_priorities =
            acc->tls_priorities ? xstrdup(acc->tls_priorities) : NULL;
        a->tls_host_override =
            acc->tls_host_override ? xstrdup(acc->tls_host_override) : NULL;
        a->logfile = acc->logfile ? xstrdup(acc->logfile) : NULL;
        a->logfile_time_format =
            acc->logfile_time_format ? xstrdup(acc->logfile_time_format) : NULL;
        a->syslog = acc->syslog ? xstrdup(acc->syslog) : NULL;
        a->aliases = acc->aliases ? xstrdup(acc->aliases) : NULL;
        a->proxy_host = acc->proxy_host ? xstrdup(acc->proxy_host) : NULL;
        a->proxy_port = acc->proxy_port;
        a->set_from_header = acc->set_from_header;
        a->set_date_header = acc->set_date_header;
        a->set_msgid_header = acc->set_msgid_header;
        a->remove_bcc_headers = acc->remove_bcc_headers;
        a->undisclosed_recipients = acc->undisclosed_recipients;
        a->source_ip = acc->source_ip ? xstrdup(acc->source_ip) : NULL;
        a->socketname = acc->socketname ? xstrdup(acc->socketname) : NULL;
    }
    return a;
}


/*
 * account_free()
 *
 * see conf.h
 */

void account_free(void *a)
{
    account_t *p = a;
    if (p)
    {
        free(p->id);
        free(p->conffile);
        free(p->host);
        free(p->domain);
        free(p->from);
        free(p->from_full_name);
        free(p->maildomain);
        free(p->auth_mech);
        free(p->username);
        free(p->password);
        free(p->passwordeval);
        free(p->ntlmdomain);
        free(p->tls_key_file);
        free(p->tls_cert_file);
        free(p->tls_trust_file);
        free(p->tls_crl_file);
        free(p->tls_sha256_fingerprint);
        free(p->tls_sha1_fingerprint);
        free(p->tls_md5_fingerprint);
        free(p->tls_priorities);
        free(p->tls_host_override);
        free(p->dsn_return);
        free(p->dsn_notify);
        free(p->logfile);
        free(p->logfile_time_format);
        free(p->syslog);
        free(p->aliases);
        free(p->proxy_host);
        free(p->source_ip);
        free(p->socketname);
        free(p);
    }
}


/*
 * find_account()
 *
 * see conf.h
 */

account_t *find_account(list_t *acc_list, const char *id)
{
    account_t *a = NULL;
    char *acc_id;

    while (!list_is_empty(acc_list))
    {
        acc_list = acc_list->next;
        acc_id = ((account_t *)(acc_list->data))->id;
        if (acc_id && strcmp(id, acc_id) == 0)
        {
            a = acc_list->data;
            break;
        }
    }

    return a;
}

static bool from_matches_account_from(const char *from, const char *acc_from)
{
#ifdef HAVE_FNMATCH_H
    if (strchr(acc_from, '?') || strchr(acc_from, '*') || strchr(acc_from, '['))
    {
        /* This is a wildcard pattern according to glob(7) */
        return fnmatch(acc_from, from, 0) != FNM_NOMATCH;
    }
#endif
    /* simple matching */
    return strcasecmp(from, acc_from) == 0;
}

/*
 * find_account_by_envelope_from()
 *
 * see conf.h
 */

account_t *find_account_by_envelope_from(list_t *acc_list, const char *from)
{
    account_t *a = NULL;
    const char *from_detail = strchr(from, '+');
    const char *from_domain = strchr(from, '@');
    const char *acc_from, *acc_domain;
    char *from_without_detail = NULL;

    while (!list_is_empty(acc_list))
    {
        acc_list = acc_list->next;
        acc_from = ((account_t *)(acc_list->data))->from;
        if (!acc_from)
        {
            continue;
        }
        if (from_matches_account_from(from, acc_from))
        {
            a = acc_list->data;
            break;
        }
        else if (from_detail && from_domain && !strchr(acc_from, '+'))
        {
            /*
             * Subaddressing matches the pattern /user+detail@domain/. Take `from` to
             * match `acc_from` iff both user and domain match; i.e., ignore the detail.
             */
            if (!from_without_detail)
            {
                from_without_detail = xstrdup(from);
                size_t pos = from_detail - from;
                strcpy(from_without_detail + pos, from_domain);
            }
            if (from_matches_account_from(from_without_detail, acc_from))
            {
                a = acc_list->data;
                break;
            }
        }
    }
    free(from_without_detail);

    return a;
}


/*
 * is_on(), is_off(), is_auto()
 *
 * see conf.h
 */

int is_on(const char *s)
{
    return (strcmp(s, "on") == 0);
}

int is_off(const char *s)
{
    return (strcmp(s, "off") == 0);
}

int is_auto(const char *s)
{
    return (strcmp(s, "auto") == 0);
}


/*
 * get_pos_int()
 *
 * see conf.h
 */

int get_pos_int(const char *s)
{
    long x;
    char *p;

    errno = 0;
    x = strtol(s, &p, 0);
    if (p == s || x <= 0 || (x == LONG_MAX && errno == ERANGE) || x > INT_MAX)
    {
        x = -1;
    }
    else if (*p != '\0')
    {
        /* trailing garbage */
        x = -1;
    }

    return x;
}


/*
 * get_fingerprint()
 *
 * see conf.h
 */

unsigned char *get_fingerprint(const char *s, size_t len)
{
    unsigned char *fingerprint = xmalloc(len);
    unsigned char hex[2];
    size_t i, j;
    char c;

    if (strlen(s) != 2 * len + (len - 1))
    {
        free(fingerprint);
        return NULL;
    }
    for (i = 0; i < len; i++)
    {
        for (j = 0; j < 2; j++)
        {
            c = toupper((unsigned char)s[3 * i + j]);
            if (c >= '0' && c <= '9')
            {
                hex[j] = c - '0';
            }
            else if (c >= 'A' && c <= 'F')
            {
                hex[j] = c - 'A' + 10;
            }
            else
            {
                free(fingerprint);
                return NULL;
            }
        }
        if (i < len - 1 && s[3 * i + 2] != ':' && s[3 * i + 2] != ' ')
        {
            free(fingerprint);
            return NULL;
        }
        fingerprint[i] = (hex[0] << 4) | hex[1];
    }
    return fingerprint;
}


/*
 * check_auth_arg()
 *
 * see conf.h
 */

int check_auth_arg(char *arg)
{
    size_t l, i;

    if (*arg == '\0')
    {
        return 0;
    }
    else if (strcmp(arg, "plain") == 0
            || strcmp(arg, "cram-md5") == 0
            || strcmp(arg, "digest-md5") == 0
            || strcmp(arg, "scram-sha-1") == 0
            || strcmp(arg, "scram-sha-256") == 0
            || strcmp(arg, "gssapi") == 0
            || strcmp(arg, "external") == 0
            || strcmp(arg, "login") == 0
            || strcmp(arg, "ntlm") == 0
            || strcmp(arg, "oauthbearer") == 0
            || strcmp(arg, "xoauth2") == 0)
    {
        l = strlen(arg);
        for (i = 0; i < l; i++)
        {
            arg[i] = toupper((unsigned char)arg[i]);
        }
        return 0;
    }
    else
    {
        return 1;
    }
}


/*
 * check_dsn_notify_arg()
 *
 * see conf.h
 */

int check_dsn_notify_arg(char *arg)
{
    int count;
    size_t i;
    size_t l;

    if (strcmp(arg, "never") != 0)
    {
        l = 0;
        count = 0;
        if (strstr(arg, "failure"))
        {
            count++;
            l += 7;
        }
        if (strstr(arg, "delay"))
        {
            count++;
            l += 5;
        }
        if (strstr(arg, "success"))
        {
            count++;
            l += 7;
        }
        if (count == 0
                || (strlen(arg) != l + count - 1)
                || (count == 2 && !strchr(arg, ','))
                || (count == 3 && !(strchr(arg, ',')
                        && strchr(strchr(arg, ',') + 1, ','))))
        {
            return 1;
        }
    }
    l = strlen(arg);
    for (i = 0; i < l; i++)
    {
        arg[i] = toupper((unsigned char)arg[i]);
    }
    return 0;
}


/*
 * check_syslog_arg()
 *
 * see conf.h
 */

int check_syslog_arg(const char *arg)
{
    if (strcmp(arg, "LOG_USER") == 0
            || strcmp(arg, "LOG_MAIL") == 0
            || (strncmp(arg, "LOG_LOCAL", 9) == 0
                && strlen(arg) == 10
                && (arg[9] == '0'
                    || arg[9] == '1'
                    || arg[9] == '2'
                    || arg[9] == '3'
                    || arg[9] == '4'
                    || arg[9] == '5'
                    || arg[9] == '6'
                    || arg[9] == '7')))
    {
        return 0;
    }
    else
    {
        return 1;
    }
}


/*
 * get_default_syslog_facility()
 *
 * Returns a pointer to an allocated string containing the default syslog
 * facility.
 */

char *get_default_syslog_facility(void)
{
    return xstrdup("LOG_USER");
}


/*
 * override_account()
 *
 * see conf.h
 */

void override_account(account_t *acc1, account_t *acc2)
{
    if (acc2->conffile)
    {
        free(acc1->conffile);
        acc1->conffile = xstrdup(acc2->conffile);
    }
    if (acc2->mask & ACC_HOST)
    {
        free(acc1->host);
        acc1->host = acc2->host ? xstrdup(acc2->host) : NULL;
    }
    if (acc2->mask & ACC_PORT)
    {
        acc1->port = acc2->port;
    }
    if (acc2->mask & ACC_TIMEOUT)
    {
        acc1->timeout = acc2->timeout;
    }
    if (acc2->mask & ACC_PROTOCOL)
    {
        acc1->protocol = acc2->protocol;
    }
    if (acc2->mask & ACC_DOMAIN)
    {
        free(acc1->domain);
        acc1->domain = acc2->domain ? xstrdup(acc2->domain) : NULL;
    }
    if (acc2->mask & ACC_AUTO_FROM)
    {
        acc1->auto_from = acc2->auto_from;
    }
    if (acc2->mask & ACC_FROM)
    {
        free(acc1->from);
        acc1->from = acc2->from ? xstrdup(acc2->from) : NULL;
    }
    if (acc2->mask & ACC_FROM_FULL_NAME)
    {
        acc1->from_full_name = acc2->from_full_name ? xstrdup(acc2->from_full_name) : NULL;
    }
    if (acc2->mask & ACC_ALLOW_FROM_OVERRIDE)
    {
        acc1->allow_from_override = acc2->allow_from_override;
    }
    if (acc2->mask & ACC_MAILDOMAIN)
    {
        free(acc1->maildomain);
        acc1->maildomain = acc2->maildomain ? xstrdup(acc2->maildomain) : NULL;
    }
    if (acc2->mask & ACC_AUTH_MECH)
    {
        free(acc1->auth_mech);
        acc1->auth_mech = acc2->auth_mech ? xstrdup(acc2->auth_mech) : NULL;
    }
    if (acc2->mask & ACC_USERNAME)
    {
        free(acc1->username);
        acc1->username = acc2->username ? xstrdup(acc2->username) : NULL;
    }
    if (acc2->mask & ACC_PASSWORD)
    {
        free(acc1->password);
        acc1->password = acc2->password ? xstrdup(acc2->password) : NULL;
    }
    if (acc2->mask & ACC_PASSWORDEVAL)
    {
        free(acc1->passwordeval);
        acc1->passwordeval =
            acc2->passwordeval ? xstrdup(acc2->passwordeval) : NULL;
    }
    if (acc2->mask & ACC_NTLMDOMAIN)
    {
        free(acc1->ntlmdomain);
        acc1->ntlmdomain = acc2->ntlmdomain ? xstrdup(acc2->ntlmdomain) : NULL;
    }
    if (acc2->mask & ACC_TLS)
    {
        acc1->tls = acc2->tls;
    }
    if (acc2->mask & ACC_TLS_NOSTARTTLS)
    {
        acc1->tls_nostarttls = acc2->tls_nostarttls;
    }
    if (acc2->mask & ACC_TLS_KEY_FILE)
    {
        free(acc1->tls_key_file);
        acc1->tls_key_file =
            acc2->tls_key_file ? xstrdup(acc2->tls_key_file) : NULL;
    }
    if (acc2->mask & ACC_TLS_CERT_FILE)
    {
        free(acc1->tls_cert_file);
        acc1->tls_cert_file =
            acc2->tls_cert_file ? xstrdup(acc2->tls_cert_file) : NULL;
    }
    if (acc2->mask & ACC_TLS_TRUST_FILE)
    {
        free(acc1->tls_trust_file);
        acc1->tls_trust_file =
            acc2->tls_trust_file ? xstrdup(acc2->tls_trust_file) : NULL;
    }
    if (acc2->mask & ACC_TLS_CRL_FILE)
    {
        free(acc1->tls_crl_file);
        acc1->tls_crl_file =
            acc2->tls_crl_file ? xstrdup(acc2->tls_crl_file) : NULL;
    }
    if (acc2->mask & ACC_TLS_FINGERPRINT)
    {
        free(acc1->tls_sha256_fingerprint);
        if (acc2->tls_sha256_fingerprint)
        {
            acc1->tls_sha256_fingerprint = xmalloc(32);
            memcpy(acc1->tls_sha256_fingerprint, acc2->tls_sha256_fingerprint, 32);
        }
        else
        {
            acc1->tls_sha256_fingerprint = NULL;
        }
        free(acc1->tls_sha1_fingerprint);
        if (acc2->tls_sha1_fingerprint)
        {
            acc1->tls_sha1_fingerprint = xmalloc(20);
            memcpy(acc1->tls_sha1_fingerprint, acc2->tls_sha1_fingerprint, 20);
        }
        else
        {
            acc1->tls_sha1_fingerprint = NULL;
        }
        free(acc1->tls_md5_fingerprint);
        if (acc2->tls_md5_fingerprint)
        {
            acc1->tls_md5_fingerprint = xmalloc(16);
            memcpy(acc1->tls_md5_fingerprint, acc2->tls_md5_fingerprint, 16);
        }
        else
        {
            acc1->tls_md5_fingerprint = NULL;
        }
    }
    if (acc2->mask & ACC_TLS_NOCERTCHECK)
    {
        acc1->tls_nocertcheck = acc2->tls_nocertcheck;
    }
    if (acc2->mask & ACC_TLS_MIN_DH_PRIME_BITS)
    {
        acc1->tls_min_dh_prime_bits = acc2->tls_min_dh_prime_bits;
    }
    if (acc2->mask & ACC_TLS_PRIORITIES)
    {
        free(acc1->tls_priorities);
        acc1->tls_priorities = acc2->tls_priorities
            ? xstrdup(acc2->tls_priorities) : NULL;
    }
    if (acc2->mask & ACC_TLS_HOST_OVERRIDE)
    {
        free(acc1->tls_host_override);
        acc1->tls_host_override = acc2->tls_host_override
            ? xstrdup(acc2->tls_host_override) : NULL;
    }
    if (acc2->mask & ACC_DSN_RETURN)
    {
        free(acc1->dsn_return);
        acc1->dsn_return = acc2->dsn_return ? xstrdup(acc2->dsn_return) : NULL;
    }
    if (acc2->mask & ACC_DSN_NOTIFY)
    {
        free(acc1->dsn_notify);
        acc1->dsn_notify = acc2->dsn_notify ? xstrdup(acc2->dsn_notify) : NULL;
    }
    if (acc2->mask & ACC_REMOVE_BCC_HEADERS)
    {
        acc1->remove_bcc_headers = acc2->remove_bcc_headers;
    }
    if (acc2->mask & ACC_UNDISCLOSED_RECIPIENTS)
    {
        acc1->undisclosed_recipients = acc2->undisclosed_recipients;
    }
    if (acc2->mask & ACC_LOGFILE)
    {
        free(acc1->logfile);
        acc1->logfile = acc2->logfile ? xstrdup(acc2->logfile) : NULL;
    }
    if (acc2->mask & ACC_LOGFILE_TIME_FORMAT)
    {
        free(acc1->logfile_time_format);
        acc1->logfile_time_format =
            acc2->logfile_time_format ? xstrdup(acc2->logfile_time_format) : NULL;
    }
    if (acc2->mask & ACC_SYSLOG)
    {
        free(acc1->syslog);
        acc1->syslog = acc2->syslog ? xstrdup(acc2->syslog) : NULL;
    }
    if (acc2->mask & ACC_ALIASES)
    {
        free(acc1->aliases);
        acc1->aliases = acc2->aliases ? xstrdup(acc2->aliases) : NULL;
    }
    if (acc2->mask & ACC_PROXY_HOST)
    {
        free(acc1->proxy_host);
        acc1->proxy_host = acc2->proxy_host ? xstrdup(acc2->proxy_host) : NULL;
    }
    if (acc2->mask & ACC_PROXY_PORT)
    {
        acc1->proxy_port = acc2->proxy_port;
    }
    if (acc2->mask & ACC_SET_FROM_HEADER)
    {
        acc1->set_from_header = acc2->set_from_header;
    }
    if (acc2->mask & ACC_SET_DATE_HEADER)
    {
        acc1->set_date_header = acc2->set_date_header;
    }
    if (acc2->mask & ACC_SET_MSGID_HEADER)
    {
        acc1->set_msgid_header = acc2->set_msgid_header;
    }
    if (acc2->mask & ACC_SOURCE_IP)
    {
        free(acc1->source_ip);
        acc1->source_ip = acc2->source_ip ? xstrdup(acc2->source_ip) : NULL;
    }
    if (acc2->mask & ACC_SOCKET)
    {
        free(acc1->socketname);
        acc1->socketname = acc2->socketname ? xstrdup(acc2->socketname) : NULL;
    }
    acc1->mask |= acc2->mask;
}


/*
 * check_account()
 *
 * see conf.h
 */

int check_account(account_t *acc, int sendmail_mode, char **errstr)
{
    if (!acc->host && !acc->socketname)
    {
        *errstr = xasprintf(_("host not set"));
        return CONF_ESYNTAX;
    }
    if (acc->port == 0)
    {
        *errstr = xasprintf(_("port not set"));
        return CONF_ESYNTAX;
    }
    if (sendmail_mode && !acc->from)
    {
        *errstr = xasprintf(_("envelope-from address is missing"));
        return CONF_ESYNTAX;
    }
    if (acc->tls && !(acc->host || acc->tls_host_override))
    {
        *errstr = xasprintf(_("host not set"));
        return CONF_ESYNTAX;
    }
    if (acc->tls_key_file && !acc->tls_cert_file)
    {
        *errstr = xasprintf(_("tls_key_file requires tls_cert_file"));
        return CONF_ESYNTAX;
    }
    if (!acc->tls_key_file && acc->tls_cert_file)
    {
        *errstr = xasprintf(_("tls_cert_file requires tls_key_file"));
        return CONF_ESYNTAX;
    }
    if (acc->tls && !acc->tls_trust_file
            && !acc->tls_sha256_fingerprint && !acc->tls_sha1_fingerprint
            && !acc->tls_md5_fingerprint && !acc->tls_nocertcheck)
    {
        *errstr = xasprintf(
                _("tls requires either tls_trust_file (highly recommended) "
                    "or tls_fingerprint or a disabled tls_certcheck"));
        return CONF_ESYNTAX;
    }
    if (acc->tls_crl_file && !acc->tls_trust_file)
    {
        *errstr = xasprintf(_("tls_crl_file requires tls_trust_file"));
        return CONF_ESYNTAX;
    }

    return CONF_EOK;
}


/*
 * helper function for expand_from() and expand_domain()
 */

static int expand_from_or_domain(char **str, int expand_U, char **errstr)
{
    char* M = NULL;
    char* U = NULL;
    char* H = NULL;
    char* C = NULL;

    if (strstr(*str, "%M"))
    {
        char *sysconfdir;
        char *filename;
        FILE *f;
        char buf[256];
        size_t buflen;

        sysconfdir = get_sysconfdir();
        filename = get_filename(sysconfdir, "mailname");
        free(sysconfdir);
        if (!(f = fopen(filename, "r")))
        {
            *errstr = xasprintf(_("%s: %s"), filename, strerror(errno));
            free(filename);
            return CONF_ECANTOPEN;
        }
        buf[0] = '\0';
        if (!fgets(buf, sizeof(buf), f) && ferror(f))
        {
            *errstr = xasprintf(_("%s: %s"), filename, strerror(errno));
            free(filename);
            fclose(f);
            return CONF_EIO;
        }
        fclose(f);
        buflen = strlen(buf);
        if (buflen > 0 && buf[buflen - 1] == '\n')
        {
            buf[--buflen] = '\0';
        }
        if (buflen > 0 && buf[buflen - 1] == '\r')
        {
            buf[--buflen] = '\0';
        }
        if (buflen == 0)
        {
            *errstr = xasprintf(_("%s: %s"), filename, strerror(EINVAL));
            free(filename);
            return CONF_EPARSE;
        }
        free(filename);
        M = xstrdup(buf);
        sanitize_string(M);
    }
    if (expand_U && strstr(*str, "%U"))
    {
        U = get_username();
        sanitize_string(U);
    }
    if (strstr(*str, "%H") || strstr(*str, "%C"))
    {
        H = get_hostname();
        sanitize_string(H);
    }
    if (strstr(*str, "%C"))
    {
        C = net_get_canonical_hostname(H);
    }

    if (M)
    {
        *str = string_replace(*str, "%M", M);
        free(M);
    }
    if (U)
    {
        *str = string_replace(*str, "%U", U);
        free(U);
    }
    if (H)
    {
        *str = string_replace(*str, "%H", H);
        free(H);
    }
    if (C)
    {
        *str = string_replace(*str, "%C", C);
        free(C);
    }

    return CONF_EOK;
}


/*
 * expand_from()
 *
 * see conf.h
 */

int expand_from(char **from, char **errstr)
{
    return expand_from_or_domain(from, 1, errstr);
}


/*
 * expand_domain()
 *
 * see conf.h
 */

int expand_domain(char **domain, char **errstr)
{
    return expand_from_or_domain(domain, 0, errstr);
}


/*
 * some small helper functions
 */

int is_blank(int c)
{
    return (c == ' ' || c == '\t');
}

int skip_blanks(const char *s, int i)
{
    while (is_blank(s[i]))
    {
        i++;
    }
    return i;
}

int get_cmd_length(const char *s)
{
    int i = 0;

    while (s[i] != '\0' && !is_blank(s[i]))
    {
        i++;
    }
    return i;
}

/* get index of last non-blank character. -1 means there is none. */
int get_last_nonblank(const char *s)
{
    int i;

    i = (int)strlen(s) - 1;
    while (i >= 0 && is_blank(s[i]))
    {
        i--;
    }
    return i;
}

/* Return string without whitespace at beginning and end. If the string is
 * enclosed in double quotes, remove these, too. String is allocated. */
char *trim_string(const char *s)
{
    char *t;
    int i;
    int l;

    i = skip_blanks(s, 0);
    l = get_last_nonblank(s + i);
    if (l >= 1 && s[i] == '"' && s[i + l] == '"')
    {
        t = xmalloc(l * sizeof(char));
        strncpy(t, s + i + 1, l - 1);
        t[l - 1] = '\0';
    }
    else
    {
        t = xmalloc((l + 2) * sizeof(char));
        strncpy(t, s + i, l + 1);
        t[l + 1] = '\0';
    }
    return t;
}


/*
 * get_cmd()
 *
 * Split the given line into a command part (first word after
 * whitespace) and an argument part (the word after the command).
 * Whitespace is ignored.
 * If the line is empty or a comment, 'cmd' and 'arg' are unchanged.
 */

void get_cmd(const char* line, char **cmd, char **arg)
{
    char *p;
    int i;
    int l;

    /* Kill '\n'. Beware: sometimes the last line of a file has no '\n' */
    if ((p = strchr(line, '\n')))
    {
        *p = '\0';
        /* Kill '\r' (if CRLF line endings are used) */
        if (p > line && *(p - 1) == '\r')
        {
            *(p - 1) = '\0';
        }
    }

    i = skip_blanks(line, 0);

    if (line[i] == '#' || line[i] == '\0')
    {
        return;
    }

    l = get_cmd_length(line + i);
    *cmd = xmalloc((l + 1) * sizeof(char));
    strncpy(*cmd, line + i, (size_t)l);
    (*cmd)[l] = '\0';

    *arg = trim_string(line + i + l);
}


/*
 * read_account_list()
 *
 * Helper function for the account command: For every account name in the comma
 * separated string 's' search the account in 'acc_list' and add a pointer to
 * it to 'l'.
 */

int read_account_list(int line, list_t *acc_list, char *s, list_t *l,
        char **errstr)
{
    list_t *lp = l;
    char *comma;
    char *acc_id;
    account_t *acc;

    for (;;)
    {
        comma = strchr(s, ',');
        if (comma)
        {
            *comma = '\0';
        }
        acc_id = trim_string(s);
        if (*acc_id == '\0')
        {
            free(acc_id);
            *errstr = xasprintf(_("line %d: missing account name"), line);
            return CONF_ESYNTAX;
        }
        if (!(acc = find_account(acc_list, acc_id)))
        {
            *errstr = xasprintf(_("line %d: account %s not (yet) defined"),
                    line, acc_id);
            free(acc_id);
            return CONF_ESYNTAX;
        }
        free(acc_id);
        list_insert(lp, acc);
        lp = lp->next;
        if (comma)
        {
            s = comma + 1;
        }
        else
        {
            break;
        }
    }
    return CONF_EOK;
}


/*
 * read_conffile()
 *
 * Read configuration data from 'f' and store it in 'acc_list'.
 * The name of the configuration file, 'conffile', will be stored in the
 * "conffile" field of each account.
 * Unless an error code is returned, 'acc_list' will always be a new list;
 * it may be empty if no accounts were found.
 * If the file contains secrets (e.g. passwords), then the flag
 * 'conffile_contains_secrets' will be set to 1, else to 0.
 * Used error codes: CONF_EIO, CONF_EPARSE, CONF_ESYNTAX
 */

int read_conffile(const char *conffile, FILE *f, list_t **acc_list,
        int *conffile_contains_secrets, char **errstr)
{
    int e;
    list_t *p;
    account_t *defaults;
    account_t *acc;
    int line;
    char *cmd;
    char *arg;
    /* for the account command: */
    char *acc_id;
    char *t;
    list_t *copy_from;
    list_t *lp;

    *conffile_contains_secrets = 0;
    defaults = account_new(NULL, NULL);
    *acc_list = list_new();
    p = *acc_list;
    acc = NULL;
    e = CONF_EOK;
    cmd = NULL;
    arg = NULL;

    for (line = 1; ; line++)
    {
        /* read the next line */
        int line_comes_from_eval = 0;
        char linebuf[LINEBUFSIZE];
        size_t linelen;
        if (!fgets(linebuf, sizeof(linebuf), f))
        {
            if (ferror(f))
            {
                *errstr = xasprintf(_("input error"));
                e = CONF_EIO;
                break;
            }
            else /* EOF */
            {
                break;
            }
        }
        linelen = strlen(linebuf);
        if (linelen == LINEBUFSIZE - 1 && linebuf[linelen - 1] != '\n')
        {
            *errstr = xasprintf(_("line longer than %d characters"),
                    LINEBUFSIZE - 1);
            return CONF_EPARSE;
        }

        /* split line into command and argument */
        get_cmd(linebuf, &cmd, &arg);
        if (!cmd)
        {
            continue;
        }

        /* handle the special eval command first */
        if (strcmp(cmd, "eval") == 0)
        {
            if (*arg == '\0')
            {
                *errstr = xasprintf(_("line %d: command %s needs an argument"),
                        line, cmd);
                e = CONF_ESYNTAX;
                break;
            }
            /* replace the current cmd/arg with the output of the given command */
            char* evalbuf;
            if (eval(arg, &evalbuf, errstr) != 0)
            {
                e = CONF_EIO;
                break;
            }
            free(cmd);
            cmd = NULL;
            free(arg);
            arg = NULL;
            get_cmd(evalbuf, &cmd, &arg);
            if (!cmd)
            {
                continue;
            }
            line_comes_from_eval = 1;
        }

        /* compatibility with 1.2.x: if no account command is given, the first
         * account will be named "default". */
        if (!acc && strcmp(cmd, "account") != 0 && strcmp(cmd, "defaults") != 0)
        {
            acc = account_copy(defaults);
            acc->id = xstrdup("default");
            acc->conffile = xstrdup(conffile);
            acc->mask = 0LL;
            list_insert(p, acc);
            p = p->next;
        }

        /* handle commands */
        if (strcmp(cmd, "defaults") == 0)
        {
            if (*arg != '\0')
            {
                *errstr = xasprintf(
                        _("line %d: command %s does not take an argument"),
                        line, cmd);
                e = CONF_ESYNTAX;
                break;
            }
            acc = defaults;
        }
        else if (strcmp(cmd, "account") == 0)
        {
            copy_from = list_new();
            if ((t = strchr(arg, ':')))
            {
                if ((e = read_account_list(line, *acc_list, t + 1, copy_from,
                                errstr)) != CONF_EOK)
                {
                    list_free(copy_from);
                    break;
                }
                *t = '\0';
                acc_id = trim_string(arg);
            }
            else
            {
                acc_id = xstrdup(arg);
            }
            if (*acc_id == '\0')
            {
                list_free(copy_from);
                *errstr = xasprintf(_("line %d: missing account name"), line);
                e = CONF_ESYNTAX;
                free(acc_id);
                break;
            }
            if (strchr(acc_id, ':') || strchr(acc_id, ','))
            {
                list_free(copy_from);
                *errstr = xasprintf(_("line %d: an account name must not "
                            "contain colons or commas"), line);
                e = CONF_ESYNTAX;
                free(acc_id);
                break;
            }
            if (find_account(*acc_list, acc_id))
            {
                list_free(copy_from);
                *errstr = xasprintf(
                        _("line %d: account %s was already defined"),
                        line, acc_id);
                e = CONF_ESYNTAX;
                free(acc_id);
                break;
            }
            acc = account_copy(defaults);
            acc->id = acc_id;
            acc->conffile = xstrdup(conffile);
            acc->mask = 0LL;
            list_insert(p, acc);
            p = p->next;
            lp = copy_from;
            while (!list_is_empty(lp))
            {
                lp = lp->next;
                override_account(acc, lp->data);
            }
            list_free(copy_from);
        }
        else if (strcmp(cmd, "host") == 0)
        {
            acc->mask |= ACC_HOST;
            if (*arg == '\0')
            {
                *errstr = xasprintf(_("line %d: command %s needs an argument"),
                        line, cmd);
                e = CONF_ESYNTAX;
                break;
            }
            else
            {
                free(acc->host);
                acc->host = xstrdup(arg);
            }
        }
        else if (strcmp(cmd, "port") == 0)
        {
            acc->mask |= ACC_PORT;
            if (*arg == '\0')
            {
                /* We should go back to the default, which is to call
                 * get_default_port(), but we cannot since the account is not
                 * complete yet. So demand an argument here. */
                *errstr = xasprintf(_("line %d: command %s needs an argument"),
                        line, cmd);
                e = CONF_ESYNTAX;
                break;
            }
            else
            {
                acc->port = get_pos_int(arg);
                if (acc->port < 1 || acc->port > 65535)
                {
                    *errstr = xasprintf(
                            _("line %d: invalid argument %s for command %s"),
                            line, arg, cmd);
                    e = CONF_ESYNTAX;
                    break;
                }
            }
        }
        else if (strcmp(cmd, "timeout") == 0
                || strcmp(cmd, "connect_timeout") == 0)
        {
            /* For compatibility with versions <= 1.4.1, connect_timeout is
             * accepted as an alias for timeout, though it had a slightly
             * different meaning. */
            acc->mask |= ACC_TIMEOUT;
            if (*arg == '\0')
            {
                *errstr = xasprintf(_("line %d: command %s needs an argument"),
                        line, cmd);
                e = CONF_ESYNTAX;
                break;
            }
            else
            {
                if (is_off(arg))
                {
                    acc->timeout = 0;
                }
                else
                {
                    acc->timeout = get_pos_int(arg);
                    if (acc->timeout < 1)
                    {
                        *errstr = xasprintf(_("line %d: invalid argument %s "
                                    "for command %s"), line, arg, cmd);
                        e = CONF_ESYNTAX;
                        break;
                    }
                }
            }
        }
        else if (strcmp(cmd, "protocol") == 0)
        {
            acc->mask |= ACC_PROTOCOL;
            if (*arg == '\0')
            {
                *errstr = xasprintf(_("line %d: command %s needs an argument"),
                        line, cmd);
                e = CONF_ESYNTAX;
                break;
            }
            else
            {
                if (strcmp(arg, "smtp") == 0)
                {
                    acc->protocol = SMTP_PROTO_SMTP;
                }
                else if (strcmp(arg, "lmtp") == 0)
                {
                    acc->protocol = SMTP_PROTO_LMTP;
                }
                else
                {
                    *errstr = xasprintf(
                            _("line %d: invalid argument %s for command %s"),
                            line, arg, cmd);
                    e = CONF_ESYNTAX;
                    break;
                }
            }
        }
        else if (strcmp(cmd, "domain") == 0)
        {
            acc->mask |= ACC_DOMAIN;
            free(acc->domain);
            acc->domain = xstrdup(arg);
        }
        else if (strcmp(cmd, "from") == 0)
        {
            acc->mask |= ACC_FROM;
            free(acc->from);
            acc->from = xstrdup(arg);
        }
        else if (strcmp(cmd, "from_full_name") == 0)
        {
            acc->mask |= ACC_FROM_FULL_NAME;
            free(acc->from_full_name);
            acc->from_full_name = xstrdup(arg);
        }
        else if (strcmp(cmd, "allow_from_override") == 0)
        {
            acc->mask |= ACC_ALLOW_FROM_OVERRIDE;
            if (is_on(arg))
            {
                acc->allow_from_override = 1;
            }
            else if (is_off(arg))
            {
                acc->allow_from_override = 0;
            }
            else
            {
                *errstr = xasprintf(
                        _("line %d: invalid argument %s for command %s"),
                        line, arg, cmd);
                e = CONF_ESYNTAX;
                break;
            }
        }
        else if (strcmp(cmd, "auth") == 0)
        {
            acc->mask |= ACC_AUTH_MECH;
            free(acc->auth_mech);
            if (*arg == '\0' || is_on(arg))
            {
                acc->auth_mech = xstrdup("");
            }
            else if (is_off(arg))
            {
                acc->auth_mech = NULL;
            }
            else if (check_auth_arg(arg) == 0)
            {
                acc->auth_mech = xstrdup(arg);
            }
            else
            {
                acc->auth_mech = NULL;
                *errstr = xasprintf(
                        _("line %d: invalid argument %s for command %s"),
                        line, arg, cmd);
                e = CONF_ESYNTAX;
                break;
            }
        }
        else if (strcmp(cmd, "user") == 0)
        {
            acc->mask |= ACC_USERNAME;
            free(acc->username);
            acc->username = (*arg == '\0') ? NULL : xstrdup(arg);
        }
        else if (strcmp(cmd, "password") == 0)
        {
            if (!line_comes_from_eval)
                *conffile_contains_secrets = 1;
            acc->mask |= ACC_PASSWORD;
            free(acc->password);
            acc->password = (*arg == '\0') ? NULL : xstrdup(arg);
        }
        else if (strcmp(cmd, "passwordeval") == 0)
        {
            acc->mask |= ACC_PASSWORDEVAL;
            free(acc->passwordeval);
            acc->passwordeval = (*arg == '\0') ? NULL : xstrdup(arg);
        }
        else if (strcmp(cmd, "ntlmdomain") == 0)
        {
            acc->mask |= ACC_NTLMDOMAIN;
            free(acc->ntlmdomain);
            acc->ntlmdomain = (*arg == '\0') ? NULL : xstrdup(arg);
        }
        else if (strcmp(cmd, "tls") == 0)
        {
            acc->mask |= ACC_TLS;
            if (*arg == '\0' || is_on(arg))
            {
                acc->tls = 1;
            }
            else if (is_off(arg))
            {
                acc->tls = 0;
            }
            else
            {
                *errstr = xasprintf(
                        _("line %d: invalid argument %s for command %s"),
                        line, arg, cmd);
                e = CONF_ESYNTAX;
                break;
            }
        }
        else if (strcmp(cmd, "tls_starttls") == 0)
        {
            acc->mask |= ACC_TLS_NOSTARTTLS;
            if (*arg == '\0' || is_on(arg))
            {
                acc->tls_nostarttls = 0;
            }
            else if (is_off(arg))
            {
                acc->tls_nostarttls = 1;
            }
            else
            {
                *errstr = xasprintf(
                        _("line %d: invalid argument %s for command %s"),
                        line, arg, cmd);
                e = CONF_ESYNTAX;
                break;
            }
        }
        else if (strcmp(cmd, "tls_key_file") == 0)
        {
            acc->mask |= ACC_TLS_KEY_FILE;
            free(acc->tls_key_file);
            if (*arg == '\0')
            {
                acc->tls_key_file = NULL;
            }
            else
            {
                acc->tls_key_file = expand_tilde(arg);
            }
        }
        else if (strcmp(cmd, "tls_cert_file") == 0)
        {
            acc->mask |= ACC_TLS_CERT_FILE;
            free(acc->tls_cert_file);
            if (*arg == '\0')
            {
                acc->tls_cert_file = NULL;
            }
            else
            {
                acc->tls_cert_file = expand_tilde(arg);
            }
        }
        else if (strcmp(cmd, "tls_trust_file") == 0)
        {
            acc->mask |= ACC_TLS_TRUST_FILE;
            free(acc->tls_trust_file);
            if (*arg == '\0')
            {
                acc->tls_trust_file = NULL;
            }
            else
            {
                acc->tls_trust_file = expand_tilde(arg);
            }
        }
        else if (strcmp(cmd, "tls_crl_file") == 0)
        {
            acc->mask |= ACC_TLS_CRL_FILE;
            free(acc->tls_crl_file);
            if (*arg == '\0')
            {
                acc->tls_crl_file = NULL;
            }
            else
            {
                acc->tls_crl_file = expand_tilde(arg);
            }
        }
        else if (strcmp(cmd, "tls_fingerprint") == 0)
        {
            acc->mask |= ACC_TLS_FINGERPRINT;
            free(acc->tls_sha256_fingerprint);
            acc->tls_sha256_fingerprint = NULL;
            free(acc->tls_sha1_fingerprint);
            acc->tls_sha1_fingerprint = NULL;
            free(acc->tls_md5_fingerprint);
            acc->tls_md5_fingerprint = NULL;
            if (*arg != '\0')
            {
                if (strlen(arg) == 2 * 32 + 31)
                {
                    acc->tls_sha256_fingerprint = get_fingerprint(arg, 32);
                }
                else if (strlen(arg) == 2 * 20 + 19)
                {
                    acc->tls_sha1_fingerprint = get_fingerprint(arg, 20);
                }
                else if (strlen(arg) == 2 * 16 + 15)
                {
                    acc->tls_md5_fingerprint = get_fingerprint(arg, 16);
                }
                if (!acc->tls_sha256_fingerprint && !acc->tls_sha1_fingerprint
                        && !acc->tls_md5_fingerprint)
                {
                    *errstr = xasprintf(
                            _("line %d: invalid argument %s for command %s"),
                            line, arg, cmd);
                    e = CONF_ESYNTAX;
                    break;
                }
            }
        }
        else if (strcmp(cmd, "tls_certcheck") == 0)
        {
            acc->mask |= ACC_TLS_NOCERTCHECK;
            if (*arg == '\0' || is_on(arg))
            {
                acc->tls_nocertcheck = 0;
            }
            else if (is_off(arg))
            {
                acc->tls_nocertcheck = 1;
            }
            else
            {
                *errstr = xasprintf(
                        _("line %d: invalid argument %s for command %s"),
                        line, arg, cmd);
                e = CONF_ESYNTAX;
                break;
            }
        }
        else if (strcmp(cmd, "tls_min_dh_prime_bits") == 0)
        {
            acc->mask |= ACC_TLS_MIN_DH_PRIME_BITS;
            if (*arg == '\0')
            {
                acc->tls_min_dh_prime_bits = -1;
            }
            else
            {
                acc->tls_min_dh_prime_bits = get_pos_int(arg);
                if (acc->tls_min_dh_prime_bits < 1)
                {
                    *errstr = xasprintf(
                            _("line %d: invalid argument %s for command %s"),
                            line, arg, cmd);
                    e = CONF_ESYNTAX;
                    break;
                }
            }
        }
        else if (strcmp(cmd, "tls_priorities") == 0)
        {
            acc->mask |= ACC_TLS_PRIORITIES;
            free(acc->tls_priorities);
            if (*arg == '\0')
            {
                acc->tls_priorities = NULL;
            }
            else
            {
                acc->tls_priorities = xstrdup(arg);
            }
        }
        else if (strcmp(cmd, "tls_host_override") == 0)
        {
            acc->mask |= ACC_TLS_HOST_OVERRIDE;
            free(acc->tls_host_override);
            if (*arg == '\0')
            {
                acc->tls_host_override = NULL;
            }
            else
            {
                acc->tls_host_override = xstrdup(arg);
            }
        }
        else if (strcmp(cmd, "dsn_return") == 0)
        {
            acc->mask |= ACC_DSN_RETURN;
            free(acc->dsn_return);
            if (*arg == '\0')
            {
                *errstr = xasprintf(_("line %d: command %s needs an argument"),
                        line, cmd);
                e = CONF_ESYNTAX;
                break;
            }
            else
            {
                if (is_off(arg))
                {
                    acc->dsn_return = NULL;
                }
                else if (strcmp(arg, "headers") == 0)
                {
                    acc->dsn_return = xstrdup("HDRS");
                }
                else if (strcmp(arg, "full") == 0)
                {
                    acc->dsn_return = xstrdup("FULL");
                }
                else
                {
                    *errstr = xasprintf(
                            _("line %d: invalid argument %s for command %s"),
                            line, arg, cmd);
                    e = CONF_ESYNTAX;
                    break;
                }
            }
        }
        else if (strcmp(cmd, "dsn_notify") == 0)
        {
            acc->mask |= ACC_DSN_NOTIFY;
            free(acc->dsn_notify);
            if (*arg == '\0')
            {
                *errstr = xasprintf(_("line %d: command %s needs an argument"),
                        line, cmd);
                e = CONF_ESYNTAX;
                break;
            }
            else
            {
                if (is_off(arg))
                {
                    acc->dsn_notify = NULL;
                }
                else if (check_dsn_notify_arg(arg) == 0)
                {
                    acc->dsn_notify = xstrdup(arg);
                }
                else
                {
                    *errstr = xasprintf(
                            _("line %d: invalid argument %s for command %s"),
                            line, arg, cmd);
                    e = CONF_ESYNTAX;
                    break;
                }
            }
        }
        else if (strcmp(cmd, "logfile") == 0)
        {
            acc->mask |= ACC_LOGFILE;
            free(acc->logfile);
            if (*arg == '\0')
            {
                acc->logfile = NULL;
            }
            else
            {
                acc->logfile = expand_tilde(arg);
            }
        }
        else if (strcmp(cmd, "logfile_time_format") == 0)
        {
            acc->mask |= ACC_LOGFILE_TIME_FORMAT;
            free(acc->logfile_time_format);
            if (*arg == '\0')
            {
                acc->logfile_time_format = NULL;
            }
            else
            {
                acc->logfile_time_format = xstrdup(arg);
            }
        }
        else if (strcmp(cmd, "syslog") == 0)
        {
            acc->mask |= ACC_SYSLOG;
            free(acc->syslog);
            if (*arg == '\0' || is_on(arg))
            {
                acc->syslog = get_default_syslog_facility();
            }
            else if (is_off(arg))
            {
                acc->syslog = NULL;
            }
            else
            {
                if (check_syslog_arg(arg) != 0)
                {
                    *errstr = xasprintf(
                            _("line %d: invalid argument %s for command %s"),
                            line, arg, cmd);
                    e = CONF_ESYNTAX;
                    break;
                }
                acc->syslog = xstrdup(arg);
            }
        }
        else if (strcmp(cmd, "aliases") == 0)
        {
            acc->mask |= ACC_ALIASES;
            free(acc->aliases);
            if (*arg == '\0')
            {
                acc->aliases = NULL;
            }
            else
            {
                acc->aliases = expand_tilde(arg);
            }
        }
        else if (strcmp(cmd, "proxy_host") == 0)
        {
            acc->mask |= ACC_PROXY_HOST;
            free(acc->proxy_host);
            if (*arg == '\0')
            {
                acc->proxy_host = NULL;
            }
            else
            {
                acc->proxy_host = xstrdup(arg);
            }
        }
        else if (strcmp(cmd, "proxy_port") == 0)
        {
            acc->mask |= ACC_PROXY_PORT;
            if (*arg == '\0')
            {
                acc->proxy_port = 0;
            }
            else
            {
                acc->proxy_port = get_pos_int(arg);
                if (acc->proxy_port < 1 || acc->proxy_port > 65535)
                {
                    *errstr = xasprintf(
                            _("line %d: invalid argument %s for command %s"),
                            line, arg, cmd);
                    e = CONF_ESYNTAX;
                    break;
                }
            }
        }
        else if (strcmp(cmd, "set_from_header") == 0)
        {
            acc->mask |= ACC_SET_FROM_HEADER;
            if (*arg == '\0' || is_auto(arg))
            {
                acc->set_from_header = 2;
            }
            else if (is_on(arg))
            {
                acc->set_from_header = 1;
            }
            else if (is_off(arg))
            {
                acc->set_from_header = 0;
            }
            else
            {
                *errstr = xasprintf(
                        _("line %d: invalid argument %s for command %s"),
                        line, arg, cmd);
                e = CONF_ESYNTAX;
                break;
            }
        }
        else if (strcmp(cmd, "set_date_header") == 0)
        {
            acc->mask |= ACC_SET_DATE_HEADER;
            if (*arg == '\0' || is_auto(arg))
            {
                acc->set_date_header = 2;
            }
            else if (is_off(arg))
            {
                acc->set_date_header = 0;
            }
            else
            {
                *errstr = xasprintf(
                        _("line %d: invalid argument %s for command %s"),
                        line, arg, cmd);
                e = CONF_ESYNTAX;
                break;
            }
        }
        else if (strcmp(cmd, "set_msgid_header") == 0)
        {
            acc->mask |= ACC_SET_MSGID_HEADER;
            if (*arg == '\0' || is_auto(arg))
            {
                acc->set_msgid_header = 2;
            }
            else if (is_off(arg))
            {
                acc->set_msgid_header = 0;
            }
            else
            {
                *errstr = xasprintf(
                        _("line %d: invalid argument %s for command %s"),
                        line, arg, cmd);
                e = CONF_ESYNTAX;
                break;
            }
        }
        else if (strcmp(cmd, "remove_bcc_headers") == 0)
        {
            acc->mask |= ACC_REMOVE_BCC_HEADERS;
            if (*arg == '\0' || is_on(arg))
            {
                acc->remove_bcc_headers = 1;
            }
            else if (is_off(arg))
            {
                acc->remove_bcc_headers = 0;
            }
            else
            {
                *errstr = xasprintf(
                        _("line %d: invalid argument %s for command %s"),
                        line, arg, cmd);
                e = CONF_ESYNTAX;
                break;
            }
        }
        else if (strcmp(cmd, "undisclosed_recipients") == 0)
        {
            acc->mask |= ACC_UNDISCLOSED_RECIPIENTS;
            if (*arg == '\0' || is_on(arg))
            {
                acc->undisclosed_recipients = 1;
            }
            else if (is_off(arg))
            {
                acc->undisclosed_recipients = 0;
            }
            else
            {
                *errstr = xasprintf(
                        _("line %d: invalid argument %s for command %s"),
                        line, arg, cmd);
                e = CONF_ESYNTAX;
                break;
            }
        }
        else if (strcmp(cmd, "source_ip") == 0)
        {
            acc->mask |= ACC_SOURCE_IP;
            free(acc->source_ip);
            if (*arg == '\0')
            {
                acc->source_ip = NULL;
            }
            else
            {
                acc->source_ip = xstrdup(arg);
            }
        }
        else if (strcmp(cmd, "socket") == 0)
        {
            acc->mask |= ACC_SOCKET;
            free(acc->socketname);
            if (*arg == '\0')
            {
                acc->socketname = NULL;
            }
            else
            {
                acc->socketname = xstrdup(arg);
            }
        }
        else if (strcmp(cmd, "add_missing_from_header") == 0)
        {
            /* compatibility with < 1.8.8 */
            acc->mask |= ACC_SET_FROM_HEADER;
            if (*arg == '\0' || is_on(arg))
            {
                acc->set_from_header = 2;
            }
            else if (is_off(arg))
            {
                acc->set_from_header = 0;
            }
            else
            {
                *errstr = xasprintf(
                        _("line %d: invalid argument %s for command %s"),
                        line, arg, cmd);
                e = CONF_ESYNTAX;
                break;
            }
        }
        else if (strcmp(cmd, "add_missing_date_header") == 0)
        {
            /* compatibility with < 1.8.8 */
            acc->mask |= ACC_SET_DATE_HEADER;
            if (*arg == '\0' || is_on(arg))
            {
                acc->set_date_header = 2;
            }
            else if (is_off(arg))
            {
                acc->set_date_header = 0;
            }
            else
            {
                *errstr = xasprintf(
                        _("line %d: invalid argument %s for command %s"),
                        line, arg, cmd);
                e = CONF_ESYNTAX;
                break;
            }
        }
        else if (strcmp(cmd, "auto_from") == 0)
        {
            /* compatibility with <= 1.8.7 */
            acc->mask |= ACC_AUTO_FROM;
            if (*arg == '\0' || is_on(arg))
            {
                acc->auto_from = 1;
            }
            else if (is_off(arg))
            {
                acc->auto_from = 0;
            }
            else
            {
                *errstr = xasprintf(
                        _("line %d: invalid argument %s for command %s"),
                        line, arg, cmd);
                e = CONF_ESYNTAX;
                break;
            }
        }
        else if (strcmp(cmd, "maildomain") == 0)
        {
            /* compatibility with <= 1.8.7 */
            acc->mask |= ACC_MAILDOMAIN;
            free(acc->maildomain);
            acc->maildomain = xstrdup(arg);
        }
        else if (strcmp(cmd, "keepbcc") == 0)
        {
            /* compatibility with 1.4.x */
            acc->mask |= ACC_REMOVE_BCC_HEADERS;
            if (*arg == '\0' || is_on(arg))
            {
                acc->remove_bcc_headers = 0;
            }
            else if (is_off(arg))
            {
                acc->remove_bcc_headers = 1;
            }
            else
            {
                *errstr = xasprintf(
                        _("line %d: invalid argument %s for command %s"),
                        line, arg, cmd);
                e = CONF_ESYNTAX;
                break;
            }
        }
        else if (strcmp(cmd, "tls_nocertcheck") == 0)
        {
            /* compatibility with 1.2.x */
            acc->mask |= ACC_TLS_NOCERTCHECK;
            if (*arg != '\0')
            {
                *errstr = xasprintf(
                        _("line %d: command %s does not take an argument"),
                        line, cmd);
                e = CONF_ESYNTAX;
                break;
            }
            else
            {
                acc->tls_nocertcheck = 1;
            }
        }
        else if (strcmp(cmd, "tls_nostarttls") == 0)
        {
            /* compatibility with 1.2.x */
            acc->mask |= ACC_TLS_NOSTARTTLS;
            if (*arg != '\0')
            {
                *errstr = xasprintf(
                        _("line %d: command %s does not take an argument"),
                        line, cmd);
                e = CONF_ESYNTAX;
                break;
            }
            else
            {
                acc->tls_nostarttls = 1;
            }
        }
        else if (strcmp(cmd, "tls_force_sslv3") == 0)
        {
            /* compatibility with versions <= 1.4.32: silently ignore */
        }
        else
        {
            *errstr = xasprintf(_("line %d: unknown command %s"), line, cmd);
            e = CONF_ESYNTAX;
            break;
        }
        free(cmd);
        cmd = NULL;
        free(arg);
        arg = NULL;
    }
    free(cmd);
    free(arg);

    if (e != CONF_EOK)
    {
        list_xfree(*acc_list, account_free);
        *acc_list = NULL;
    }
    account_free(defaults);

    return e;
}


/*
 * get_conf()
 *
 * see conf.h
 */

int get_conf(const char *conffile, int securitycheck, list_t **acc_list,
        char **errstr)
{
    FILE *f;
    int conffile_contains_secrets;
    int e;

    if (!(f = fopen(conffile, "r")))
    {
        *errstr = xasprintf("%s", strerror(errno));
        return CONF_ECANTOPEN;
    }
    if ((e = read_conffile(conffile, f, acc_list, &conffile_contains_secrets,
                    errstr)) != CONF_EOK)
    {
        fclose(f);
        return e;
    }
    fclose(f);
    e = CONF_EOK;
    if (securitycheck && conffile_contains_secrets)
    {
        switch (check_secure(conffile))
        {
            case 1:
                *errstr = xasprintf(_("contains secrets and therefore "
                            "must be owned by you"));
                e = CONF_EINSECURE;
                break;

            case 2:
                *errstr = xasprintf(_("contains secrets and therefore "
                            "must have no more than user "
                            "read/write permissions"));
                e = CONF_EINSECURE;
                break;

            case 3:
                *errstr = xasprintf("%s", strerror(errno));
                e = CONF_EIO;
                break;
        }
    }

    return e;
}
