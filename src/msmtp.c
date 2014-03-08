/*
 * msmtp.c
 *
 * This file is part of msmtp, an SMTP client.
 *
 * Copyright (C) 2000, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011,
 * 2012, 2013, 2014
 * Martin Lambers <marlam@marlam.de>
 * Jay Soffian <jaysoffian@gmail.com> (Mac OS X keychain support)
 * Satoru SATOH <satoru.satoh@gmail.com> (GNOME keyring support)
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
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif
#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif
#ifdef ENABLE_NLS
# include <locale.h>
#endif
#ifdef HAVE_SYSLOG
# include <syslog.h>
#endif
#ifdef HAVE_GNOME_KEYRING
# include <gnome-keyring.h>
#endif
#ifdef HAVE_MACOSXKEYRING
# include <Security/Security.h>
#endif

#include "gettext.h"
#define _(string) gettext(string)
#define N_(string) gettext_noop(string)

#include "xalloc.h"
#include "conf.h"
#include "list.h"
#include "net.h"
#include "netrc.h"
#include "smtp.h"
#include "tools.h"
#include "aliases.h"
#ifdef HAVE_TLS
# include "tls.h"
#endif /* HAVE_TLS */

/* Default file names. */
#ifdef W32_NATIVE
#define SYSCONFFILE     "msmtprc.txt"
#define USERCONFFILE    "msmtprc.txt"
#define SYSNETRCFILE    "netrc.txt"
#define USERNETRCFILE   "netrc.txt"
#elif defined (DJGPP)
#define SYSCONFFILE     "msmtprc"
#define USERCONFFILE    "_msmtprc"
#define SYSNETRCFILE    "netrc"
#define USERNETRCFILE   "_netrc"
#else /* UNIX */
#define SYSCONFFILE     "msmtprc"
#define USERCONFFILE    ".msmtprc"
#define SYSNETRCFILE    "netrc"
#define USERNETRCFILE   ".netrc"
#endif

/* The name of this program */
const char *prgname;


/*
 * Die if memory allocation fails
 */

void xalloc_die(void)
{
    fprintf(stderr, _("%s: FATAL: %s\n"), prgname, strerror(ENOMEM));
    exit(EX_OSERR);
}


/*
 * Translate error codes from net.h, tls.h or smtp.h
 * to error codes from sysexits.h
 */

int exitcode_net(int net_error_code)
{
    switch (net_error_code)
    {
        case NET_EHOSTNOTFOUND:
            return EX_NOHOST;

        case NET_ESOCKET:
            return EX_OSERR;

        case NET_ECONNECT:
            return EX_TEMPFAIL;

        case NET_EIO:
            return EX_IOERR;

        case NET_ELIBFAILED:
        default:
            return EX_SOFTWARE;
    }
}

#ifdef HAVE_TLS
int exitcode_tls(int tls_error_code)
{
    switch (tls_error_code)
    {
        case TLS_EIO:
            return EX_IOERR;

        case TLS_EFILE:
            return EX_NOINPUT;

        case TLS_EHANDSHAKE:
            return EX_PROTOCOL;

        case TLS_ECERT:
            /* did not find anything better... */
            return EX_UNAVAILABLE;

        case TLS_ELIBFAILED:
        case TLS_ESEED:
        default:
            return EX_SOFTWARE;
    }
}
#endif /* HAVE_TLS */

int exitcode_smtp(int smtp_error_code)
{
    switch (smtp_error_code)
    {
        case SMTP_EIO:
            return EX_IOERR;

        case SMTP_EPROTO:
            return EX_PROTOCOL;

        case SMTP_EINVAL:
            return EX_DATAERR;

        case SMTP_EAUTHFAIL:
            return EX_NOPERM;

        case SMTP_EINSECURE:
        case SMTP_EUNAVAIL:
            return EX_UNAVAILABLE;

        case SMTP_ELIBFAILED:
        default:
            return EX_SOFTWARE;
    }
}


/*
 * Return the name of a sysexits.h exitcode
 */
const char *exitcode_to_string(int exitcode)
{
    switch (exitcode)
    {
        case EX_OK:
            return "EX_OK";

        case EX_USAGE:
            return "EX_USAGE";

        case EX_DATAERR:
            return "EX_DATAERR";

        case EX_NOINPUT:
            return "EX_NOINPUT";

        case EX_NOUSER:
            return "EX_NOUSER";

        case EX_NOHOST:
            return "EX_NOHOST";

        case EX_UNAVAILABLE:
            return "EX_UNAVAILABLE";

        case EX_SOFTWARE:
            return "EX_SOFTWARE";

        case EX_OSERR:
            return "EX_OSERR";

        case EX_OSFILE:
            return "EX_OSFILE";

        case EX_CANTCREAT:
            return "EX_CANTCREAT";

        case EX_IOERR:
            return "EX_IOERR";

        case EX_TEMPFAIL:
            return "EX_TEMPFAIL";

        case EX_PROTOCOL:
            return "EX_PROTOCOL";

        case EX_NOPERM:
            return "EX_NOPERM";

        case EX_CONFIG:
            return "EX_CONFIG";

        default:
            return "BUG:UNKNOWN";
    }
}


/*
 * msmtp_sanitize_string()
 *
 * Replaces all control characters in the string with a question mark
 */

char *msmtp_sanitize_string(char *str)
{
    char *p = str;

    while (*p != '\0')
    {
        if (iscntrl((unsigned char)*p))
        {
            *p = '?';
        }
        p++;
    }

    return str;
}


/*
 * msmtp_password_callback()
 *
 * This function will be called by smtp_auth() to get a password if none was
 * given. It tries to read a password from .netrc. If that fails, it tries to
 * get it from the system's keychain (if available). If that fails, it tries to
 * read a password from /dev/tty (not stdin) with getpass().
 * It must return NULL on failure or a password in an allocated buffer.
 */

char *msmtp_password_callback(const char *hostname, const char *user)
{
    char *netrc_directory;
    char *netrc_filename;
    netrc_entry *netrc_hostlist;
    netrc_entry *netrc_host;
#ifdef HAVE_GNOME_KEYRING
    const char *protocol = "smtp";
    GList *found_list = NULL;
    GnomeKeyringNetworkPasswordData *found;
#endif
#ifdef HAVE_MACOSXKEYRING
    void *password_data;
    UInt32 password_length;
    OSStatus status;
#endif
    FILE *tty;
    int getpass_uses_tty;
    char *prompt;
    char *gpw;
    char *password = NULL;

    netrc_directory = get_homedir();
    netrc_filename = get_filename(netrc_directory, USERNETRCFILE);
    free(netrc_directory);
    if ((netrc_hostlist = parse_netrc(netrc_filename)))
    {
        if ((netrc_host = search_netrc(netrc_hostlist, hostname, user)))
        {
            password = xstrdup(netrc_host->password);
        }
        free_netrc_entry_list(netrc_hostlist);
    }
    free(netrc_filename);

    if (!password)
    {
        netrc_directory = get_sysconfdir();
        netrc_filename = get_filename(netrc_directory, SYSNETRCFILE);
        free(netrc_directory);
        if ((netrc_hostlist = parse_netrc(netrc_filename)))
        {
            if ((netrc_host = search_netrc(netrc_hostlist, hostname, user)))
            {
                password = xstrdup(netrc_host->password);
            }
            free_netrc_entry_list(netrc_hostlist);
        }
        free(netrc_filename);
    }

#ifdef HAVE_GNOME_KEYRING
    if (!password)
    {
        g_set_application_name(PACKAGE);
        if (gnome_keyring_find_network_password_sync(
                    user,     /* user */
                    NULL,     /* domain */
                    hostname, /* server */
                    NULL,     /* object */
                    protocol, /* protocol */
                    NULL,     /* authtype */
                    0,        /* port */
                    &found_list) == GNOME_KEYRING_RESULT_OK)
        {
            found = (GnomeKeyringNetworkPasswordData *) found_list->data;
            if (found->password)
                password = g_strdup(found->password);
        }
        gnome_keyring_network_password_list_free(found_list);
    }
#endif /* HAVE_GNOME_KEYRING */

#ifdef HAVE_MACOSXKEYRING
    if (!password)
    {
        if (SecKeychainFindInternetPassword(
                    NULL,
                    strlen(hostname), hostname,
                    0, NULL,
                    strlen(user), user,
                    0, (char *)NULL,
                    0,
                    kSecProtocolTypeSMTP,
                    kSecAuthenticationTypeDefault,
                    &password_length, &password_data,
                    NULL) == noErr)
        {
            password = xmalloc((password_length + 1) * sizeof(char));
            strncpy(password, password_data, (size_t)password_length);
            password[password_length] = '\0';
            SecKeychainItemFreeContent(NULL, password_data);
        }
    }
#endif /* HAVE_MACOSXKEYRING */

    /* Do not let getpass() read from stdin, because we read the mail from
     * there. DJGPP's getpass() always reads from stdin. On W32, gnulib's
     * getpass() uses _getch(), which always reads from the 'console' and not
     * stdin. On other systems, we test if /dev/tty can be opened before calling
     * getpass(). */
    if (!password)
    {
#ifdef DJGPP
        getpass_uses_tty = 0;
#elif defined W32_NATIVE || defined __CYGWIN__
        getpass_uses_tty = 1;
#else
        getpass_uses_tty = 0;
        if ((tty = fopen("/dev/tty", "w+")))
        {
            getpass_uses_tty = 1;
            fclose(tty);
        }
#endif
        if (getpass_uses_tty)
        {
            prompt = xasprintf(_("password for %s at %s: "), user, hostname);
            gpw = getpass(prompt);
            free(prompt);
            if (gpw)
            {
                password = xstrdup(gpw);
            }
        }
    }

    return password;
}


/*
 * msmtp_print_tls_cert_info()
 *
 * Prints information about a TLS certificate.
 */

#ifdef HAVE_TLS
/* Convert the given time into a string. */
void msmtp_time_to_string(time_t *t, char *buf, size_t bufsize)
{
#ifdef ENABLE_NLS
    (void)strftime(buf, bufsize, "%c", localtime(t));
#else
    char *p;

    (void)snprintf(buf, bufsize, "%s", ctime(t));
    if ((p = strchr(buf, '\n')))
    {
        *p = '\0';
    }
#endif
}
#endif

void msmtp_fingerprint_string(char *s, unsigned char *fingerprint, size_t len)
{
    const char *hex = "0123456789ABCDEF";
    size_t i;

    for (i = 0; i < len; i++)
    {
        s[3 * i + 0] = hex[(fingerprint[i] & 0xf0) >> 4];
        s[3 * i + 1] = hex[fingerprint[i] & 0x0f];
        s[3 * i + 2] = (i < len - 1 ? ':' : '\0');
    }
}

#ifdef HAVE_TLS
void msmtp_print_tls_cert_info(tls_cert_info_t *tci)
{
    const char *info_fieldname[6] = { N_("Common Name"), N_("Organization"),
        N_("Organizational unit"), N_("Locality"), N_("State or Province"),
        N_("Country") };
    char sha1_fingerprint_string[60];
    char md5_fingerprint_string[48];
    char timebuf[128];          /* should be long enough for every locale */
    char *tmp;
    int i;

    msmtp_fingerprint_string(sha1_fingerprint_string,
            tci->sha1_fingerprint, 20);
    msmtp_fingerprint_string(md5_fingerprint_string,
            tci->md5_fingerprint, 16);

    printf(_("TLS certificate information:\n"));
    printf("    %s:\n", _("Owner"));
    for (i = 0; i < 6; i++)
    {
        if (tci->owner_info[i])
        {
            tmp = xstrdup(tci->owner_info[i]);
            printf("        %s: %s\n", gettext(info_fieldname[i]),
                    msmtp_sanitize_string(tmp));
            free(tmp);
        }
    }
    printf("    %s:\n", _("Issuer"));
    for (i = 0; i < 6; i++)
    {
        if (tci->issuer_info[i])
        {
            tmp = xstrdup(tci->issuer_info[i]);
            printf("        %s: %s\n", gettext(info_fieldname[i]),
                    msmtp_sanitize_string(tmp));
            free(tmp);
        }
    }
    printf("    %s:\n", _("Validity"));
    msmtp_time_to_string(&tci->activation_time, timebuf, sizeof(timebuf));
    printf("        %s: %s\n", _("Activation time"), timebuf);
    msmtp_time_to_string(&tci->expiration_time, timebuf, sizeof(timebuf));
    printf("        %s: %s\n", _("Expiration time"), timebuf);
    printf("    %s:\n", _("Fingerprints"));
    printf("        SHA1: %s\n", sha1_fingerprint_string);
    printf("        MD5:  %s\n", md5_fingerprint_string);
}
#endif


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
 * If an error occured, '*errstr' points to an allocated string that describes
 * the error or is NULL, and '*msg' may contain the offending message from the
 * SMTP server (or be NULL).
 */

int msmtp_rmqs(account_t *acc, int debug, const char *rmqs_argument,
        list_t **msg, char **errstr)
{
    smtp_server_t srv;
    int e;
#ifdef HAVE_TLS
    tls_cert_info_t *tci = NULL;
#endif /* HAVE_TLS */

    *errstr = NULL;
    *msg = NULL;

    /* create a new smtp_server_t */
    srv = smtp_new(debug ? stdout : NULL, acc->protocol);

    /* connect */
    if ((e = smtp_connect(&srv, acc->host, acc->port, acc->timeout,
                    NULL, NULL, errstr)) != NET_EOK)
    {
        return exitcode_net(e);
    }

    /* prepare tls */
#ifdef HAVE_TLS
    if (acc->tls)
    {
        if ((e = smtp_tls_init(&srv, acc->tls_key_file, acc->tls_cert_file,
                        acc->tls_trust_file, acc->tls_crl_file,
                        acc->tls_sha1_fingerprint, acc->tls_md5_fingerprint,
                        acc->tls_force_sslv3, acc->tls_min_dh_prime_bits,
                        acc->tls_priorities, errstr)) != TLS_EOK)
        {
            return exitcode_tls(e);
        }
    }
#endif /* HAVE_TLS */

    /* start tls for smtps servers */
#ifdef HAVE_TLS
    if (acc->tls && acc->tls_nostarttls)
    {
        if (debug)
        {
            tci = tls_cert_info_new();
        }
        if ((e = smtp_tls(&srv, acc->host, acc->tls_nocertcheck, tci, errstr))
                != TLS_EOK)
        {
            if (debug)
            {
                tls_cert_info_free(tci);
            }
            msmtp_endsession(&srv, 0);
            return exitcode_tls(e);
        }
        if (debug)
        {
            msmtp_print_tls_cert_info(tci);
            tls_cert_info_free(tci);
        }
    }
#endif /* HAVE_TLS */

    /* get greeting */
    if ((e = smtp_get_greeting(&srv, msg, NULL, errstr)) != SMTP_EOK)
    {
        msmtp_endsession(&srv, 0);
        return exitcode_smtp(e);
    }

    /* initialize session */
    if ((e = smtp_init(&srv, acc->domain, msg, errstr)) != SMTP_EOK)
    {
        msmtp_endsession(&srv, 0);
        return exitcode_smtp(e);
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
            return exitcode_smtp(e);
        }
        if (debug)
        {
            tci = tls_cert_info_new();
        }
        if ((e = smtp_tls(&srv, acc->host, acc->tls_nocertcheck, tci, errstr))
                != TLS_EOK)
        {
            if (debug)
            {
                tls_cert_info_free(tci);
            }
            msmtp_endsession(&srv, 0);
            return exitcode_tls(e);
        }
        if (debug)
        {
            msmtp_print_tls_cert_info(tci);
            tls_cert_info_free(tci);
        }
        /* initialize again */
        if ((e = smtp_init(&srv, acc->domain, msg, errstr)) != SMTP_EOK)
        {
            msmtp_endsession(&srv, 0);
            return exitcode_smtp(e);
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
        if ((e = smtp_auth(&srv, acc->host, acc->username, acc->password,
                        acc->ntlmdomain, acc->auth_mech,
                        msmtp_password_callback, msg, errstr))
                != SMTP_EOK)
        {
            msmtp_endsession(&srv, 0);
            return exitcode_smtp(e);
        }
    }

    /* send the ETRN request */
    if ((e = smtp_etrn(&srv, rmqs_argument, msg, errstr)) != SMTP_EOK)
    {
        msmtp_endsession(&srv, 0);
        return exitcode_smtp(e);
    }

    /* end session */
    msmtp_endsession(&srv, 1);
    return EX_OK;
}


/*
 * msmtp_serverinfo()
 *
 * Prints information about the SMTP server specified in the account 'acc'.
 * If an error occured, '*errstr' points to an allocated string that describes
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
    tls_cert_info_t *tci = NULL;
#endif /* HAVE_TLS */

    *errstr = NULL;
    *msg = NULL;

    /* create a new smtp_server_t */
    srv = smtp_new(debug ? stdout : NULL, acc->protocol);

    /* connect */
    if ((e = smtp_connect(&srv, acc->host, acc->port, acc->timeout,
                    &server_canonical_name, &server_address, errstr))
            != NET_EOK)
    {
        e = exitcode_net(e);
        goto error_exit;
    }

    /* prepare tls */
#ifdef HAVE_TLS
    if (acc->tls)
    {
        tci = tls_cert_info_new();
        if ((e = smtp_tls_init(&srv, acc->tls_key_file, acc->tls_cert_file,
                        acc->tls_trust_file, acc->tls_crl_file,
                        acc->tls_sha1_fingerprint, acc->tls_md5_fingerprint,
                        acc->tls_force_sslv3, acc->tls_min_dh_prime_bits,
                        acc->tls_priorities, errstr)) != TLS_EOK)
        {
            e = exitcode_tls(e);
            goto error_exit;
        }
    }
#endif /* HAVE_TLS */

    /* start tls for smtps servers */
#ifdef HAVE_TLS
    if (acc->tls && acc->tls_nostarttls)
    {
        if ((e = smtp_tls(&srv, acc->host, acc->tls_nocertcheck, tci, errstr))
                != TLS_EOK)
        {
            msmtp_endsession(&srv, 0);
            e = exitcode_tls(e);
            goto error_exit;
        }
    }
#endif /* HAVE_TLS */

    /* get greeting */
    if ((e = smtp_get_greeting(&srv, msg, &server_greeting,
                    errstr)) != SMTP_EOK)
    {
        msmtp_endsession(&srv, 0);
        e = exitcode_smtp(e);
        goto error_exit;
    }

    /* initialize session */
    if ((e = smtp_init(&srv, acc->domain, msg, errstr)) != SMTP_EOK)
    {
        msmtp_endsession(&srv, 0);
        e = exitcode_smtp(e);
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
            e = exitcode_smtp(e);
            goto error_exit;
        }
        if ((e = smtp_tls(&srv, acc->host, acc->tls_nocertcheck, tci, errstr))
                != TLS_EOK)
        {
            msmtp_endsession(&srv, 0);
            e = exitcode_tls(e);
            goto error_exit;
        }
        /* initialize again */
        if ((e = smtp_init(&srv, acc->domain, msg, errstr)) != SMTP_EOK)
        {
            msmtp_endsession(&srv, 0);
            e = exitcode_smtp(e);
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
                acc->host, server_canonical_name, server_address, acc->port);
    }
    else if (server_canonical_name)
    {
        printf(_("%s server at %s (%s), port %d:\n"),
                acc->protocol == SMTP_PROTO_SMTP ? "SMTP" : "LMTP",
                acc->host, server_canonical_name, acc->port);
    }
    else if (server_address)
    {
        printf(_("%s server at %s ([%s]), port %d:\n"),
                acc->protocol == SMTP_PROTO_SMTP ? "SMTP" : "LMTP",
                acc->host, server_address, acc->port);
    }
    else
    {
        printf(_("%s server at %s, port %d:\n"),
                acc->protocol == SMTP_PROTO_SMTP ? "SMTP" : "LMTP",
                acc->host, acc->port);
    }
    if (*server_greeting != '\0')
    {
        printf("    %s\n", msmtp_sanitize_string(server_greeting));
    }
#ifdef HAVE_TLS
    if (acc->tls)
    {
        msmtp_print_tls_cert_info(tci);
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
            if (srv.cap.flags & SMTP_CAP_AUTH_PLAIN)
            {
                printf("PLAIN ");
            }
            if (srv.cap.flags & SMTP_CAP_AUTH_SCRAM_SHA_1)
            {
                printf("SCRAM-SHA-1 ");
            }
            if (srv.cap.flags & SMTP_CAP_AUTH_CRAM_MD5)
            {
                printf("CRAM-MD5 ");
            }
            if (srv.cap.flags & SMTP_CAP_AUTH_GSSAPI)
            {
                printf("GSSAPI ");
            }
            if (srv.cap.flags & SMTP_CAP_AUTH_EXTERNAL)
            {
                printf("EXTERNAL ");
            }
            if (srv.cap.flags & SMTP_CAP_AUTH_DIGEST_MD5)
            {
                printf("DIGEST-MD5 ");
            }
            if (srv.cap.flags & SMTP_CAP_AUTH_LOGIN)
            {
                printf("LOGIN ");
            }
            if (srv.cap.flags & SMTP_CAP_AUTH_NTLM)
            {
                printf("NTLM ");
            }
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
        tls_cert_info_free(tci);
    }
#endif /* HAVE_TLS */
    free(server_greeting);
    return e;
}


/*
 * msmtp_read_addresses()
 *
 * Copies the headers of the mail from 'mailf' to a temporary file 'tmpfile',
 * including the blank line that separates the header from the body of the mail.
 *
 * If 'recipients' is not NULL: extracts all recipients from the To, Cc, and Bcc
 * headers and adds them to 'recipients'. If Resent-* headers are present, all
 * recipients from the Resent-To, Resent-Cc, Resent-Bcc headers in the first
 * block of Resent- headers are extracted instead.
 *
 * If 'from' is not NULL: extracts the address from the From header and stores
 * it in an allocated string. A pointer to this string is stored in 'from'.
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
#define STATE_FROM1                     3       /* we saw "^F" */
#define STATE_FROM2                     4       /* we saw "^Fr" */
#define STATE_FROM3                     5       /* we saw "^Fro" */
#define STATE_TO                        6       /* we saw "^T" */
#define STATE_CC                        7       /* we saw "^C" */
#define STATE_BCC1                      8       /* we saw "^B" */
#define STATE_BCC2                      9       /* we saw "^Bc" */
#define STATE_ADDRHDR_ALMOST            10      /* we saw "^To", "^Cc"
                                                   or "^Bcc" */
#define STATE_RESENT                    11      /* we saw part of "^Resent-" */
#define STATE_ADDRHDR_DEFAULT           12      /* in_rcpt_hdr and in_rcpt
                                                   state our position */
#define STATE_ADDRHDR_DQUOTE            13      /* duoble quotes */
#define STATE_ADDRHDR_BRACKETS_START    14      /* entering <...> */
#define STATE_ADDRHDR_IN_BRACKETS       15      /* an address inside <> */
#define STATE_ADDRHDR_PARENTH_START     16      /* entering (...) */
#define STATE_ADDRHDR_IN_PARENTH        17      /* a comment inside () */
#define STATE_ADDRHDR_IN_ADDRESS        18      /* a bare address */
#define STATE_ADDRHDR_BACKQUOTE         19      /* we saw a '\\' */
#define STATE_HEADERS_END               20      /* we saw "^$", the blank line
                                                   between headers and body */

int msmtp_read_addresses(FILE *mailf, FILE *tmpfile,
        list_t *recipients, char **from, char **errstr)
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
                    if (from && from_hdr < 0 && (c == 'f' || c == 'F'))
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

                case STATE_LINESTART_AFTER_ADDRHDR:
                    resent_index = -1;
                    if (c != ' ' && c != '\t' && current_recipient)
                        finish_current_recipient = 1;
                    if (c == ' ' || c == '\t')
                        state = folded_rcpthdr_savestate;
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

        if (tmpfile && c != EOF && fputc(c, tmpfile) == EOF)
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
        }
    }

    if (ferror(mailf))
    {
        *errstr = xasprintf(_("input error while reading the mail"));
        goto error_exit;
    }

    return EX_OK;

error_exit:
    if (recipients)
    {
        list_xfree(normal_recipients_list, free);
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
 * If an error occured, '*errstr' points to an allocated string that describes
 * the error or is NULL, and '*msg' may contain the offending message from the
 * SMTP server (or be NULL).
 * In case of success, 'mailsize' contains the number of bytes of the mail
 * transferred to the SMTP server. In case of failure, its contents are
 * undefined.
 */

int msmtp_sendmail(account_t *acc, list_t *recipients,
        FILE *f, FILE *tmpfile, int debug, long *mailsize,
        list_t **lmtp_errstrs, list_t **lmtp_error_msgs,
        list_t **msg, char **errstr)
{
    smtp_server_t srv;
    int e;
#ifdef HAVE_TLS
    tls_cert_info_t *tci = NULL;
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
        if ((e = smtp_tls_init(&srv, acc->tls_key_file, acc->tls_cert_file,
                        acc->tls_trust_file, acc->tls_crl_file,
                        acc->tls_sha1_fingerprint, acc->tls_md5_fingerprint,
                        acc->tls_force_sslv3, acc->tls_min_dh_prime_bits,
                        acc->tls_priorities, errstr)) != TLS_EOK)
        {
            e = exitcode_tls(e);
            return e;
        }
    }
#endif /* HAVE_TLS */

    /* connect */
    if ((e = smtp_connect(&srv, acc->host, acc->port, acc->timeout,
                    NULL, NULL, errstr)) != NET_EOK)
    {
        e = exitcode_net(e);
        return e;
    }

    /* start tls for smtps servers */
#ifdef HAVE_TLS
    if (acc->tls && acc->tls_nostarttls)
    {
        if (debug)
        {
            tci = tls_cert_info_new();
        }
        if ((e = smtp_tls(&srv, acc->host, acc->tls_nocertcheck, tci, errstr))
                != TLS_EOK)
        {
            if (debug)
            {
                tls_cert_info_free(tci);
            }
            msmtp_endsession(&srv, 0);
            e = exitcode_tls(e);
            return e;
        }
        if (debug)
        {
            msmtp_print_tls_cert_info(tci);
            tls_cert_info_free(tci);
        }
    }
#endif /* HAVE_TLS */

    /* get greeting */
    if ((e = smtp_get_greeting(&srv, msg, NULL, errstr)) != SMTP_EOK)
    {
        msmtp_endsession(&srv, 0);
        e = exitcode_smtp(e);
        return e;
    }

    /* initialize session */
    if ((e = smtp_init(&srv, acc->domain, msg, errstr)) != SMTP_EOK)
    {
        msmtp_endsession(&srv, 0);
        e = exitcode_smtp(e);
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
            e = exitcode_smtp(e);
            return e;
        }
        if (debug)
        {
            tci = tls_cert_info_new();
        }
        if ((e = smtp_tls(&srv, acc->host, acc->tls_nocertcheck, tci, errstr))
                != TLS_EOK)
        {
            if (debug)
            {
                tls_cert_info_free(tci);
            }
            msmtp_endsession(&srv, 0);
            e = exitcode_tls(e);
            return e;
        }
        if (debug)
        {
            msmtp_print_tls_cert_info(tci);
            tls_cert_info_free(tci);
        }
        /* initialize again */
        if ((e = smtp_init(&srv, acc->domain, msg, errstr)) != SMTP_EOK)
        {
            msmtp_endsession(&srv, 0);
            e = exitcode_smtp(e);
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
        if ((e = smtp_auth(&srv, acc->host, acc->username, acc->password,
                        acc->ntlmdomain, acc->auth_mech,
                        msmtp_password_callback, msg, errstr))
                != SMTP_EOK)
        {
            msmtp_endsession(&srv, 0);
            e = exitcode_smtp(e);
            return e;
        }
    }

    /* send the envelope */
    if ((e = smtp_send_envelope(&srv, acc->from, recipients,
                    acc->dsn_notify, acc->dsn_return, msg, errstr)) != SMTP_EOK)
    {
        msmtp_endsession(&srv, 0);
        e = exitcode_smtp(e);
        return e;
    }
    /* send header and body */
    *mailsize = 0;
    if (tmpfile)
    {
        /* first the headers from the temp file */
        if ((e = smtp_send_mail(&srv, tmpfile, acc->keepbcc, mailsize, errstr))
                != SMTP_EOK)
        {
            msmtp_endsession(&srv, 0);
            e = exitcode_smtp(e);
            return e;
        }
        /* then the body from the original file */
        if ((e = smtp_send_mail(&srv, f, 1, mailsize, errstr)) != SMTP_EOK)
        {
            msmtp_endsession(&srv, 0);
            e = exitcode_smtp(e);
            return e;
        }
    }
    else
    {
        if ((e = smtp_send_mail(&srv, f, acc->keepbcc, mailsize, errstr))
                != SMTP_EOK)
        {
            msmtp_endsession(&srv, 0);
            e = exitcode_smtp(e);
            return e;
        }
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
        e = exitcode_smtp(e);
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
            p = msmtp_sanitize_string(l->data);
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
    /* "host=%s " */
    s += 5 + strlen(acc->host) + 1;
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
    n = snprintf(p, s, "host=%s tls=%s auth=%s ",
            acc->host, (acc->tls ? "on" : "off"),
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
        n = snprintf(p, s, "errormsg='%s' ", msmtp_sanitize_string(errstr));
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
 * Append a log entry to 'acc->logfile' with the following information:
 * - date/time
 * - the log line as delivered by msmtp_get_log_info
 */

void msmtp_log_to_file(const char *logfile, const char *loginfo)
{
    FILE *f;
    time_t t;
    struct tm *tm;
    char *failure_reason;
    char time_str[64];
    int e;

    /* get time */
    if ((t = time(NULL)) < 0)
    {
        failure_reason = xasprintf(_("cannot get system time: %s"),
                strerror(errno));
        goto log_failure;
    }
    if (!(tm = localtime(&t)))
    {
        failure_reason = xstrdup(_("cannot convert UTC time to local time"));
        goto log_failure;
    }
    (void)strftime(time_str, sizeof(time_str), "%b %d %H:%M:%S", tm);

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
    char *homedir;
    char *userconffile;

    printf(_("%s version %s\n"), PACKAGE_NAME, VERSION);
    printf(_("Platform: %s\n"), PLATFORM);
    /* TLS/SSL support */
    printf(_("TLS/SSL library: %s\n"),
#ifdef HAVE_LIBGNUTLS
            "GnuTLS"
#elif defined (HAVE_LIBSSL)
            "OpenSSL"
#else
            _("none")
#endif
          );
    /* Authentication support */
    printf(_("Authentication library: %s\n"
                "Supported authentication methods:\n"),
#ifdef HAVE_LIBGSASL
            "GNU SASL"
#else
            _("built-in")
#endif /* HAVE_LIBGSASL */
          );
    if (smtp_client_supports_authmech("PLAIN"))
    {
        printf("plain ");
    }
    if (smtp_client_supports_authmech("SCRAM-SHA-1"))
    {
        printf("scram-sha-1 ");
    }
    if (smtp_client_supports_authmech("CRAM-MD5"))
    {
        printf("cram-md5 ");
    }
    if (smtp_client_supports_authmech("GSSAPI"))
    {
        printf("gssapi ");
    }
    if (smtp_client_supports_authmech("EXTERNAL"))
    {
        printf("external ");
    }
    if (smtp_client_supports_authmech("DIGEST-MD5"))
    {
        printf("digest-md5 ");
    }
    if (smtp_client_supports_authmech("LOGIN"))
    {
        printf("login ");
    }
    if (smtp_client_supports_authmech("NTLM"))
    {
        printf("ntlm ");
    }
    printf("\n");
    /* Internationalized Domain Names support */
    printf(_("IDN support: "));
#ifdef HAVE_LIBIDN
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
#if !defined HAVE_GNOME_KEYRING && !defined HAVE_MACOSXKEYRING
    printf(_("none"));
#else
# ifdef HAVE_GNOME_KEYRING
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
    homedir = get_homedir();
    userconffile = get_filename(homedir, USERCONFFILE);
    printf(_("User configuration file name: %s\n"), userconffile);
    free(userconffile);
    free(homedir);
    printf("\n");
    printf(_("Copyright (C) 2014 Martin Lambers and others.\n"
                "This is free software.  You may redistribute copies of "
                    "it under the terms of\n"
                "the GNU General Public License "
                    "<http://www.gnu.org/licenses/gpl.html>.\n"
                "There is NO WARRANTY, to the extent permitted by law.\n"));
}


/*
 * msmtp_print_help()
 *
 * Print --help information
 */

void msmtp_print_help(void)
{
    printf(_("USAGE:\n\n"
            "Sendmail mode (default):\n"
            "  %s [option...] [--] recipient...\n"
            "  %s [option...] -t [--] [recipient...]\n"
            "  Read a mail from standard input and transmit it to an SMTP "
                "or LMTP server.\n"
            "Server information mode:\n"
            "  %s [option...] --serverinfo\n"
            "  Print information about a server.\n"
            "Remote Message Queue Starting mode:\n"
            "  %s [option...] --rmqs=host|@domain|#queue\n"
            "  Send a Remote Message Queue Starting request to a server.\n"
            "\nOPTIONS:\n\n"
            "General options:\n"
            "  --version                    Print version.\n"
            "  --help                       Print help.\n"
            "  -P, --pretend                Print configuration info and "
                "exit.\n"
            "  -d, --debug                  Print debugging information.\n"
            "Changing the mode of operation:\n"
            "  -S, --serverinfo             Print information about the "
                "server.\n"
            "  --rmqs=host|@domain|#queue   Send a Remote Message Queue "
                "Starting request.\n"
            "Configuration options:\n"
            "  -C, --file=filename          Set configuration file.\n"
            "  -a, --account=id             Use the given account instead of "
                "the account\n"
            "                               named \"default\"; its settings "
                "may be changed\n"
            "                               with command line options.\n"
            "  --host=hostname              Set the server, use only command "
                "line settings;\n"
            "                               do not use any configuration file "
                "data.\n"
            "  --port=number                Set port number.\n"
            "  --timeout=(off|seconds)      Set/unset network timeout in "
                "seconds.\n"
            "  --protocol=(smtp|lmtp)       Use the given sub protocol.\n"
            "  --domain=string              Set the argument of EHLO or LHLO "
                "command.\n"
            "  --auth[=(on|off|method)]     Enable/disable authentication and "
                "optionally\n"
            "                               choose the method.\n"
            "  --user=[username]            Set/unset user name for "
                "authentication.\n"
            "  --passwordeval=[eval]        Evaluate password for "
                "authentication.\n"
            "  --tls[=(on|off)]             Enable/disable TLS encryption.\n"
            "  --tls-starttls[=(on|off)]    Enable/disable STARTTLS for TLS.\n"
            "  --tls-trust-file=[file]      Set/unset trust file for TLS.\n"
            "  --tls-crl-file=[file]        Set/unset revocation file for "
                "TLS.\n"
            "  --tls-fingerprint=[f]        Set/unset trusted certificate "
                "fingerprint for\n"
            "                               TLS.\n"
            "  --tls-key-file=[file]        Set/unset private key file for "
                "TLS.\n"
            "  --tls-cert-file=[file]       Set/unset private cert file for "
                "TLS.\n"
            "  --tls-certcheck[=(on|off)]   Enable/disable server certificate "
                "checks for TLS.\n"
            "  --tls-force-sslv3[=(on|off)] Enable/disable restriction to "
                "SSLv3.\n"
            "  --tls-min-dh-prime-bits=[b]  Set/unset minimum bit size of "
                "DH prime.\n"
            "  --tls-priorities=[prios]     Set/unset TLS priorities.\n"
            "Options specific to sendmail mode:\n"
            "  --auto-from[=(on|off)]       Enable/disable automatic "
                "envelope-from addresses.\n"
            "  -f, --from=address           Set envelope from address.\n"
            "  --maildomain=[domain]        Set the domain for automatic "
                "envelope from\n"
            "                               addresses.\n"
            "  -N, --dsn-notify=(off|cond)  Set/unset DSN conditions.\n"
            "  -R, --dsn-return=(off|ret)   Set/unset DSN amount.\n"
            "  --keepbcc[=(on|off)]         Enable/disable preservation of the "
                "Bcc header.\n"
            "  -X, --logfile=[file]         Set/unset log file.\n"
            "  --syslog[=(on|off|facility)] Enable/disable/configure syslog "
                "logging.\n"
            "  -t, --read-recipients        Read additional recipients from "
                "the mail.\n"
            "  --read-envelope-from         Read envelope from address from "
                "the mail.\n"
            "  --aliases=[file]             Set/unset aliases file.\n"
            "  --                           End of options.\n"
            "Accepted but ignored: -A, -B, -bm, -F, -G, -h, -i, -L, -m, -n, "
                "-O, -o, -v\n"
            "\nReport bugs to <%s>.\n"),
            prgname, prgname, prgname, prgname, PACKAGE_BUGREPORT);
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
#define LONGONLYOPT_VERSION                     0
#define LONGONLYOPT_HELP                        1
#define LONGONLYOPT_HOST                        2
#define LONGONLYOPT_PORT                        3
#define LONGONLYOPT_TIMEOUT                     4
#define LONGONLYOPT_AUTH                        5
#define LONGONLYOPT_USER                        6
#define LONGONLYOPT_PASSWORDEVAL                7
#define LONGONLYOPT_TLS                         8
#define LONGONLYOPT_TLS_STARTTLS                9
#define LONGONLYOPT_TLS_TRUST_FILE              10
#define LONGONLYOPT_TLS_CRL_FILE                11
#define LONGONLYOPT_TLS_FINGERPRINT             12
#define LONGONLYOPT_TLS_KEY_FILE                13
#define LONGONLYOPT_TLS_CERT_FILE               14
#define LONGONLYOPT_TLS_CERTCHECK               15
#define LONGONLYOPT_TLS_FORCE_SSLV3             16
#define LONGONLYOPT_TLS_MIN_DH_PRIME_BITS       17
#define LONGONLYOPT_TLS_PRIORITIES              18
#define LONGONLYOPT_PROTOCOL                    19
#define LONGONLYOPT_DOMAIN                      20
#define LONGONLYOPT_KEEPBCC                     21
#define LONGONLYOPT_RMQS                        22
#define LONGONLYOPT_SYSLOG                      23
#define LONGONLYOPT_MAILDOMAIN                  24
#define LONGONLYOPT_AUTO_FROM                   25
#define LONGONLYOPT_READ_ENVELOPE_FROM          26
#define LONGONLYOPT_ALIASES                     27

int msmtp_cmdline(msmtp_cmdline_conf_t *conf, int argc, char *argv[])
{
    struct option options[] =
    {
        { "version",               no_argument,       0, LONGONLYOPT_VERSION },
        { "help",                  no_argument,       0, LONGONLYOPT_HELP },
        { "pretend",               no_argument,       0, 'P' },
        /* accept an optional argument for sendmail compatibility: */
        { "debug",                 optional_argument, 0, 'd' },
        { "serverinfo",            no_argument,       0, 'S' },
        { "rmqs",                  required_argument, 0, LONGONLYOPT_RMQS },
        { "file",                  required_argument, 0, 'C' },
        { "account",               required_argument, 0, 'a' },
        { "host",                  required_argument, 0, LONGONLYOPT_HOST },
        { "port",                  required_argument, 0, LONGONLYOPT_PORT },
        { "timeout",               required_argument, 0, LONGONLYOPT_TIMEOUT},
        /* for compatibility with versions <= 1.4.1: */
        { "connect-timeout",       required_argument, 0, LONGONLYOPT_TIMEOUT},
        { "auto-from",             optional_argument, 0,
            LONGONLYOPT_AUTO_FROM },
        { "from",                  required_argument, 0, 'f' },
        { "maildomain",            required_argument, 0,
            LONGONLYOPT_MAILDOMAIN },
        { "auth",                  optional_argument, 0, LONGONLYOPT_AUTH },
        { "user",                  required_argument, 0, LONGONLYOPT_USER },
        { "passwordeval",          required_argument, 0,
            LONGONLYOPT_PASSWORDEVAL },
        { "tls",                   optional_argument, 0, LONGONLYOPT_TLS },
        { "tls-starttls",          optional_argument, 0,
            LONGONLYOPT_TLS_STARTTLS },
        { "tls-trust-file",        required_argument, 0,
            LONGONLYOPT_TLS_TRUST_FILE },
        { "tls-crl-file",          required_argument, 0,
            LONGONLYOPT_TLS_CRL_FILE },
        { "tls-fingerprint",       required_argument, 0,
            LONGONLYOPT_TLS_FINGERPRINT },
        { "tls-key-file",          required_argument, 0,
            LONGONLYOPT_TLS_KEY_FILE },
        { "tls-cert-file",         required_argument, 0,
            LONGONLYOPT_TLS_CERT_FILE },
        { "tls-certcheck",         optional_argument, 0,
            LONGONLYOPT_TLS_CERTCHECK },
        { "tls-force-sslv3",       optional_argument, 0,
            LONGONLYOPT_TLS_FORCE_SSLV3 },
        { "tls-min-dh-prime-bits", required_argument, 0,
            LONGONLYOPT_TLS_MIN_DH_PRIME_BITS },
        { "tls-priorities",        required_argument, 0,
            LONGONLYOPT_TLS_PRIORITIES },
        { "dsn-notify",            required_argument, 0, 'N' },
        { "dsn-return",            required_argument, 0, 'R' },
        { "protocol",              required_argument, 0, LONGONLYOPT_PROTOCOL },
        { "domain",                required_argument, 0, LONGONLYOPT_DOMAIN },
        { "keepbcc",               optional_argument, 0, LONGONLYOPT_KEEPBCC },
        { "logfile",               required_argument, 0, 'X' },
        { "syslog",                optional_argument, 0, LONGONLYOPT_SYSLOG },
        { "aliases",               required_argument, 0, LONGONLYOPT_ALIASES },
        { "read-recipients",       no_argument,       0, 't' },
        { "read-envelope-from",    no_argument,       0,
            LONGONLYOPT_READ_ENVELOPE_FROM },
        { 0, 0, 0, 0 }
    };
    int error_code;
    int c;
    int i;
    int rcptc;
    char **rcptv;
    FILE *tmpfile;
    char *errstr;
#ifdef HAVE_FMEMOPEN
    size_t rcptf_size;
    void *rcptf_buf;
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
                free(conf->cmdline_account->tls_sha1_fingerprint);
                conf->cmdline_account->tls_sha1_fingerprint = NULL;
                free(conf->cmdline_account->tls_md5_fingerprint);
                conf->cmdline_account->tls_md5_fingerprint = NULL;
                if (*optarg)
                {
                    if (strlen(optarg) == 2 * 20 + 19)
                    {
                        conf->cmdline_account->tls_sha1_fingerprint =
                            get_fingerprint(optarg, 20);
                    }
                    else if (strlen(optarg) == 2 * 16 + 15)
                    {
                        conf->cmdline_account->tls_md5_fingerprint =
                            get_fingerprint(optarg, 16);
                    }
                    if (!conf->cmdline_account->tls_sha1_fingerprint
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
                if (!optarg || is_on(optarg))
                {
                    conf->cmdline_account->tls_force_sslv3 = 1;
                }
                else if (is_off(optarg))
                {
                    conf->cmdline_account->tls_force_sslv3 = 0;
                }
                else
                {
                    print_error(_("invalid argument %s for %s"),
                            optarg, "--tls-force-sslv3");
                    error_code = 1;
                }
                conf->cmdline_account->mask |= ACC_TLS_FORCE_SSLV3;
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

            case LONGONLYOPT_KEEPBCC:
                if (!optarg || is_on(optarg))
                {
                    conf->cmdline_account->keepbcc = 1;
                }
                else if (is_off(optarg))
                {
                    conf->cmdline_account->keepbcc = 0;
                }
                else
                {
                    print_error(_("invalid argument %s for %s"),
                            optarg, "--keepbcc");
                    error_code = 1;
                }
                conf->cmdline_account->mask |= ACC_KEEPBCC;
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

            case 'A':
            case 'B':
            case 'F':
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
     * Write these to a temporary mail header so that msmtp_read_addresses() can
     * parse them. */
    rcptc = argc - optind;
    rcptv = &(argv[optind]);
#ifdef HAVE_FMEMOPEN
    rcptf_size = 2;     /* terminating "\n\0" */
    for (i = 0; i < rcptc; i++)
    {
        rcptf_size += 4 + strlen(rcptv[i]) + 1;
    }
    rcptf_buf = xmalloc(rcptf_size);
    tmpfile = fmemopen(rcptf_buf, rcptf_size, "w+");
#else
    tmpfile = tempfile(PACKAGE_NAME);
#endif
    if (!tmpfile)
    {
        print_error(_("cannot create temporary file: %s"),
                msmtp_sanitize_string(strerror(errno)));
        error_code = EX_IOERR;
        goto error_exit;
    }
    for (i = 0; i < rcptc && error_code != EOF; i++)
    {
        error_code = fputs("To: ", tmpfile);
        if (error_code != EOF)
        {
            error_code = fputs(rcptv[i], tmpfile);
        }
        if (error_code != EOF)
        {
            error_code = fputc('\n', tmpfile);
        }
    }
    if (error_code != EOF)
    {
        error_code = fputc('\n', tmpfile);
    }
    if (error_code == EOF)
    {
        print_error(_("cannot write mail headers to temporary "
                    "file: output error"));
        error_code = EX_IOERR;
        goto error_exit;
    }
    if (fseeko(tmpfile, 0, SEEK_SET) != 0)
    {
        print_error(_("cannot rewind temporary file: %s"),
                msmtp_sanitize_string(strerror(errno)));
        error_code = EX_IOERR;
        goto error_exit;
    }
    conf->recipients = list_new();
    if ((error_code = msmtp_read_addresses(tmpfile, NULL,
                    list_last(conf->recipients), NULL, &errstr)) != EX_OK)
    {
        print_error("%s", msmtp_sanitize_string(errstr));
        goto error_exit;
    }
    error_code = EX_OK;

error_exit:
    if (tmpfile)
    {
        fclose(tmpfile);
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
    char *homedir;
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
                        system_conffile, msmtp_sanitize_string(errstr));
            }
        }
        else
        {
            print_error("%s: %s", system_conffile,
                    msmtp_sanitize_string(errstr));
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
        homedir = get_homedir();
        real_user_conffile = get_filename(homedir, USERCONFFILE);
        free(homedir);
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
                        msmtp_sanitize_string(errstr));
                return EX_IOERR;
            }
            /* otherwise, we can ignore it */
            if (print_info)
            {
                printf(_("ignoring user configuration file %s: %s\n"),
                        real_user_conffile, msmtp_sanitize_string(errstr));
            }
        }
        else
        {
            print_error("%s: %s", real_user_conffile,
                    msmtp_sanitize_string(errstr));
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
    char fingerprint_string[2 * 20 + 19 + 1];

    if (account->id && account->conffile)
    {
        printf(_("using account %s from %s\n"),
                account->id, account->conffile);
    }
    printf("host                  = %s\n"
            "port                  = %d\n",
            account->host,
            account->port);
    printf("timeout               = ");
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
    printf("protocol              = %s\n"
            "domain                = %s\n",
            account->protocol == SMTP_PROTO_SMTP ? "smtp" : "lmtp",
            account->domain);
    printf("auth                  = ");
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
    if (account->tls_sha1_fingerprint)
    {
        msmtp_fingerprint_string(fingerprint_string,
                account->tls_sha1_fingerprint, 20);
    }
    else if (account->tls_md5_fingerprint)
    {
        msmtp_fingerprint_string(fingerprint_string,
                account->tls_md5_fingerprint, 16);
    }
    printf("user                  = %s\n"
            "password              = %s\n"
            "passwordeval          = %s\n"
            "ntlmdomain            = %s\n"
            "tls                   = %s\n"
            "tls_starttls          = %s\n"
            "tls_trust_file        = %s\n"
            "tls_crl_file          = %s\n"
            "tls_fingerprint       = %s\n"
            "tls_key_file          = %s\n"
            "tls_cert_file         = %s\n"
            "tls_certcheck         = %s\n"
            "tls_force_sslv3       = %s\n",
            account->username ? account->username : _("(not set)"),
            account->password ? "*" : _("(not set)"),
            account->passwordeval ? account->passwordeval : _("(not set)"),
            account->ntlmdomain ? account->ntlmdomain : _("(not set)"),
            account->tls ? _("on") : _("off"),
            account->tls_nostarttls ? _("off") : _("on"),
            account->tls_trust_file ? account->tls_trust_file : _("(not set)"),
            account->tls_crl_file ? account->tls_crl_file : _("(not set)"),
            account->tls_sha1_fingerprint || account->tls_md5_fingerprint
                ? fingerprint_string : _("(not set)"),
            account->tls_key_file ? account->tls_key_file : _("(not set)"),
            account->tls_cert_file ? account->tls_cert_file : _("(not set)"),
            account->tls_nocertcheck ? _("off") : _("on"),
            account->tls_force_sslv3 ? _("on") : _("off"));
    printf("tls_min_dh_prime_bits = ");
    if (account->tls_min_dh_prime_bits >= 0)
    {
        printf("%d\n", account->tls_min_dh_prime_bits);
    }
    else
    {
        printf("%s\n", _("(not set)"));
    }
    printf("tls_priorities        = %s\n",
            account->tls_priorities ? account->tls_priorities : _("(not set)"));
    if (conf.sendmail)
    {
        printf("auto_from             = %s\n"
                "maildomain            = %s\n"
                "from                  = %s\n"
                "dsn_notify            = %s\n"
                "dsn_return            = %s\n"
                "keepbcc               = %s\n"
                "logfile               = %s\n"
                "syslog                = %s\n"
                "aliases               = %s\n",
                account->auto_from ? _("on") : _("off"),
                account->maildomain ? account->maildomain : _("(not set)"),
                account->from ? account->from : conf.read_envelope_from
                    ? _("(read from mail)") : _("(not set)"),
                account->dsn_notify ? account->dsn_notify : _("(not set)"),
                account->dsn_return ? account->dsn_return : _("(not set)"),
                account->keepbcc ? _("on") : _("off"),
                account->logfile ? account->logfile : _("(not set)"),
                account->syslog ? account->syslog : _("(not set)"),
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
        printf("RMQS argument   = %s\n", conf.rmqs_argument);
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
    long mailsize;
    /* special LMTP error info */
    list_t *lmtp_errstrs;
    list_t *lmtp_error_msgs;
    list_t *lp_lmtp_errstrs;
    list_t *lp_lmtp_error_msgs;
    /* log information */
    char *log_info;
    /* needed to get the default port */
#if HAVE_GETSERVBYNAME
    struct servent *se;
#endif
    /* needed to extract addresses from headers */
    FILE *tmpfile = NULL;


    /* Avoid the side effects of text mode interpretations on DOS systems. */
#if defined W32_NATIVE || defined DJGPP
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
    if (conf.sendmail && (conf.read_recipients || conf.read_envelope_from))
    {
        if (!(tmpfile = tempfile(PACKAGE_NAME)))
        {
            print_error(_("cannot create temporary file: %s"),
                    msmtp_sanitize_string(strerror(errno)));
            error_code = EX_IOERR;
            goto exit;
        }
        if ((error_code = msmtp_read_addresses(stdin, tmpfile,
                        conf.read_recipients
                            ? list_last(conf.recipients) : NULL,
                        conf.read_envelope_from
                            ? &(conf.cmdline_account->from) : NULL,
                        &errstr)) != EX_OK)
        {
            print_error("%s", msmtp_sanitize_string(errstr));
            goto exit;
        }
        if (conf.read_envelope_from && (conf.pretend || conf.debug))
        {
            printf(_("envelope from address extracted from mail: %s\n"),
                    conf.cmdline_account->from);
        }
        if (fseeko(tmpfile, 0, SEEK_SET) != 0)
        {
            print_error(_("cannot rewind temporary file: %s"),
                    msmtp_sanitize_string(strerror(errno)));
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
        if (get_password_eval(account->passwordeval,
                    &account->password, &errstr) != CONF_EOK)
        {
            print_error("%s", msmtp_sanitize_string(errstr));
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
#ifdef HAVE_GETSERVBYNAME
                se = getservbyname("smtps", NULL);
                account->port = se ? ntohs(se->s_port) : 465;
#else
                account->port = 465;
#endif
            }
            else
            {
#ifdef HAVE_GETSERVBYNAME
                se = getservbyname("smtp", NULL);
                account->port = se ? ntohs(se->s_port) : 25;
#else
                account->port = 25;
#endif
            }
        }
        else /* LMTP. Has no default port as of 2006-06-17. */
        {
#ifdef HAVE_GETSERVBYNAME
            se = getservbyname("lmtp", NULL);
            if (se)
            {
                account->port = ntohs(se->s_port);
            }
#endif
        }
    }
    if (conf.sendmail && account->auto_from)
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
                    account->conffile, msmtp_sanitize_string(errstr));
        }
        else
        {
            print_error("%s", msmtp_sanitize_string(errstr));
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
                    msmtp_sanitize_string(errstr));
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
                msmtp_sanitize_string(errstr));
        error_code = EX_SOFTWARE;
        goto exit;
    }
    net_lib_initialized = 1;
    if (account->tls)
    {
#ifdef HAVE_TLS
        if ((e = tls_lib_init(&errstr)) != TLS_EOK)
        {
            print_error(_("cannot initialize TLS library: %s"),
                    msmtp_sanitize_string(errstr));
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
        if ((error_code = msmtp_sendmail(account, conf.recipients,
                        stdin, tmpfile, conf.debug, &mailsize,
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
                        print_error("%s", msmtp_sanitize_string(
                                    lp_lmtp_errstrs->data));
                        if ((lp = lp_lmtp_error_msgs->data))
                        {
                            while (!list_is_empty(lp))
                            {
                                lp = lp->next;
                                print_error(_("LMTP server message: %s"),
                                        msmtp_sanitize_string(lp->data));
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
                    print_error("%s", msmtp_sanitize_string(errstr));
                }
                if (errmsg)
                {
                    lp = errmsg;
                    while (!list_is_empty(lp))
                    {
                        lp = lp->next;
                        print_error(_("server message: %s"),
                                msmtp_sanitize_string(lp->data));
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
                msmtp_log_to_file(account->logfile, log_info);
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
                print_error("%s", msmtp_sanitize_string(errstr));
            }
            if (errmsg)
            {
                lp = errmsg;
                while (!list_is_empty(lp))
                {
                    lp = lp->next;
                    print_error(_("server message: %s"),
                            msmtp_sanitize_string(lp->data));
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
                print_error("%s", msmtp_sanitize_string(errstr));
            }
            if (errmsg)
            {
                lp = errmsg;
                while (!list_is_empty(lp))
                {
                    lp = lp->next;
                    print_error(_("server message: %s"),
                            msmtp_sanitize_string(lp->data));
                }
            }
        }
    }


exit:

    /* clean up */
    if (tmpfile)
    {
        fclose(tmpfile);
    }
    free(loaded_system_conffile);
    free(loaded_user_conffile);
#ifdef HAVE_TLS
    if (tls_lib_initialized)
    {
        tls_lib_deinit();
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
