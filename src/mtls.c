/*
 * mtls.c
 *
 * This file is part of msmtp, an SMTP client, and of mpop, a POP3 client.
 *
 * Copyright (C) 2000, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011,
 * 2012, 2014, 2016, 2018, 2019, 2020
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
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdlib.h>
#include <limits.h>
#include <time.h>
#include <errno.h>

#ifdef HAVE_LIBIDN
# include <idn2.h>
#endif

#include "gettext.h"
#define _(string) gettext(string)
#define N_(string) gettext_noop(string)

#include "xalloc.h"
#include "readbuf.h"
#include "tools.h"
#include "mtls.h"


/*
 * mtls_clear()
 *
 * see mtls.h
 */

void mtls_clear(mtls_t *mtls)
{
    mtls->is_active = 0;
    mtls->have_trust_file = 0;
    mtls->have_sha256_fingerprint = 0;
    mtls->have_sha1_fingerprint = 0;
    mtls->have_md5_fingerprint = 0;
    mtls->no_certcheck = 0;
    mtls->hostname = NULL;
    mtls->internals = NULL;
}


/*
 * mtls_is_active()
 *
 * see mtls.h
 */

int mtls_is_active(mtls_t *mtls)
{
    return mtls->is_active;
}


/*
 * mtls_cert_info_new()
 */

mtls_cert_info_t *mtls_cert_info_new(void)
{
    mtls_cert_info_t *tci;
    int i;

    tci = xmalloc(sizeof(mtls_cert_info_t));
    for (i = 0; i < 6; i++)
    {
        tci->owner_info[i] = NULL;
        tci->issuer_info[i] = NULL;
    }

    return tci;
}


/*
 * mtls_cert_info_free()
 */

void mtls_cert_info_free(mtls_cert_info_t *tci)
{
    int i;

    if (tci)
    {
        for (i = 0; i < 6; i++)
        {
            free(tci->owner_info[i]);
            free(tci->issuer_info[i]);
        }
        free(tci);
    }
}


/*
 * mtls_print_info()
 *
 * see mtls.h
 */

/* Convert the given time into a string. */
static void mtls_time_to_string(const time_t *t, char *buf, size_t bufsize)
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

void mtls_print_info(const char *mtls_parameter_description,
        const mtls_cert_info_t *tci)
{
    const char *info_fieldname[6] = { N_("Common Name"), N_("Organization"),
        N_("Organizational unit"), N_("Locality"), N_("State or Province"),
        N_("Country") };
    char sha256_fingerprint_string[96];
    char sha1_fingerprint_string[60];
    char timebuf[128];          /* should be long enough for every locale */
    char *tmp;
    int i;

    printf(_("TLS session parameters:\n"));
    printf("    %s\n", mtls_parameter_description
            ? mtls_parameter_description : _("not available"));

    print_fingerprint(sha256_fingerprint_string, tci->sha256_fingerprint, 32);
    print_fingerprint(sha1_fingerprint_string, tci->sha1_fingerprint, 20);

    printf(_("TLS certificate information:\n"));
    printf("    %s:\n", _("Owner"));
    for (i = 0; i < 6; i++)
    {
        if (tci->owner_info[i])
        {
            tmp = xstrdup(tci->owner_info[i]);
            printf("        %s: %s\n", gettext(info_fieldname[i]),
                    sanitize_string(tmp));
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
                    sanitize_string(tmp));
            free(tmp);
        }
    }
    printf("    %s:\n", _("Validity"));
    mtls_time_to_string(&tci->activation_time, timebuf, sizeof(timebuf));
    printf("        %s: %s\n", _("Activation time"), timebuf);
    mtls_time_to_string(&tci->expiration_time, timebuf, sizeof(timebuf));
    printf("        %s: %s\n", _("Expiration time"), timebuf);
    printf("    %s:\n", _("Fingerprints"));
    printf("        SHA256: %s\n", sha256_fingerprint_string);
    printf("        SHA1 (deprecated): %s\n", sha1_fingerprint_string);
}


/*
 * mtls_gets()
 *
 * see mtls.h
 */

int mtls_gets(mtls_t *mtls, readbuf_t *readbuf,
        char *str, size_t size, size_t *len, char **errstr)
{
    char c;
    size_t i;
    int ret;

    i = 0;
    while (i + 1 < size)
    {
        if ((ret = mtls_readbuf_read(mtls, readbuf, &c, errstr)) == 1)
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
            return TLS_EIO;
        }
    }
    str[i] = '\0';
    *len = i;
    return TLS_EOK;
}


/*
 * mtls_exitcode()
 *
 * see mtls.h
 */

int mtls_exitcode(int mtls_error_code)
{
    switch (mtls_error_code)
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
