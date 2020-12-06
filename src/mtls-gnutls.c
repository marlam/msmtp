/*
 * mtls-gnutls.c
 *
 * This file is part of msmtp, an SMTP client.
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

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/pkcs11.h>

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


struct mtls_internals_t
{
    gnutls_session_t session;
    gnutls_certificate_credentials_t cred;
};


/*
 * mtls_lib_init()
 *
 * see mtls.h
 */

int mtls_lib_init(char **errstr)
{
    /* Library initialization is implicit */
    (void)errstr;
    return TLS_EOK;
}


/*
 * mtls_cert_info_get()
 *
 * see mtls.h
 */

int mtls_cert_info_get(mtls_t *mtls, mtls_cert_info_t *tci, char **errstr)
{
    const gnutls_datum_t *cert_list;
    unsigned int cert_list_size;
    gnutls_x509_crt_t cert;
    size_t size;
    const char *oid[6] = { GNUTLS_OID_X520_COMMON_NAME,
        GNUTLS_OID_X520_ORGANIZATION_NAME,
        GNUTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME,
        GNUTLS_OID_X520_LOCALITY_NAME,
        GNUTLS_OID_X520_STATE_OR_PROVINCE_NAME,
        GNUTLS_OID_X520_COUNTRY_NAME };
    int i;
    int e;
    char *p;
    const char *errmsg;

    errmsg = _("cannot get TLS certificate info");
    if (!(cert_list =
                gnutls_certificate_get_peers(mtls->internals->session, &cert_list_size))
            || cert_list_size == 0)
    {
        *errstr = xasprintf(_("%s: no certificate was found"), errmsg);
        return TLS_ECERT;
    }
    if (gnutls_x509_crt_init(&cert) != 0)
    {
        *errstr = xasprintf(_("%s: cannot initialize certificate structure"),
                errmsg);
        return TLS_ECERT;
    }
    if (gnutls_x509_crt_import(cert, &cert_list[0], GNUTLS_X509_FMT_DER) != 0)
    {
        *errstr = xasprintf(_("%s: error parsing certificate"), errmsg);
        gnutls_x509_crt_deinit(cert);
        return TLS_ECERT;
    }

    /* certificate information */
    size = 32;
    if (gnutls_x509_crt_get_fingerprint(cert, GNUTLS_DIG_SHA256,
                tci->sha256_fingerprint, &size) != 0)
    {
        *errstr = xasprintf(_("%s: error getting SHA256 fingerprint"), errmsg);
        gnutls_x509_crt_deinit(cert);
        return TLS_ECERT;
    }
    size = 20;
    if (gnutls_x509_crt_get_fingerprint(cert, GNUTLS_DIG_SHA,
                tci->sha1_fingerprint, &size) != 0)
    {
        *errstr = xasprintf(_("%s: error getting SHA1 fingerprint"), errmsg);
        gnutls_x509_crt_deinit(cert);
        return TLS_ECERT;
    }
    if ((tci->activation_time = gnutls_x509_crt_get_activation_time(cert)) < 0)
    {
        *errstr = xasprintf(_("%s: cannot get activation time"), errmsg);
        gnutls_x509_crt_deinit(cert);
        return TLS_ECERT;
    }
    if ((tci->expiration_time = gnutls_x509_crt_get_expiration_time(cert)) < 0)
    {
        *errstr = xasprintf(_("%s: cannot get expiration time"), errmsg);
        gnutls_x509_crt_deinit(cert);
        return TLS_ECERT;
    }

    /* owner information */
    for (i = 0; i < 6; i++)
    {
        size = 0;
        e = gnutls_x509_crt_get_dn_by_oid(cert, oid[i], 0, 0, NULL, &size);
        if (e == GNUTLS_E_SHORT_MEMORY_BUFFER)
        {
            p = xmalloc(size);
            e = gnutls_x509_crt_get_dn_by_oid(cert, oid[i], 0, 0, p, &size);
            if (e == 0)
            {
                tci->owner_info[i] = p;
            }
            else
            {
                free(p);
            }
        }
    }

    /* issuer information */
    for (i = 0; i < 6; i++)
    {
        size = 0;
        e = gnutls_x509_crt_get_issuer_dn_by_oid(
                cert, oid[i], 0, 0, NULL, &size);
        if (e == GNUTLS_E_SHORT_MEMORY_BUFFER)
        {
            p = xmalloc(size);
            e = gnutls_x509_crt_get_issuer_dn_by_oid(
                    cert, oid[i], 0, 0, p, &size);
            if (e == 0)
            {
                tci->issuer_info[i] = p;
            }
            else
            {
                free(p);
            }
        }
    }

    gnutls_x509_crt_deinit(cert);
    return TLS_EOK;
}


/*
 * mtls_check_cert()
 *
 * If the 'mtls->have_trust_file' flag is set, perform a real verification of
 * the peer's certificate. If this succeeds, the connection can be considered
 * secure.
 * If one of the 'mtls->have_*_fingerprint' flags is
 * set, compare the 'mtls->fingerprint' data with the peer certificate's
 * fingerprint. If this succeeds, the connection can be considered secure.
 * If none of these flags is set, perform only a few sanity checks of the
 * peer's certificate. You cannot trust the connection when this succeeds.
 * Used error codes: TLS_ECERT
 */

static int mtls_check_cert(mtls_t *mtls, char **errstr)
{
    int error_code;
    unsigned int status;
    const char *error_msg = _("TLS certificate verification failed");

    /* The following fingerprint checking is deprecated and should be removed
     * in the next major version. */
    if (mtls->have_sha256_fingerprint
            || mtls->have_sha1_fingerprint || mtls->have_md5_fingerprint)
    {
        const gnutls_datum_t *cert_list;
        unsigned int cert_list_size;
        gnutls_x509_crt_t cert;
        unsigned char fingerprint[32];
        size_t size;

        /* If one of these matches, we trust the peer and do not perform any
         * other checks. */
        if (!(cert_list = gnutls_certificate_get_peers(
                        mtls->internals->session, &cert_list_size)))
        {
            *errstr = xasprintf(_("%s: no certificate was found"), error_msg);
            return TLS_ECERT;
        }
        if (gnutls_x509_crt_init(&cert) < 0)
        {
            *errstr = xasprintf(
                    _("%s: cannot initialize certificate structure"),
                    error_msg);
            return TLS_ECERT;
        }
        if (gnutls_x509_crt_import(cert, &cert_list[0], GNUTLS_X509_FMT_DER)
                < 0)
        {
            *errstr = xasprintf(_("%s: error parsing certificate %u of %u"),
                    error_msg, 0 + 1, cert_list_size);
            return TLS_ECERT;
        }
        if (mtls->have_sha256_fingerprint)
        {
            size = 32;
            if (gnutls_x509_crt_get_fingerprint(cert, GNUTLS_DIG_SHA256,
                        fingerprint, &size) != 0)
            {
                *errstr = xasprintf(_("%s: error getting SHA256 fingerprint"),
                        error_msg);
                gnutls_x509_crt_deinit(cert);
                return TLS_ECERT;
            }
            if (memcmp(fingerprint, mtls->fingerprint, 32) != 0)
            {
                *errstr = xasprintf(_("%s: the certificate fingerprint "
                            "does not match"), error_msg);
                gnutls_x509_crt_deinit(cert);
                return TLS_ECERT;
            }
        }
        else if (mtls->have_sha1_fingerprint)
        {
            size = 20;
            if (gnutls_x509_crt_get_fingerprint(cert, GNUTLS_DIG_SHA,
                        fingerprint, &size) != 0)
            {
                *errstr = xasprintf(_("%s: error getting SHA1 fingerprint"),
                        error_msg);
                gnutls_x509_crt_deinit(cert);
                return TLS_ECERT;
            }
            if (memcmp(fingerprint, mtls->fingerprint, 20) != 0)
            {
                *errstr = xasprintf(_("%s: the certificate fingerprint "
                            "does not match"), error_msg);
                gnutls_x509_crt_deinit(cert);
                return TLS_ECERT;
            }
        }
        else
        {
            size = 16;
            if (gnutls_x509_crt_get_fingerprint(cert, GNUTLS_DIG_MD5,
                        fingerprint, &size) != 0)
            {
                *errstr = xasprintf(_("%s: error getting MD5 fingerprint"),
                        error_msg);
                gnutls_x509_crt_deinit(cert);
                return TLS_ECERT;
            }
            if (memcmp(fingerprint, mtls->fingerprint, 16) != 0)
            {
                *errstr = xasprintf(_("%s: the certificate fingerprint "
                            "does not match"), error_msg);
                gnutls_x509_crt_deinit(cert);
                return TLS_ECERT;
            }
        }
        gnutls_x509_crt_deinit(cert);
        return TLS_EOK;
    }

    /* Verify the certificate(s). */
    if ((error_code = gnutls_certificate_verify_peers3(mtls->internals->session,
                    mtls->hostname, &status)) != 0)
    {
        *errstr = xasprintf("%s: %s", error_msg, gnutls_strerror(error_code));
        return TLS_ECERT;
    }
    if (mtls->have_trust_file && status)
    {
        gnutls_datum_t txt;
        gnutls_certificate_verification_status_print(status,
                GNUTLS_CRT_X509, &txt, 0);
        *errstr = xasprintf(_("%s: %s"), error_msg, txt.data);
        free(txt.data);
        return TLS_ECERT;
    }

    return TLS_EOK;
}


/*
 * mtls_pin_callback()
 *
 * Passes a PIN to GnuTLS for PKCS11 smart cards or similar
 */
static int mtls_pin_callback(void *userdata, int attempt,
        const char *token_url, const char *token_label,
        unsigned int flags, char *pin, size_t pin_max)
{
    (void)attempt;
    (void)token_url;
    (void)token_label;
    (void)flags;

    size_t len;
    if (userdata && (len = strlen(userdata)) < pin_max)
    {
        strcpy(pin, userdata);
        return 0;
    }
    else
    {
        return 1;
    }
}


/*
 * mtls_init()
 *
 * see mtls.h
 */

int mtls_init(mtls_t *mtls,
        const char *key_file, const char *cert_file, const char *pin,
        const char *trust_file, const char *crl_file,
        const unsigned char *sha256_fingerprint,
        const unsigned char *sha1_fingerprint,
        const unsigned char *md5_fingerprint,
        int min_dh_prime_bits, const char *priorities,
        const char *hostname,
        int no_certcheck,
        char **errstr)
{
    int error_code;

    mtls->internals = xmalloc(sizeof(struct mtls_internals_t));

    if ((error_code = gnutls_init(&mtls->internals->session, GNUTLS_CLIENT)) != 0)
    {
        *errstr = xasprintf(_("cannot initialize TLS session: %s"),
                gnutls_strerror(error_code));
        return TLS_ELIBFAILED;
    }
    if (priorities)
    {
        const char *error_pos = NULL;
        if ((error_code = gnutls_priority_set_direct(mtls->internals->session,
                        priorities, &error_pos)) != 0)
        {
            if (error_pos)
            {
                char *error_pos_str = xasprintf(
                        _("error in priority string at position %d"),
                        (int)(error_pos - priorities + 1));
                *errstr = xasprintf(
                        _("cannot set priorities for TLS session: %s"),
                        error_pos_str);
                free(error_pos_str);
            }
            else
            {
                *errstr = xasprintf(
                        _("cannot set priorities for TLS session: %s"),
                        gnutls_strerror(error_code));
            }
            gnutls_deinit(mtls->internals->session);
            free(mtls->internals);
            mtls->internals = NULL;
            return TLS_ELIBFAILED;
        }
    }
    else
    {
        if ((error_code = gnutls_set_default_priority(mtls->internals->session)) != 0)
        {
            *errstr = xasprintf(_("cannot set default priority for TLS session: "
                        "%s"), gnutls_strerror(error_code));
            gnutls_deinit(mtls->internals->session);
            free(mtls->internals);
            mtls->internals = NULL;
            return TLS_ELIBFAILED;
        }
    }
    if (min_dh_prime_bits >= 0)
    {
        gnutls_dh_set_prime_bits(mtls->internals->session, min_dh_prime_bits);
    }
    if ((error_code = gnutls_certificate_allocate_credentials(&mtls->internals->cred)) < 0)
    {
        *errstr = xasprintf(
                _("cannot allocate certificate for TLS session: %s"),
                gnutls_strerror(error_code));
        gnutls_deinit(mtls->internals->session);
        free(mtls->internals);
        mtls->internals = NULL;
        return TLS_ELIBFAILED;
    }
    if (key_file && cert_file)
    {
        gnutls_pkcs11_set_pin_function(mtls_pin_callback, (void*)pin);
        if ((error_code = gnutls_certificate_set_x509_key_file(mtls->internals->cred,
                        cert_file, key_file, GNUTLS_X509_FMT_PEM)) < 0)
        {
            *errstr = xasprintf(_("cannot set X509 key file %s and/or "
                        "X509 cert file %s for TLS session: %s"),
                    key_file, cert_file, gnutls_strerror(error_code));
            gnutls_deinit(mtls->internals->session);
            gnutls_certificate_free_credentials(mtls->internals->cred);
            free(mtls->internals);
            mtls->internals = NULL;
            return TLS_EFILE;
        }
    }
    if (trust_file
            && !no_certcheck
            && !sha256_fingerprint
            && !sha1_fingerprint
            && !md5_fingerprint)
    {
        if (strcmp(trust_file, "system") == 0)
        {
            if ((error_code = gnutls_certificate_set_x509_system_trust(
                            mtls->internals->cred)) < 0)
            {
                *errstr = xasprintf(
                        _("cannot set X509 system trust for TLS session: %s"),
                        gnutls_strerror(error_code));
                gnutls_deinit(mtls->internals->session);
                gnutls_certificate_free_credentials(mtls->internals->cred);
                free(mtls->internals);
                mtls->internals = NULL;
                return TLS_ELIBFAILED;
            }
        }
        else
        {
            if ((error_code = gnutls_certificate_set_x509_trust_file(
                            mtls->internals->cred, trust_file, GNUTLS_X509_FMT_PEM)) <= 0)
            {
                *errstr = xasprintf(
                        _("cannot set X509 trust file %s for TLS session: %s"),
                        trust_file, gnutls_strerror(error_code));
                gnutls_deinit(mtls->internals->session);
                gnutls_certificate_free_credentials(mtls->internals->cred);
                free(mtls->internals);
                mtls->internals = NULL;
                return TLS_EFILE;
            }
        }
        if (crl_file)
        {
            if ((error_code = gnutls_certificate_set_x509_crl_file(
                            mtls->internals->cred, crl_file, GNUTLS_X509_FMT_PEM)) < 0)
            {
                *errstr = xasprintf(
                        _("cannot set X509 CRL file %s for TLS session: %s"),
                        crl_file, gnutls_strerror(error_code));
                gnutls_deinit(mtls->internals->session);
                gnutls_certificate_free_credentials(mtls->internals->cred);
                free(mtls->internals);
                mtls->internals = NULL;
                return TLS_EFILE;
            }
        }
        mtls->have_trust_file = 1;
    }
    if (sha256_fingerprint && !no_certcheck)
    {
        memcpy(mtls->fingerprint, sha256_fingerprint, 32);
        mtls->have_sha256_fingerprint = 1;
    }
    else if (sha1_fingerprint && !no_certcheck)
    {
        memcpy(mtls->fingerprint, sha1_fingerprint, 20);
        mtls->have_sha1_fingerprint = 1;
    }
    else if (md5_fingerprint && !no_certcheck)
    {
        memcpy(mtls->fingerprint, md5_fingerprint, 16);
        mtls->have_md5_fingerprint = 1;
    }
    if ((error_code = gnutls_credentials_set(mtls->internals->session,
                    GNUTLS_CRD_CERTIFICATE, mtls->internals->cred)) < 0)
    {
        *errstr = xasprintf(_("cannot set credentials for TLS session: %s"),
                gnutls_strerror(error_code));
        gnutls_deinit(mtls->internals->session);
        gnutls_certificate_free_credentials(mtls->internals->cred);
        free(mtls->internals);
        mtls->internals = NULL;
        return TLS_ELIBFAILED;
    }
    mtls->no_certcheck = no_certcheck;
    mtls->hostname = xstrdup(hostname);
    return TLS_EOK;
}


/*
 * mtls_start()
 *
 * see mtls.h
 */

int mtls_start(mtls_t *mtls, int fd,
        mtls_cert_info_t *tci, char **mtls_parameter_description, char **errstr)
{
    int error_code;

    gnutls_server_name_set(mtls->internals->session, GNUTLS_NAME_DNS, mtls->hostname, strlen(mtls->hostname));
    gnutls_transport_set_int(mtls->internals->session, fd);
    do
    {
        error_code = gnutls_handshake(mtls->internals->session);
    }
    while (error_code < 0 && gnutls_error_is_fatal(error_code) == 0);

    if (error_code != 0)
    {
        *errstr = xasprintf(_("TLS handshake failed: %s"),
                gnutls_strerror(error_code));
        gnutls_deinit(mtls->internals->session);
        gnutls_certificate_free_credentials(mtls->internals->cred);
        return TLS_EHANDSHAKE;
    }
    if (tci)
    {
        if ((error_code = mtls_cert_info_get(mtls, tci, errstr)) != TLS_EOK)
        {
            gnutls_deinit(mtls->internals->session);
            gnutls_certificate_free_credentials(mtls->internals->cred);
            return error_code;
        }
    }
    if (mtls_parameter_description)
    {
        *mtls_parameter_description = gnutls_session_get_desc(mtls->internals->session);
    }
    if (!mtls->no_certcheck)
    {
        if ((error_code = mtls_check_cert(mtls, errstr)) != TLS_EOK)
        {
            gnutls_deinit(mtls->internals->session);
            gnutls_certificate_free_credentials(mtls->internals->cred);
            return error_code;
        }
    }
    mtls->is_active = 1;
    return TLS_EOK;
}


/*
 * mtls_readbuf_read()
 *
 * Wraps TLS read function to provide buffering for mtls_gets().
 */

int mtls_readbuf_read(mtls_t *mtls, readbuf_t *readbuf, char *ptr,
        char **errstr)
{
    ssize_t ret;

    if (readbuf->count <= 0)
    {
        do
        {
            ret = gnutls_record_recv(mtls->internals->session,
                    readbuf->buf, sizeof(readbuf->buf));
        }
        while (ret == GNUTLS_E_AGAIN);
        if (ret < 0)
        {
            if (ret == GNUTLS_E_INTERRUPTED)
            {
                *errstr = xasprintf(_("operation aborted"));
            }
            else
            {
                *errstr = xasprintf(_("cannot read from TLS connection: %s"),
                        gnutls_strerror(ret));
            }
            return TLS_EIO;
        }
        else if (ret == 0)
        {
            return 0;
        }
        readbuf->count = (int)ret;
        readbuf->ptr = readbuf->buf;
    }
    readbuf->count--;
    *ptr = *((readbuf->ptr)++);
    return 1;
}


/*
 * mtls_puts()
 *
 * see mtls.h
 */

int mtls_puts(mtls_t *mtls, const char *s, size_t len, char **errstr)
{
    ssize_t ret;

    if (len < 1)
    {
        /* nothing to be done */
        return TLS_EOK;
    }

    do
    {
        ret = gnutls_record_send(mtls->internals->session, s, len);
    }
    while (ret == GNUTLS_E_AGAIN);
    if (ret < 0)
    {
        if (ret == GNUTLS_E_INTERRUPTED)
        {
            *errstr = xasprintf(_("operation aborted"));
        }
        else
        {
            *errstr = xasprintf(_("cannot write to TLS connection: %s"),
                    gnutls_strerror(ret));
        }
        return TLS_EIO;
    }
    else if ((size_t)ret == len)
    {
        return TLS_EOK;
    }
    else /* 0 <= error_code < len */
    {
        *errstr = xasprintf(_("cannot write to TLS connection: %s"),
                _("unknown error"));
        return TLS_EIO;
    }
}


/*
 * mtls_close()
 *
 * see mtls.h
 */

void mtls_close(mtls_t *mtls)
{
    if (mtls->is_active)
    {
        int e;
        do
        {
            e = gnutls_bye(mtls->internals->session, GNUTLS_SHUT_WR);
        }
        while (e == GNUTLS_E_AGAIN);
        gnutls_deinit(mtls->internals->session);
        gnutls_certificate_free_credentials(mtls->internals->cred);
    }
    free(mtls->internals);
    if (mtls->hostname)
    {
        free(mtls->hostname);
    }
    mtls_clear(mtls);
}


/*
 * mtls_lib_deinit()
 *
 * see mtls.h
 */

void mtls_lib_deinit(void)
{
}
