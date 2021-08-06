/*
 * mtls-openssl.c
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

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define X509_get0_notBefore X509_get_notBefore
#define X509_get0_notAfter X509_get_notAfter
#endif

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
    SSL_CTX *ssl_ctx;
    SSL *ssl;
};



/*
 * seed_prng()
 *
 * Seeds the OpenSSL random number generator.
 * Used error codes: TLS_ESEED
 */

static int seed_prng(char **errstr)
{
    char randfile[512];
    time_t t;
    int prn;
    int system_prn_max = 1024;

    /* Most systems have /dev/random or other sources of random numbers that
     * OpenSSL can use to seed itself.
     * The only system I know of where we must seed the PRNG is DOS.
     */
    if (!RAND_status())
    {
        if (!RAND_file_name(randfile, 512))
        {
            *errstr = xasprintf(_("no environment variables RANDFILE or HOME, "
                        "or filename of rand file too long"));
            return TLS_ESEED;
        }
        if (RAND_load_file(randfile, -1) < 1)
        {
            *errstr = xasprintf(_("%s: input error"), randfile);
            return TLS_ESEED;
        }
        /* Seed in time. I can't think of other "random" things on DOS
         * systems. */
        t = time(NULL);
        RAND_seed((unsigned char *)&t, sizeof(time_t));
        /* If the RANDFILE + time is not enough, we fall back to the insecure
         * and stupid method of seeding OpenSSLs PRNG with the systems PRNG. */
        if (!RAND_status())
        {
            srand((unsigned int)(t % UINT_MAX));
            while (!RAND_status() && system_prn_max > 0)
            {
                prn = rand();
                RAND_seed(&prn, sizeof(int));
                system_prn_max--;
            }
        }
        /* Are we happy now? */
        if (!RAND_status())
        {
            *errstr = xasprintf(_("random file + time + pseudo randomness is "
                        "not enough, giving up"));
            return TLS_ESEED;
        }
        /* Save a rand file for later usage. We ignore errors here as we can't
         * do anything about them. */
        (void)RAND_write_file(randfile);
    }
    return TLS_EOK;
}


/*
 * mtls_lib_init()
 *
 * see mtls.h
 */

int mtls_lib_init(char **errstr)
{
    int e;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_load_error_strings();
    SSL_library_init();
#endif
    if ((e = seed_prng(errstr)) != TLS_EOK)
    {
        return e;
    }

    return TLS_EOK;
}


/*
 * asn1time_to_time_t() [OpenSSL only]
 *
 * Convert a ASN1 time string ([YY]YYMMDDhhmm[ss](Z)) into a time_t.
 * The flag 'is_utc' indicates whether the string is in UTC or GENERALIZED
 * format. GENERALIZED means a 4 digit year.
 * In case of invalid strings or over-/underflows, 1 is returned, and the value
 * of 't' is undefined. On success, 0 is returned.
 *
 * This code uses many ideas from GnuTLS code (lib/x509/common.c).
 * The transformation of struct tm to time_t is based on code from Russ Allbery
 * (rra@stanford.edu), who wrote a mktime_utc function and placed it under
 * public domain.
 */

static int is_leap(int year)
{
    return (((year) % 4) == 0 && (((year) % 100) != 0 || ((year) % 400) == 0));
}

static int asn1time_to_time_t(const char *asn1time, int is_utc, time_t *t)
{
    size_t len;
    int i;
    size_t j;
    const char *p;
    char xx[3];
    char xxxx[5];
    const int monthdays[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    struct tm tm;

    len = strlen(asn1time);
    if ((is_utc && len < 10) || (!is_utc && len < 12))
    {
        goto error_exit;
    }
    for (j = 0; j < len - 1; j++)
    {
        if (!isdigit((unsigned char)asn1time[j]))
        {
            goto error_exit;
        }
    }

    xx[2] = '\0';
    xxxx[4] = '\0';
    p = asn1time;
    if (is_utc)
    {
        strncpy(xx, p, 2);
        tm.tm_year = atoi(xx);
        tm.tm_year += (tm.tm_year > 49) ? 1900 : 2000;
        p += 2;
    }
    else
    {
        strncpy(xxxx, p, 4);
        tm.tm_year = atoi(xxxx);
        p += 4;
    }
    strncpy(xx, p, 2);
    tm.tm_mon = atoi(xx) - 1;
    p += 2;
    strncpy(xx, p, 2);
    tm.tm_mday = atoi(xx);
    p += 2;
    strncpy(xx, p, 2);
    tm.tm_hour = atoi(xx);
    p += 2;
    strncpy(xx, p, 2);
    tm.tm_min = atoi(xx);
    p += 2;
    if (isdigit((unsigned char)(*p)))
    {
        strncpy(xx, p, 2);
        tm.tm_sec = atoi(xx);
    }
    else
    {
        tm.tm_sec = 0;
    }

    /* basic check for 32 bit time_t overflows. */
    if (sizeof(time_t) <= 4 && tm.tm_year >= 2038)
    {
        goto error_exit;
    }
    if (tm.tm_year < 1970 || tm.tm_mon < 0 || tm.tm_mon > 11)
    {
        goto error_exit;
    }
    *t = 0;
    for (i = 1970; i < tm.tm_year; i++)
    {
        *t += 365 + (is_leap(i) ? 1 : 0);
    }
    for (i = 0; i < tm.tm_mon; i++)
    {
        *t += monthdays[i];
    }
    if (tm.tm_mon > 1 && is_leap(tm.tm_year))
    {
        *t += 1;
    }
    *t = 24 * (*t + tm.tm_mday - 1) + tm.tm_hour;
    *t = 60 * (*t) + tm.tm_min;
    *t = 60 * (*t) + tm.tm_sec;

    return 0;

error_exit:
    return 1;
}


/*
 * mtls_cert_info_get()
 *
 * see mtls.h
 */

int mtls_cert_info_get(mtls_t *mtls, mtls_cert_info_t *mtci, char **errstr)
{
    X509 *x509cert;
    X509_NAME *x509_subject;
    X509_NAME *x509_issuer;
    const ASN1_TIME *asn1time;
    unsigned int usize;
    const char *errmsg;

    errmsg = _("cannot get TLS certificate info");
    if (!(x509cert = SSL_get_peer_certificate(mtls->internals->ssl)))
    {
        *errstr = xasprintf(_("%s: no certificate was found"), errmsg);
        return TLS_ECERT;
    }
    if (!(x509_subject = X509_get_subject_name(x509cert)))
    {
        *errstr = xasprintf(_("%s: cannot get certificate subject"), errmsg);
        X509_free(x509cert);
        return TLS_ECERT;
    }
    if (!(x509_issuer = X509_get_issuer_name(x509cert)))
    {
        *errstr = xasprintf(_("%s: cannot get certificate issuer"), errmsg);
        X509_free(x509cert);
        return TLS_ECERT;
    }

    /* certificate information */
    usize = 32;
    if (!X509_digest(x509cert, EVP_sha256(), mtci->sha256_fingerprint, &usize))
    {
        *errstr = xasprintf(_("%s: error getting SHA256 fingerprint"), errmsg);
        return TLS_ECERT;
    }
    usize = 20;
    if (!X509_digest(x509cert, EVP_sha1(), mtci->sha1_fingerprint, &usize))
    {
        *errstr = xasprintf(_("%s: error getting SHA1 fingerprint"), errmsg);
        return TLS_ECERT;
    }
    asn1time = X509_get0_notBefore(x509cert);
    if (asn1time_to_time_t((const char *)asn1time->data,
                (asn1time->type != V_ASN1_GENERALIZEDTIME),
                &(mtci->activation_time)) != 0)
    {
        *errstr = xasprintf(_("%s: cannot get activation time"), errmsg);
        X509_free(x509cert);
        mtls_cert_info_free(mtci);
        return TLS_ECERT;
    }
    asn1time = X509_get0_notAfter(x509cert);
    if (asn1time_to_time_t((const char *)asn1time->data,
                (asn1time->type != V_ASN1_GENERALIZEDTIME),
                &(mtci->expiration_time)) != 0)
    {
        *errstr = xasprintf(_("%s: cannot get expiration time"), errmsg);
        X509_free(x509cert);
        mtls_cert_info_free(mtci);
        return TLS_ECERT;
    }

    /* subject information */
    mtci->subject_info = X509_NAME_oneline(x509_subject, NULL, 0);

    /* issuer information */
    mtci->issuer_info = X509_NAME_oneline(x509_issuer, NULL, 0);

    X509_free(x509cert);
    return TLS_EOK;
}


/*
 * [OpenSSL only] hostname_match()
 *
 * Compares the hostname with the name in the certificate. The certificate name
 * may include a wildcard as the leftmost domain component (its first two
 * characters are "*." in this case).
 *
 * Returns 1 if the names match, 0 otherwise.
 *
 * This is the same form of matching that gnutls_x509_crt_check_hostname() from
 * GnuTLS 1.2.0 uses.
 * It conforms to RFC2595 (Using TLS with IMAP, POP3 and ACAP), section 2.4.
 * RFC2818 (HTTP over TLS), section 3.1 says that `f*.com matches foo.com'. This
 * function does not allow that.
 * RFC3207 (SMTP Service Extension for Secure SMTP over Transport Layer
 * Security), section 4.1 says nothing more than `A SMTP client would probably
 * only want to authenticate an SMTP server whose server certificate has a
 * domain name that is the domain name that the client thought it was connecting
 * to'.
 */

static int hostname_match(const char *hostname, const char *certname)
{
    const char *cmp1, *cmp2;

    if (strncmp(certname, "*.", 2) == 0)
    {
        cmp1 = certname + 2;
        cmp2 = strchr(hostname, '.');
        if (!cmp2)
        {
            return 0;
        }
        else
        {
            cmp2++;
        }
    }
    else
    {
        cmp1 = certname;
        cmp2 = hostname;
    }

    if (*cmp1 == '\0' || *cmp2 == '\0')
    {
        return 0;
    }

    if (strcasecmp(cmp1, cmp2) != 0)
    {
        return 0;
    }

    return 1;
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
    X509 *x509cert;
    long status;
    const char *error_msg;
    int i;
    /* hostname in ASCII format: */
    char *idn_hostname = NULL;
    /* needed to get the common name: */
    X509_NAME *x509_subject;
    char *buf;
    int length;
    /* needed to get the DNS subjectAltNames: */
    void *subj_alt_names;
    int subj_alt_names_count;
    GENERAL_NAME *subj_alt_name;
    /* did we find a name matching hostname? */
    int match_found;
    /* needed for fingerprint checking */
    unsigned int usize;
    unsigned char fingerprint[32];


    if (mtls->have_trust_file)
    {
        error_msg = _("TLS certificate verification failed");
    }
    else
    {
        error_msg = _("TLS certificate check failed");
    }

    /* Get certificate */
    if (!(x509cert = SSL_get_peer_certificate(mtls->internals->ssl)))
    {
        *errstr = xasprintf(_("%s: no certificate was sent"), error_msg);
        return TLS_ECERT;
    }

    if (mtls->have_sha256_fingerprint
            || mtls->have_sha1_fingerprint || mtls->have_md5_fingerprint)
    {
        /* If one of these matches, we trust the peer and do not perform any
         * other checks. */
        if (mtls->have_sha256_fingerprint)
        {
            usize = 32;
            if (!X509_digest(x509cert, EVP_sha256(), fingerprint, &usize))
            {
                *errstr = xasprintf(_("%s: error getting SHA256 fingerprint"),
                        error_msg);
                X509_free(x509cert);
                return TLS_ECERT;
            }
            if (memcmp(fingerprint, mtls->fingerprint, 32) != 0)
            {
                *errstr = xasprintf(_("%s: the certificate fingerprint "
                            "does not match"), error_msg);
                X509_free(x509cert);
                return TLS_ECERT;
            }
        }
        else if (mtls->have_sha1_fingerprint)
        {
            usize = 20;
            if (!X509_digest(x509cert, EVP_sha1(), fingerprint, &usize))
            {
                *errstr = xasprintf(_("%s: error getting SHA1 fingerprint"),
                        error_msg);
                X509_free(x509cert);
                return TLS_ECERT;
            }
            if (memcmp(fingerprint, mtls->fingerprint, 20) != 0)
            {
                *errstr = xasprintf(_("%s: the certificate fingerprint "
                            "does not match"), error_msg);
                X509_free(x509cert);
                return TLS_ECERT;
            }
        }
        else
        {
            usize = 16;
            if (!X509_digest(x509cert, EVP_md5(), fingerprint, &usize))
            {
                *errstr = xasprintf(_("%s: error getting MD5 fingerprint"),
                        error_msg);
                X509_free(x509cert);
                return TLS_ECERT;
            }
            if (memcmp(fingerprint, mtls->fingerprint, 16) != 0)
            {
                *errstr = xasprintf(_("%s: the certificate fingerprint "
                            "does not match"), error_msg);
                X509_free(x509cert);
                return TLS_ECERT;
            }
        }
        X509_free(x509cert);
        return TLS_EOK;
    }

    /* Get result of OpenSSL's default verify function */
    if ((status = SSL_get_verify_result(mtls->internals->ssl)) != X509_V_OK)
    {
        if (mtls->have_trust_file
                || (status != X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
                    && status != X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
                    && status != X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN))
        {
            *errstr = xasprintf("%s: %s", error_msg,
                    X509_verify_cert_error_string(status));
            X509_free(x509cert);
            return TLS_ECERT;
        }
    }

    /* Check if 'hostname' matches the one of the subjectAltName extensions of
     * type DNS or the Common Name (CN). */

#ifdef HAVE_LIBIDN
    idn2_to_ascii_lz(mtls->hostname, &idn_hostname, IDN2_NFC_INPUT | IDN2_NONTRANSITIONAL);
#endif

    /* Try the DNS subjectAltNames. */
    match_found = 0;
    if ((subj_alt_names =
                X509_get_ext_d2i(x509cert, NID_subject_alt_name, NULL, NULL)))
    {
        subj_alt_names_count = sk_GENERAL_NAME_num(subj_alt_names);
        for (i = 0; i < subj_alt_names_count; i++)
        {
            subj_alt_name = sk_GENERAL_NAME_value(subj_alt_names, i);
            if (subj_alt_name->type == GEN_DNS)
            {
                if ((size_t)(subj_alt_name->d.ia5->length)
                        != strlen((char *)(subj_alt_name->d.ia5->data)))
                {
                    *errstr = xasprintf(_("%s: certificate subject "
                                "alternative name contains NUL"), error_msg);
                    X509_free(x509cert);
                    free(idn_hostname);
                    return TLS_ECERT;
                }
                if ((match_found = hostname_match(
                                idn_hostname ? idn_hostname : mtls->hostname,
                                (char *)(subj_alt_name->d.ia5->data))))
                {
                    break;
                }
            }
        }
    }
    if (!match_found)
    {
        /* Try the common name */
        if (!(x509_subject = X509_get_subject_name(x509cert)))
        {
            *errstr = xasprintf(_("%s: cannot get certificate subject"),
                    error_msg);
            X509_free(x509cert);
            free(idn_hostname);
            return TLS_ECERT;
        }
        length = X509_NAME_get_text_by_NID(x509_subject, NID_commonName,
                NULL, 0);
        buf = xmalloc((size_t)length + 1);
        if (X509_NAME_get_text_by_NID(x509_subject, NID_commonName,
                    buf, length + 1) == -1)
        {
            *errstr = xasprintf(_("%s: cannot get certificate common name"),
                    error_msg);
            X509_free(x509cert);
            free(idn_hostname);
            free(buf);
            return TLS_ECERT;
        }
        if ((size_t)length != strlen(buf))
        {
            *errstr = xasprintf(_("%s: certificate common name contains NUL"),
                    error_msg);
            X509_free(x509cert);
            free(idn_hostname);
            free(buf);
            return TLS_ECERT;
        }
        match_found = hostname_match(idn_hostname ? idn_hostname : mtls->hostname,
                buf);
        free(buf);
    }
    X509_free(x509cert);
    free(idn_hostname);

    if (!match_found)
    {
        *errstr = xasprintf(
                _("%s: the certificate owner does not match hostname %s"),
                error_msg, mtls->hostname);
        return TLS_ECERT;
    }

    return TLS_EOK;
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
    const SSL_METHOD *ssl_method = SSLv23_client_method();

    /* FIXME: Implement support for 'min_dh_prime_bits' */
    if (min_dh_prime_bits >= 0)
    {
        *errstr = xasprintf(
                _("cannot set minimum number of DH prime bits for TLS: %s"),
                _("feature not yet implemented for OpenSSL"));
        return TLS_ELIBFAILED;
    }
    /* FIXME: Implement support for 'priorities' */
    if (priorities)
    {
        *errstr = xasprintf(
                _("cannot set priorities for TLS session: %s"),
                _("feature not yet implemented for OpenSSL"));
        return TLS_ELIBFAILED;
    }
    /* FIXME: Implement support for 'crl_file' */
    if (trust_file && crl_file)
    {
        *errstr = xasprintf(
                _("cannot load CRL file: %s"),
                _("feature not yet implemented for OpenSSL"));
        return TLS_ELIBFAILED;
    }

    if (!ssl_method)
    {
        *errstr = xasprintf(_("cannot set TLS method"));
        return TLS_ELIBFAILED;
    }

    mtls->internals = xmalloc(sizeof(struct mtls_internals_t));

    if (!(mtls->internals->ssl_ctx = SSL_CTX_new(ssl_method)))
    {
        *errstr = xasprintf(_("cannot create TLS context: %s"),
                ERR_error_string(ERR_get_error(), NULL));
        free(mtls->internals);
        mtls->internals = NULL;
        return TLS_ELIBFAILED;
    }
    /* SSLv2 and SSLv3 have known flaws. Disable them. */
    (void)SSL_CTX_set_options(mtls->internals->ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    if (key_file && cert_file)
    {
        if (SSL_CTX_use_PrivateKey_file(
                    mtls->internals->ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1)
        {
            *errstr = xasprintf(_("cannot load key file %s: %s"),
                    key_file, ERR_error_string(ERR_get_error(), NULL));
            SSL_CTX_free(mtls->internals->ssl_ctx);
            free(mtls->internals);
            mtls->internals = NULL;
            return TLS_EFILE;
        }
        if (SSL_CTX_use_certificate_chain_file(mtls->internals->ssl_ctx, cert_file) != 1)
        {
            *errstr = xasprintf(_("cannot load certificate file %s: %s"),
                    cert_file, ERR_error_string(ERR_get_error(), NULL));
            SSL_CTX_free(mtls->internals->ssl_ctx);
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
            if (SSL_CTX_set_default_verify_paths(mtls->internals->ssl_ctx) != 1)
            {
                *errstr = xasprintf(_("cannot set X509 system trust for TLS session: %s"),
                        ERR_error_string(ERR_get_error(), NULL));
                SSL_CTX_free(mtls->internals->ssl_ctx);
                free(mtls->internals);
                mtls->internals = NULL;
                return TLS_EFILE;
            }
        }
        else
        {
            if (SSL_CTX_load_verify_locations(mtls->internals->ssl_ctx, trust_file, NULL) != 1)
            {
                *errstr = xasprintf(_("cannot load trust file %s: %s"),
                        trust_file, ERR_error_string(ERR_get_error(), NULL));
                SSL_CTX_free(mtls->internals->ssl_ctx);
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
    if (!(mtls->internals->ssl = SSL_new(mtls->internals->ssl_ctx)))
    {
        *errstr = xasprintf(_("cannot create a TLS structure: %s"),
                ERR_error_string(ERR_get_error(), NULL));
        SSL_CTX_free(mtls->internals->ssl_ctx);
        free(mtls->internals);
        mtls->internals = NULL;
        return TLS_ELIBFAILED;
    }
    mtls->no_certcheck = no_certcheck;
    mtls->hostname = xstrdup(hostname);
    return TLS_EOK;
}


/*
 * openssl_io_error()
 *
 * Used only internally by the OpenSSL code.
 *
 * Construct an error line according to 'error_code' (which originates from an
 * SSL_read(), SSL_write() or SSL_connect() operation) and 'error_code2' (which
 * originates from an SSL_get_error() call with 'error_code' as its argument).
 * The line will read: "error_string: error_reason". 'error_string' is given by
 * the calling function, this function finds out 'error_reason'.
 * The resulting string will be returned in an allocated string.
 * OpenSSL error strings are max 120 characters long according to
 * ERR_error_string(3).
 */

static char *openssl_io_error(int error_code, int error_code2,
        const char *error_string)
{
    unsigned long error_code3;
    const char *error_reason;

    switch (error_code2)
    {
        case SSL_ERROR_SYSCALL:
            error_code3 = ERR_get_error();
            if (error_code3 == 0)
            {
                if (error_code == 0)
                {
                    error_reason = _("a protocol violating EOF occurred");
                }
                else if (error_code == -1)
                {
                    error_reason = strerror(errno);
                }
                else
                {
                    error_reason = _("unknown error");
                }
            }
            else
            {
                error_reason = ERR_error_string(error_code3, NULL);
            }
            break;

        case SSL_ERROR_ZERO_RETURN:
            error_reason = _("the connection was closed unexpectedly");
            break;

        case SSL_ERROR_SSL:
            error_reason = ERR_error_string(ERR_get_error(), NULL);
            break;

        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            error_reason = _("the operation timed out");
            break;

        default:
            /* probably SSL_ERROR_NONE */
            error_reason = _("unknown error");
            break;
    }
    return xasprintf("%s: %s", error_string, error_reason);
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

    if (!SSL_set_fd(mtls->internals->ssl, fd))
    {
        *errstr = xasprintf(_("cannot set the file descriptor for TLS: %s"),
                ERR_error_string(ERR_get_error(), NULL));
        SSL_free(mtls->internals->ssl);
        SSL_CTX_free(mtls->internals->ssl_ctx);
        return TLS_ELIBFAILED;
    }
    if ((error_code = SSL_connect(mtls->internals->ssl)) < 1)
    {
        if (errno == EINTR
                && (SSL_get_error(mtls->internals->ssl, error_code) == SSL_ERROR_WANT_READ
                    || SSL_get_error(mtls->internals->ssl, error_code)
                    == SSL_ERROR_WANT_WRITE))
        {
            *errstr = xasprintf(_("operation aborted"));
        }
        else
        {
            *errstr = openssl_io_error(error_code,
                    SSL_get_error(mtls->internals->ssl, error_code),
                    _("TLS handshake failed"));
        }
        SSL_free(mtls->internals->ssl);
        SSL_CTX_free(mtls->internals->ssl_ctx);
        return TLS_EIO;
    }
    if (tci)
    {
        if ((error_code = mtls_cert_info_get(mtls, tci, errstr)) != TLS_EOK)
        {
            SSL_free(mtls->internals->ssl);
            SSL_CTX_free(mtls->internals->ssl_ctx);
            return error_code;
        }
    }
    if (mtls_parameter_description)
    {
        *mtls_parameter_description = NULL; /* TODO */
    }
    if (!mtls->no_certcheck)
    {
        if ((error_code = mtls_check_cert(mtls, errstr)) != TLS_EOK)
        {
            SSL_free(mtls->internals->ssl);
            SSL_CTX_free(mtls->internals->ssl_ctx);
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
    int ret;
    int error_code;

    if (readbuf->count <= 0)
    {
        ret = SSL_read(mtls->internals->ssl, readbuf->buf, sizeof(readbuf->buf));
        if (ret < 1)
        {
            if ((error_code = SSL_get_error(mtls->internals->ssl, ret)) == SSL_ERROR_NONE)
            {
                return 0;
            }
            else
            {
                if (errno == EINTR
                        && (SSL_get_error(mtls->internals->ssl, ret) == SSL_ERROR_WANT_READ
                            || SSL_get_error(mtls->internals->ssl, ret)
                            == SSL_ERROR_WANT_WRITE))
                {
                    *errstr = xasprintf(_("operation aborted"));
                }
                else
                {
                    *errstr = openssl_io_error(ret, error_code,
                            _("cannot read from TLS connection"));
                }
                return TLS_EIO;
            }
        }
        readbuf->count = ret;
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
    int error_code;

    if (len < 1)
    {
        /* nothing to be done */
        return TLS_EOK;
    }

    if ((error_code = SSL_write(mtls->internals->ssl, s, (int)len)) != (int)len)
    {
        if (errno == EINTR
                && ((SSL_get_error(mtls->internals->ssl, error_code) == SSL_ERROR_WANT_READ
                        || SSL_get_error(mtls->internals->ssl, error_code)
                        == SSL_ERROR_WANT_WRITE)))
        {
            *errstr = xasprintf(_("operation aborted"));
        }
        else
        {
            *errstr = openssl_io_error(error_code,
                    SSL_get_error(mtls->internals->ssl, error_code),
                    _("cannot write to TLS connection"));
        }
        return TLS_EIO;
    }

    return TLS_EOK;
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
        SSL_shutdown(mtls->internals->ssl);
        SSL_free(mtls->internals->ssl);
        SSL_CTX_free(mtls->internals->ssl_ctx);
    }
    free(mtls->internals);
    mtls->internals = NULL;
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
