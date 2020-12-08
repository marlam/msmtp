/*
 * mtls-openssl.c
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

#include <tls.h>

#include "gettext.h"
#define _(string) gettext(string)
#define N_(string) gettext_noop(string)

#include "xalloc.h"
#include "readbuf.h"
#include "tools.h"
#include "mtls.h"


struct mtls_internals_t
{
    struct tls *tls_ctx;
};

/*
 * mtls_lib_init()
 *
 * see mtls.h
 */

int mtls_lib_init(char **errstr)
{
    if (tls_init() == -1)
    {
        *errstr = xasprintf("failed to initialize libtls");
        return TLS_ELIBFAILED;
    }

    return TLS_EOK;
}

/* libtls gives certificate fingerprints in a string formatted as
 * type:fingerprint. This function simply decodes this into the standard
 * binary representation.
 */
int decode_sha256(unsigned char *dest, char *src)
{
    char prefix[] = "SHA256:";
    unsigned char msn, lsn;

    if (dest == NULL || src == NULL)
    {
        return -1;
    }

    if (memcmp(src, prefix, sizeof(prefix)-1) != 0)
    {
        return -1;
    }

    for (int i = 0; i < 32; i++) 
    {
        msn = src[2*i + sizeof(prefix)-1];
        lsn = src[2*i + sizeof(prefix)];

        dest[i] = (isdigit(lsn) ? lsn - '0' : lsn - 'a' + 10) 
            + ((isdigit(msn) ? (msn - '0') : (msn - 'a' + 10)) << 4);
    }

    return 0;
}

/*
 * mtls_cert_info_get()
 *
 * see mtls.h
 */

int mtls_cert_info_get(mtls_t *mtls, mtls_cert_info_t *mtci, char **errstr)
{
    unsigned char *sha256_fingerprint;
    time_t notbefore, notafter;

    if ((sha256_fingerprint = 
                (char *)tls_peer_cert_hash(mtls->internals->tls_ctx))
                == NULL)
    {
        *errstr = xasprintf(_("Could not get certificate fingerprint: %s"),
                tls_error(mtls->internals->tls_ctx));
        return TLS_ECERT;
    }

    if (decode_sha256(mtci->sha256_fingerprint, sha256_fingerprint) != 0)
    {
        return TLS_ECERT;
    }

    if ((mtci->activation_time =
                tls_peer_cert_notbefore(mtls->internals->tls_ctx)) == -1)
    {
        *errstr = xasprintf(_("Could not get certificate activation: %s"),
                tls_error(mtls->internals->tls_ctx));
        return TLS_ECERT;
    }

    if ((mtci->expiration_time =
                tls_peer_cert_notafter(mtls->internals->tls_ctx)) == -1)
    {
        *errstr = xasprintf(_("Could not get certificate expiration: %s"),
                tls_error(mtls->internals->tls_ctx));
        return TLS_ECERT;
    }

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
    char *sha256_fingerprint_raw;
    char sha256_fingerprint[32];

    if (mtls->have_trust_file)
    {
        return TLS_EOK;
    }

    if (mtls->have_sha256_fingerprint)
    {
        if ((sha256_fingerprint_raw = 
                    (char *)tls_peer_cert_hash(mtls->internals->tls_ctx))
                    == NULL)
        {
            *errstr = xasprintf(_("Could not get certificate fingerprint: %s"),
                    tls_error(mtls->internals->tls_ctx));
            return TLS_ECERT;
        }

        if (decode_sha256(sha256_fingerprint, sha256_fingerprint_raw) == -1)
        {
            *errstr = xasprintf(_("Could not decode certificate fingerprint"));
            return TLS_ECERT;
        }

        if (memcmp(sha256_fingerprint, mtls->fingerprint, 32) != 0)
        {
            *errstr = xasprintf(_("Certificate fingerprints do not match"));
            return TLS_ECERT;
        }
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
    struct tls_config *config;

    if ((config = tls_config_new()) == NULL)
    {
        return TLS_ELIBFAILED;
    }

    if (key_file && cert_file)
    {
        if (tls_config_set_key_file(config, key_file) == -1)
            *errstr = xasprintf(_("tls_config failed: %s"),
                    tls_config_error(config));
            tls_config_free(config);
            return TLS_ELIBFAILED;

        if (tls_config_set_cert_file(config, cert_file) == -1)
            *errstr = xasprintf(_("tls_config failed: %s"),
                    tls_config_error(config));
            tls_config_free(config);
            return TLS_ELIBFAILED;
    }

    /* TODO what if sha1 or md5 is given? */
    if (no_certcheck)
    {
        tls_config_insecure_noverifycert(config);
    }
    else if (sha256_fingerprint && !no_certcheck)
    {
        tls_config_insecure_noverifycert(config);
        memcpy(mtls->fingerprint, sha256_fingerprint, 32);
        mtls->have_sha256_fingerprint = 1;
    }
    else if (trust_file && !no_certcheck)
    {
        if (tls_config_set_ca_file(config, trust_file) == -1)
        {
            *errstr = xasprintf(_("tls_config failed: %s"),
                    tls_config_error(config));
            tls_config_free(config);
            return TLS_ELIBFAILED;
        }

        mtls->have_trust_file = 1;
    }

    if (crl_file && tls_config_set_crl_file(config, crl_file) == -1)
    {
        *errstr = xasprintf(_("tls_config failed: %s"),
                tls_config_error(config));
        tls_config_free(config);
        return TLS_ELIBFAILED;
    }

    mtls->internals = xmalloc(sizeof(struct mtls_internals_t));

    if ((mtls->internals->tls_ctx = tls_client()) == NULL) 
    {
        *errstr = xasprintf(_("couldn't init tls_client"));
        tls_config_free(config);
        free(mtls->internals);
        mtls->internals = NULL;
        return TLS_ELIBFAILED;
    }

    if (tls_configure(mtls->internals->tls_ctx, config) == -1)
    {
        *errstr = xasprintf(_("Could not configure TLS client: %s"),
                tls_config_error(config));
        tls_free(mtls->internals->tls_ctx);
        tls_config_free(config);
        free(mtls->internals);
        mtls->internals = NULL;
        return TLS_ELIBFAILED;
    }

    tls_config_free(config);
    mtls->hostname = xstrdup(hostname);
    mtls->no_certcheck = no_certcheck;
    return TLS_EOK;
}

/*
 * mtls_start()
 *
 * see mtls.h
 */

int mtls_start(mtls_t *mtls, int fd,
        mtls_cert_info_t *mtci, char **mtls_parameter_description, char **errstr)
{
    int error_code;

    if (tls_connect_socket(mtls->internals->tls_ctx, fd, mtls->hostname) == -1) 
    {
        *errstr = xasprintf(_("tls_connect failed: %s"),
                tls_error(mtls->internals->tls_ctx));
        tls_free(mtls->internals->tls_ctx);
        return TLS_EHANDSHAKE;
    }

    if (tls_handshake(mtls->internals->tls_ctx) == -1) 
    {
        tls_close(mtls->internals->tls_ctx);
        tls_free(mtls->internals->tls_ctx);
        *errstr = xasprintf(_("tls_handshake failed: %s"),
                tls_error(mtls->internals->tls_ctx));
        return TLS_EHANDSHAKE;
    }

    if (!mtls->no_certcheck)
    {
        if ((error_code = mtls_check_cert(mtls, errstr)) != TLS_EOK)
        {
            tls_close(mtls->internals->tls_ctx);
            tls_free(mtls->internals->tls_ctx);
            return error_code;
        }
    }

    if (mtls_parameter_description)
    {
        *mtls_parameter_description = NULL; /* TODO */
    }

    if (mtci)
    {
        if ((error_code = mtls_cert_info_get(mtls, mtci, errstr)) != TLS_EOK)
        {
            *errstr = xasprintf(_("couldn't get cert info"));
            tls_close(mtls->internals->tls_ctx);
            tls_free(mtls->internals->tls_ctx);
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

    /* immediately run `tls_read` again for TLS_WANT* */
    while (readbuf->count <= 0)
    {
        ret = tls_read(mtls->internals->tls_ctx, readbuf->buf,
                sizeof(readbuf->buf));
        if (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT)
        {
            continue;
        } 
        else if (ret == -1)
        {
            *errstr = xasprintf(_("tls_read failed: %s"),
                    tls_error(mtls->internals->tls_ctx));
            return TLS_EIO;
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
    while (len > 0) 
    {
        ssize_t ret;
        ret = tls_write(mtls->internals->tls_ctx, s, len);

        if (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT)
        {
            continue;
        }
        if (ret == -1)
        {
            *errstr = xasprintf(_("tls_write: %s"),
                    tls_error(mtls->internals->tls_ctx));
            return TLS_EIO;
        }
        s += ret;
        len -= ret;
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
        tls_close(mtls->internals->tls_ctx);
        tls_free(mtls->internals->tls_ctx);
        mtls->internals->tls_ctx = NULL;
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
