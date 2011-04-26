/*
 * md5-apps.c
 *
 * This file is part of msmtp, an SMTP client.
 *
 * This code was adapted from GNU Anubis, version 3.6.2
 * Copyright (C) 2001, 2002 The Anubis Team.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include "md5.h"
#include "md5-apps.h"


void md5_hmac(const char *secret, size_t secret_len,
        char *challenge, size_t challenge_len,
        unsigned char *digest)
{
    MD5_CTX context;
    unsigned char ipad[64];
    unsigned char opad[64];
    int i;

    memset(digest, 0, (size_t)16);
    memset(ipad, 0, sizeof(ipad));
    memset(opad, 0, sizeof(opad));

    if (secret_len > 64)
    {
        MD5_Init(&context);
        MD5_Update(&context, (unsigned char *)secret, secret_len);
        MD5_Final(ipad, &context);
        MD5_Final(opad, &context);
    }
    else
    {
        memcpy(ipad, secret, secret_len);
        memcpy(opad, secret, secret_len);
    }

    for (i = 0; i < 64; i++)
    {
        ipad[i] ^= 0x36;
        opad[i] ^= 0x5c;
    }

    MD5_Init(&context);
    MD5_Update(&context, ipad, (size_t)64);
    MD5_Update(&context, (unsigned char *)challenge, challenge_len);
    MD5_Final(digest, &context);

    MD5_Init(&context);
    MD5_Update(&context, opad, (size_t)64);
    MD5_Update(&context, digest, (size_t)16);
    MD5_Final(digest, &context);
}

void md5_digest(unsigned char *src, size_t srclen, char *dst)
{
    MD5_CTX context;
    unsigned char digest[16];
    char hex[] = "0123456789abcdef";
    int i;

    MD5_Init(&context);
    MD5_Update(&context, src, srclen);
    MD5_Final(digest, &context);

    for (i = 0; i < 16; i++)
    {
        dst[2 * i] = hex[(digest[i] & 0xf0) >> 4];
        dst[2 * i + 1] = hex[digest[i] & 0x0f];
    }
    dst[32] = '\0';
}
