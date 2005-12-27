/*
 * crypto.c
 *
 * This file is part of msmtp, an SMTP client.
 *
 * Copyright (C) 2005
 * Martin Lambers <marlam@marlam.de>
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
 *   along with this program; if not, write to the Free Software Foundation,
 *   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include "md5.h"


/* 
 * md5_hmac()
 *
 * see crypto.h
 */

void md5_hmac(const char *secret, size_t secret_len, 
	char *challenge, size_t challenge_len,
	unsigned char *digest)
{
    struct md5_ctx context;
    unsigned char ipad[64];
    unsigned char opad[64];
    int i;

    memset(digest, 0, (size_t)16);
    memset(ipad, 0, sizeof(ipad));
    memset(opad, 0, sizeof(opad));
    
    if (secret_len > 64) 
    {
	md5_init_ctx(&context);
	md5_process_bytes(secret, secret_len, &context);
	md5_finish_ctx(&context, ipad);
	md5_finish_ctx(&context, opad);
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
    
    md5_init_ctx(&context);
    md5_process_block(ipad, (size_t)64, &context);
    md5_process_bytes(challenge, challenge_len, &context);
    md5_finish_ctx(&context, digest);
    
    md5_init_ctx(&context);
    md5_process_block(opad, (size_t)64, &context);
    md5_process_bytes(digest, (size_t)16, &context);
    md5_finish_ctx(&context, digest);
}


/* 
 * md5_digest()
 * 
 * see crypto.h
 */

void md5_digest(unsigned char *src, size_t srclen, char *dst)
{
    struct md5_ctx context;
    unsigned char digest[16];
    char hex[] = "0123456789abcdef";
    int i;

    md5_init_ctx(&context);
    md5_process_bytes(src, srclen, &context);
    md5_finish_ctx(&context, digest);

    for (i = 0; i < 16; i++)
    {
	dst[2 * i] = hex[(digest[i] & 0xf0) >> 4];
	dst[2 * i + 1] = hex[digest[i] & 0x0f];
    }
    dst[32] = '\0';
}
