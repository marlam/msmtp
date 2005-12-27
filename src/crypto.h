/*
 * crypto.h
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

#ifndef CRYPTO_H
#define CRYPTO_H

/* 
 * md5_hmac()
 *
 * RFC 2104 
 */
void md5_hmac(const char *secret, size_t secret_len, 
	char *challenge, size_t challenge_len,
	unsigned char *digest);

/* 
 * md5_digest()
 * 
 * Writes the MD5 Digest of the data 'src' with the length 'srclen' in ascii 
 * (hex) to 'dst', which must be 33 characters long.
 */
void md5_digest(unsigned char *src, size_t srclen, char *dst);

#endif
