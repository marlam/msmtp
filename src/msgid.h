/*
 * msgid.h
 *
 * This file is part of msmtp, an SMTP client.
 *
 * Copyright (C) 2022, 2023  Martin Lambers <marlam@marlam.de>
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

#ifndef MSGID_H
#define MSGID_H

/* Create a message id suitable for a Message-ID header and return it in an
 * allocated buffer.
 *
 * The id will contain the hash over some unique identifiying information
 * and a domain part (<hash@domain>).
 *
 * The domain part will be:
 * 1. The value of "domain", unless it is "localhost"
 * 2. Otherwise: the domain part of the envelope from address, if available
 * 3. Otherwise: the value of "host"
 */
char* create_msgid(const char* host, const char* domain, const char* envelope_from);

#endif
