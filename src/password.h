/*
 * password.h
 *
 * This file is part of msmtp, an SMTP client, and of mpop, a POP3 client.
 *
 * Copyright (C) 2019, 2020, 2021  Martin Lambers <marlam@marlam.de>
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

#ifndef PASSWORD_H
#define PASSWORD_H

typedef enum {
    password_service_smtp,
    password_service_pop3
} password_service_t;

/*
 * password_get()
 *
 * This function tries to get a password for service::user@hostname.
 * It tries to get it from the system's keychain (if available).
 * If that fails and consult_netrc is set, it tries to read a password from .netrc.
 * If that fails, it tries to read a password via getpass().
 * If getpass_only_via_tty is set, then getpass() will only be called
 * if it reads from /dev/tty instead of stdin.
 * This function returns NULL on failure or the password in an allocated
 * buffer.
 */
char *password_get(const char *hostname, const char *user,
        password_service_t service,
        int consult_netrc,
        int getpass_only_via_tty);

#endif
