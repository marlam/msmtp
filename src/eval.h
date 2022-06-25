/*
 * eval.h
 *
 * This file is part of msmtp, an SMTP client, and of mpop, a POP3 client.
 *
 * Copyright (C) 2019, 2020, 2021, 2022  Martin Lambers <marlam@marlam.de>
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

#ifndef EVAL_H
#define EVAL_H

/*
 * eval()
 *
 * Evaluates command in 'arg' and stores result in 'buf' (which is allocated).
 * Returns non-zero if command execution failed, otherwise zero. On error,
 * *errstr will contain an error string.
 */
int eval(const char *arg, char **buf, char **errstr);

#endif
