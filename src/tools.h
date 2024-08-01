/*
 * tools.h
 *
 * This file is part of msmtp, an SMTP client, and of mpop, a POP3 client.
 *
 * Copyright (C) 2004, 2005, 2006, 2007, 2011, 2014, 2018, 2019, 2020, 2021,
 * 2022, 2023, 2024
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

#ifndef TOOLS_H
#define TOOLS_H

#include <stdio.h>
#include <time.h> /* time_t */

#ifdef HAVE_SYSEXITS_H
# include <sysexits.h>
#else
/* exit() exit codes for some BSD system programs.
   Copyright (C) 2003, 2006-2011 Free Software Foundation, Inc.
   Written by Simon Josefsson based on sysexits(3) man page */
# define EX_OK 0 /* same value as EXIT_SUCCESS */
# define EX_USAGE 64
# define EX_DATAERR 65
# define EX_NOINPUT 66
# define EX_NOUSER 67
# define EX_NOHOST 68
# define EX_UNAVAILABLE 69
# define EX_SOFTWARE 70
# define EX_OSERR 71
# define EX_OSFILE 72
# define EX_CANTCREAT 73
# define EX_IOERR 74
# define EX_TEMPFAIL 75
# define EX_PROTOCOL 76
# define EX_NOPERM 77
# define EX_CONFIG 78
#endif

#ifndef HAVE_FSEEKO
# ifdef HAVE_FSEEKO64
#  define fseeko(s,o,w) fseeko64(s,o,w)
# else
#  define fseeko(s,o,w) fseek(s,o,w)
# endif
#endif

/* The path separator character */
#ifdef W32_NATIVE
# define PATH_SEP '\\'
#else
# define PATH_SEP '/'
#endif


/*
 * exitcode_to_string()
 *
 * Return the name of a sysexits.h exitcode
 */
const char *exitcode_to_string(int exitcode);

/*
 * tmpfile() - only for Windows systems where the native tmpfile() is broken
 */
#ifdef W32_NATIVE
#define tmpfile() w32_tmpfile()
FILE *w32_tmpfile(void);
#endif

/*
 * link() - only for systems that lack it
 */
#ifndef HAVE_LINK
int link(const char *path1, const char *path2);
#endif

/*
 * getpass() - only for systems that lack it
 */
#ifndef HAVE_GETPASS
char *getpass(const char *prompt);
#endif

/*
 * get_prgname()
 *
 * Get the program name from an argv[0]-like string.
 * Returns a pointer to a static buffer.
 */
const char *get_prgname(const char *argv0);

/*
 * get_sysconfdir()
 *
 * Get the system configuration directory (or something similar, depending
 * on the OS). Returns a pointer to an allocated string.
 * Cannot fail because it uses safe defaults as fallback.
 */
char *get_sysconfdir(void);

/*
 * get_username()
 *
 * Get the name (login name) of the current user. The returned string is
 * allocated.
 * The returned string may come from a environment variable and may contain
 * all sorts of rubbish!
 */
char *get_username(void);

/*
 * get_hostname()
 *
 * Get the name of the host. The returned string is allocated.
 * The returned string may come from a environment variable and may contain
 * all sorts of rubbish!
 */
char *get_hostname(void);

/*
 * get_userconfig()
 *
 * Get the path of the user config. The returned string is allocated.
 * On windows like systems it will return ~/USERCONFFILE, in unix like systems
 * it will return the first found file at the following locations:
 * - ~/USERCONFFILE
 * - $XDG_CONFIG_DIR/PACKAGE_NAME/config
 * - ~/.config/PACKAGE_NAME/config
 */
char *get_userconfig(const char *userconfigfile);

/*
 * get_homedir()
 *
 * Get the users home directory (or something similar, depending on the OS).
 * Returns a pointer to an allocated string.
 * Cannot fail because it uses safe defaults as fallback.
 */
char *get_homedir(void);

/*
 * get_filename()
 *
 * Get the name of file from two components:
 * 1) The directory containing the file.
 * 2) The name of the file.
 * The returned string is allocated.
 */
char *get_filename(const char *directory, const char *name);

/*
 * expand_tilde()
 *
 * Return a new filename in an allocated string, which differs from 'filename'
 * in the following way:
 * If the first character of 'filename' is '~', it will be replaced by
 * the user's home directory.
 * If the first character of 'filename' is not '~', the returned string
 * will simply be a copy of 'filename'.
 */
char *expand_tilde(const char *filename);

/*
 * check_secure()
 *
 * Checks whether the given file
 * 1) is owned by the current user
 * 2) has permissions no more than 0600
 * The return value is
 * 0 if both conditions are met
 * 1 if condition 1) is not met
 * 2 if condition 2) is not met
 * 3 if an error occurred (errno will be set in this case)
 */
int check_secure(const char *pathname);

/*
 * lock_file()
 *
 * Locks a file for reading (if lock_type is TOOLS_LOCK_READ) or writing (if
 * lock_type is TOOLS_LOCK_WRITE). Returns 0 in case of success, 1 if the file
 * could not be locked before the given timeout (in seconds) because some other
 * process holds a lock on the file, and 2 if the file could not be locked due
 * to some other error. If 1 or 2 is returned, errno will be set.
 */
#define TOOLS_LOCK_READ 0
#define TOOLS_LOCK_WRITE 1
int lock_file(FILE *f, int lock_type, int timeout);

/*
 * string_replace()
 *
 * Replace all occurrences of 's' in the string 'str' with 'r'.
 * The string 'str' must be an allocated string. A pointer to the expanded
 * string is returned.
 */
char *string_replace(char *str, const char *s, const char *r);

/*
 * sanitize_string()
 *
 * Replaces all control characters in the string with a question mark
 */
char *sanitize_string(char *str);

/*
 * token_in_string()
 *
 * Checks if a given token can be found in a list of space-separated tokens.
 * This function makes sure that the token is not just found as a substring of
 * another token. The string may optionally end with '\r\n'.
 */
int token_in_string(const char *string, const char *token);

/*
 * print_fingerprint()
 *
 * Prints a fingerprint of the given length in bytes in hexadecimal form into a
 * buffer. Each input byte is transformed to three output characters (the last
 * one is '\0').
 */
void print_fingerprint(char *s, const unsigned char *fingerprint, size_t len);

/*
 * print_time_rfc2822()
 *
 * Print the given time stamp in RFC2822 format into the given buffer.
 */
void print_time_rfc2822(time_t t, char rfc2822_timestamp[32]);

/*
 * split_mail_address()
 *
 * Splits a mail address into a local part (before the last '@') and a domain
 * part (after the last '@'). The returned domain_part pointer may be NULL if
 * there is no '@' in the address, and both local and domain part may be empty.
 */
void split_mail_address(const char *address, char **local_part, char **domain_part);

/*
 * check_hostname_matches_domain()
 *
 * Checks whether the given host name is within the given domain.
 */
int check_hostname_matches_domain(const char *hostname, const char *domain);

#endif
