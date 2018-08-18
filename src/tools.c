/*
 * tools.c
 *
 * This file is part of msmtp, an SMTP client.
 *
 * Copyright (C) 2004, 2005, 2006, 2007, 2009, 2011, 2014, 2018
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

#ifdef W32_NATIVE
# define WIN32_LEAN_AND_MEAN    /* do not include more than necessary */
# define _WIN32_WINNT 0x0601    /* Windows 7 or later */
# include <windows.h>
# include <io.h>
# include <conio.h>
# include <lmcons.h>
# include <sys/locking.h>
# include <limits.h>
#else
# include <pwd.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "xalloc.h"
#include "tools.h"


/*
 * link()
 *
 * A link replacement, currently only for W32.
 */
#ifndef HAVE_LINK
# if W32_NATIVE
int link(const char *path1, const char *path2)
{
    if (CreateHardLink(path2, path1, NULL) == 0)
    {
        /* It is not documented which errors CreateHardLink() can produce.
         * The following conversions are based on tests on a Windows XP SP2
         * system. */
        DWORD err = GetLastError();
        switch (err)
        {
            case ERROR_ACCESS_DENIED:
                errno = EACCES;
                break;

            case ERROR_INVALID_FUNCTION:        /* fs does not support hard links */
                errno = EPERM;
                break;

            case ERROR_NOT_SAME_DEVICE:
                errno = EXDEV;
                break;

            case ERROR_PATH_NOT_FOUND:
            case ERROR_FILE_NOT_FOUND:
                errno = ENOENT;
                break;

            case ERROR_INVALID_PARAMETER:
                errno = ENAMETOOLONG;
                break;

            case ERROR_TOO_MANY_LINKS:
                errno = EMLINK;
                break;

            case ERROR_ALREADY_EXISTS:
                errno = EEXIST;
                break;

            default:
                errno = EIO;
        }
        return -1;
    }

    return 0;
}
# endif
#endif

/*
 * getpass()
 *
 * A getpass replacement, currently only for W32.
 * Taken from gnulib on 2011-03-20.
 * Original copyright:
 * Windows implementation by Martin Lambers <marlam@marlam.de>,
 * improved by Simon Josefsson.
 */
#ifndef HAVE_GETPASS
# if W32_NATIVE
char *getpass(const char *prompt)
{
    const size_t pass_max = 512;
    char getpassbuf[pass_max + 1];
    size_t i = 0;
    int c;

    if (prompt)
    {
        fputs(prompt, stderr);
        fflush(stderr);
    }

    for (;;)
    {
        c = _getch ();
        if (c == '\r')
        {
            getpassbuf[i] = '\0';
            break;
        }
        else if (i < pass_max)
        {
            getpassbuf[i++] = c;
        }

        if (i >= pass_max)
        {
            getpassbuf[i] = '\0';
            break;
        }
    }

    if (prompt)
    {
        fputs ("\r\n", stderr);
        fflush (stderr);
    }

    return strdup(getpassbuf);
}
# endif
#endif


/*
 * get_prgname()
 *
 * see tools.h
 */

const char *get_prgname(const char *argv0)
{
    const char *prgname;

    if (argv0)
    {
        prgname = strrchr(argv0, PATH_SEP);
        if (!prgname)
        {
            prgname = argv0;
        }
        else
        {
            prgname++;
        }
    }
    else
    {
        prgname = "";
    }

    return prgname;
}


/*
 * get_sysconfdir()
 *
 * see tools.h
 */

char *get_sysconfdir(void)
{
#ifdef W32_NATIVE

    BYTE sysconfdir[MAX_PATH + 1];
    HKEY hkey;
    DWORD len;
    DWORD type;
    long l;

    l = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\"
            "Shell Folders", 0, KEY_READ, &hkey);
    if (l != ERROR_SUCCESS)
    {
        return xstrdup("C:");
    }
    len = MAX_PATH;
    l = RegQueryValueEx(hkey, "Common AppData", NULL, &type, sysconfdir, &len);
    if (l != ERROR_SUCCESS || len >= MAX_PATH)
    {
        if (l != ERROR_SUCCESS || len >= MAX_PATH)
        {
            return xstrdup("C:");
        }
    }
    RegCloseKey(hkey);
    return xstrdup((char *)sysconfdir);

#else /* UNIX */

#ifdef SYSCONFDIR
    return xstrdup(SYSCONFDIR);
#else
    return xstrdup("/etc");
#endif

#endif
}


/*
 * get_username()
 *
 * see tools.h
 */

char *get_username(void)
{
    char *username;
#ifdef W32_NATIVE
    DWORD size = UNLEN + 1;
    TCHAR buf[UNLEN + 1];
#else /* UNIX */
    struct passwd *pw;
#endif

    username = getenv("USER");
    if (username)
    {
        username = xstrdup(username);
    }
    else
    {
        username = getenv("LOGNAME");
        if (username)
        {
            username = xstrdup(username);
        }
        else
        {
#ifdef W32_NATIVE
            if (GetUserName(buf, &size))
            {
                username = xstrdup((char *)buf);
            }
            else
            {
                /* last resort */
                username = xstrdup("unknown");
            }
#else /* UNIX */
            username = getlogin();
            if (username)
            {
                username = xstrdup(username);
            }
            else
            {
                pw = getpwuid(getuid());
                if (pw && pw->pw_name)
                {
                    username = xstrdup(pw->pw_name);
                }
                else
                {
                    /* last resort */
                    username = xstrdup("unknown");
                }
            }
#endif
        }
    }

    return username;
}

char *get_userconfig(const char *userconfigfile)
{
    char *homedir = get_homedir();
    char *path = get_filename(homedir, userconfigfile);

#if !defined(W32_NATIVE)
    struct stat buf;
    char *xdg_home;
    char *newpath;

    //does not exist, thus check XDG_CONFIG_HOME/PACKAGE_NAME/config
    if (stat(path, &buf) != 0) {
        xdg_home = getenv("XDG_CONFIG_HOME");
        if (xdg_home) {
            xdg_home = xstrdup(xdg_home);
        } else {
            xdg_home = expand_tilde("~/.config");
        }
        newpath = get_filename(xdg_home, PACKAGE_NAME);
        free(xdg_home);
        xdg_home = get_filename(newpath, "config");
        free(newpath);
        newpath = xdg_home;
        //If this does not exist fallback
        if (stat(newpath, &buf) == 0) {
            free(path);
            path = newpath;
        } else {
            free(newpath);
        }
    }
#endif

    free(homedir);
    return path;
}


/*
 * get_homedir()
 *
 * see tools.h
 */

char *get_homedir(void)
{
#ifdef W32_NATIVE

    char *home;
    BYTE homebuf[MAX_PATH + 1];
    HKEY hkey;
    DWORD len;
    DWORD type;
    long l;

    if ((home = getenv("HOME")))
    {
        home = xstrdup(home);
    }
    else
    {
        home = NULL;
        l = RegOpenKeyEx(HKEY_CURRENT_USER,
                "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\"
                "Shell Folders", 0, KEY_READ, &hkey);
        if (l == ERROR_SUCCESS)
        {
            len = MAX_PATH;
            l = RegQueryValueEx(hkey, "AppData", NULL, &type, homebuf, &len);
            if (l == ERROR_SUCCESS && len < MAX_PATH)
            {
                RegCloseKey(hkey);
                home = xstrdup((char *)homebuf);
            }
        }
        if (!home)
        {
            home = xstrdup("C:");
        }
    }

    return home;

#else /* UNIX */

    char *home;
    struct passwd *pw;

    if ((home = getenv("HOME")))
    {
        home = xstrdup(home);
    }
    else
    {
        pw = getpwuid(getuid());
        if (pw && pw->pw_dir)
        {
            home = xstrdup(pw->pw_dir);
        }
        else
        {
            home = xstrdup("");
        }
    }

    return home;

#endif
}


/*
 * get_filename()
 *
 * see tools.h
 */

char *get_filename(const char *directory, const char *name)
{
    char *path;
    size_t dirlen;

    dirlen = strlen(directory);
    path = xmalloc((dirlen + strlen(name) + 2) * sizeof(char));
    strcpy(path, directory);
    if (dirlen == 0 || path[dirlen - 1] != PATH_SEP)
    {
        path[dirlen++] = PATH_SEP;
    }
    strcpy(path + dirlen, name);

    return path;
}


/*
 * expand_tilde()
 *
 * see tools.h
 */

char *expand_tilde(const char *filename)
{
    char *new_filename;
    size_t homedirlen;

    if (filename[0] == '~')
    {
        new_filename = get_homedir();
        homedirlen = strlen(new_filename);
        new_filename = xrealloc(new_filename,
                (homedirlen + strlen(filename)) * sizeof(char));
        strcpy(new_filename + homedirlen, filename + 1);
        return new_filename;
    }
    else
    {
        return xstrdup(filename);
    }
}


/*
 * check_secure()
 *
 * see tools.h
 */

int check_secure(const char *pathname)
{
#if defined W32_NATIVE || defined __CYGWIN__

    return 0;

#else /* UNIX */

    struct stat statbuf;

    if (stat(pathname, &statbuf) < 0)
    {
        return 3;
    }

    if (statbuf.st_uid != geteuid())
    {
        return 1;
    }
    if (statbuf.st_mode & (S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP
                | S_IROTH | S_IWOTH | S_IXOTH))
    {
        return 2;
    }

    return 0;

#endif /* UNIX */
}


/*
 * lock_file()
 *
 * see tools.h
 */

/* Helper function that sleeps for the tenth of a second */
static void sleep_tenth_second(void)
{
#ifdef W32_NATIVE
    Sleep(100);
#else /* POSIX */
    struct timespec tenth_second = { 0, 100000000 };
    nanosleep(&tenth_second, NULL);
#endif
}

int lock_file(FILE *f, int lock_type, int timeout)
{
    int fd;
    int lock_success;
    int tenth_seconds;
#ifndef W32_NATIVE
    struct flock lock;
#endif /* not W32_NATIVE */

    fd = fileno(f);
#ifndef W32_NATIVE
    lock.l_type = (lock_type == TOOLS_LOCK_WRITE) ? F_WRLCK : F_RDLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0;
#endif /* not W32_NATIVE */
    tenth_seconds = 0;
    for (;;)
    {
        errno = 0;
#ifdef W32_NATIVE
        lock_success = (_locking(fd, _LK_NBLCK, LONG_MAX) != -1);
#else /* UNIX */
        lock_success = (fcntl(fd, F_SETLK, &lock) != -1);
#endif
        if (lock_success || (errno != EACCES && errno != EAGAIN)
            || tenth_seconds / 10 >= timeout)
        {
            break;
        }
        else
        {
            sleep_tenth_second();
            tenth_seconds++;
        }
    }
    return (lock_success ? 0 : (tenth_seconds / 10 >= timeout ? 1 : 2));
}


/*
 * string_replace()
 *
 * see tools.h
 */

char *string_replace(char *str, const char *s, const char *r)
{
    char *p, *new_str;
    size_t next_pos = 0;
    size_t slen = strlen(s);
    size_t rlen = strlen(r);

    while ((p = strstr(str + next_pos, s)))
    {
        new_str = xmalloc((strlen(str) + rlen - 1) * sizeof(char));
        strncpy(new_str, str, (size_t)(p - str));
        strcpy(new_str + (size_t)(p - str), r);
        strcpy(new_str + (size_t)(p - str) + rlen,
                str + (size_t)(p - str) + slen);
        next_pos = (size_t)(p - str) + rlen;
        free(str);
        str = new_str;
    }
    return str;
}

/*
 * print_time_rfc2822()
 *
 * see tools.h
 */

void print_time_rfc2822(time_t t, char rfc2822_timestamp[32])
{
    /* Calculate a RFC 2822 timestamp. strftime() is unreliable for this because
     * it is locale dependant, and because the timezone offset conversion
     * specifier %z is not portable. */
    struct tm gmt, *lt;
    char tz_offset_sign;
    int tz_offset_hours;
    int tz_offset_minutes;
    const char *weekday[7] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri",
        "Sat" };
    const char *month[12] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul",
        "Aug", "Sep", "Oct", "Nov", "Dec" };

    /* copy the struct tm, because the subsequent call to localtime() will
     * overwrite it */
    gmt = *gmtime(&t);
    lt = localtime(&t);
    tz_offset_minutes = (lt->tm_hour - gmt.tm_hour) * 60
        + lt->tm_min - gmt.tm_min
        + (lt->tm_year - gmt.tm_year) * 24 * 60
        + (lt->tm_yday - gmt.tm_yday) * 24 * 60;
    if (tz_offset_minutes < 0)
    {
        tz_offset_sign = '-';
        tz_offset_minutes = -tz_offset_minutes;
    }
    else
    {
        tz_offset_sign = '+';
    }
    tz_offset_hours = tz_offset_minutes / 60;
    tz_offset_minutes %= 60;
    if (tz_offset_hours > 99)
    {
        /* Values equal to or larger than 24 are not meaningful, but we just
         * make sure that the value fits into two digits. If the system time is
         * broken, we cannot fix it. */
        tz_offset_hours = 99;
    }
    (void)snprintf(rfc2822_timestamp, 32,
            "%s, %02d %s %04d %02d:%02d:%02d %c%02d%02d",
            weekday[lt->tm_wday], lt->tm_mday, month[lt->tm_mon],
            lt->tm_year + 1900, lt->tm_hour, lt->tm_min, lt->tm_sec,
            tz_offset_sign, tz_offset_hours, tz_offset_minutes);
}
