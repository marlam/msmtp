/*
 * tools.c
 *
 * This file is part of msmtp, an SMTP client.
 *
 * Copyright (C) 2004, 2005, 2006, 2007, 2009, 2011
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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#ifdef W32_NATIVE
# define WIN32_LEAN_AND_MEAN    /* do not include more than necessary */
# define _WIN32_WINNT 0x0502    /* Windows XP SP2 or later */
# include <windows.h>
# include <io.h>
# include <conio.h>
# include <lmcons.h>
# include <sys/locking.h>
# include <limits.h>
#else
# include <pwd.h>
#endif

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

#else /* UNIX or DJGPP */

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
#elif defined DJGPP
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
#elif defined DJGPP
            /* DJGPP's getlogin() checks USER, then LOGNAME, and then uses
             * "dosuser" as a last resort. We already checked USER and LOGNAME
             * and choose "unknown" as a last resort to be consistent with the
             * other systems. */
            username = xstrdup("unknown");
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

#elif defined DJGPP

    char *home;

    if ((home = getenv("HOME")))
    {
        home = xstrdup(home);
    }
    else
    {
        home = xstrdup("C:");
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
#if defined W32_NATIVE || defined DJGPP || defined __CYGWIN__

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
 * [DJGPP and Windows only] mymkstemp()
 *
 * This function does on DOS/Windows what mkstemp() followed by unlink() do on
 * UNIX.
 *
 * 1. unlink() on DOS and Windows is not POSIX conformant: it does not wait
 *    until the last file descriptor is closed before unlinking the file.
 *    Instead, it fails (Windows) or may even mess up the file system (DOS).
 * 2. Windows does not have mkstemp.
 * 3. If a file is opened with O_TEMPORARY on Windows or DOS, it will be deleted
 *    after the last file descriptor is closed. This is what this function does.
 *
 * Return value: file descriptor, or -1 on error (errno will be set).
 */

#if defined(W32_NATIVE) || defined(DJGPP)
int mymkstemp(char *template, int remove_on_close)
{
    size_t templatelen;
    char *X;
    int i;
    int try;
    int ret;
    const char alnum[]
        = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
#ifdef W32_NATIVE
    int temporary_flag = (remove_on_close ? _O_TEMPORARY : 0);
#else /* DJGPP */
    int temporary_flag = (remove_on_close ? O_TEMPORARY : 0);
#endif /* DJGPP */

    templatelen = strlen(template);
    if (templatelen < 6)
    {
        errno = EINVAL;
        return -1;
    }
    X = template + templatelen - 6;
    if (strcmp(X, "XXXXXX") != 0)
    {
        errno = EINVAL;
        return -1;
    }

    srand((unsigned int)time(NULL));

    /* We have 62^6 possible filenames. We try 62^2=3844 times. */
    ret = -1;
    for (try = 0; ret == -1 && try < 3844; try++)
    {
        for (i = 0; i < 6; i++)
        {
            X[i] = alnum[rand() % 36];
        }
#ifdef W32_NATIVE
        ret = _open(template, _O_CREAT | _O_EXCL | _O_RDWR | _O_BINARY
                | temporary_flag, _S_IREAD | _S_IWRITE);
#else /* DJGPP */
        ret = open(template, O_CREAT | O_EXCL | O_RDWR | _O_BINARY
                | temporary_flag, S_IRUSR | S_IWUSR);
#endif /* DJGPP */
    }

    return ret;
}
#endif /* W32_NATIVE or DJGPP */

#ifndef HAVE_MKSTEMP
# if defined(W32_NATIVE) || defined(DJGPP)
int mkstemp(char *template)
{
    return mymkstemp(template, 0);
}
# endif
#endif


/*
 * tempfile()
 *
 * see tools.h
 */

FILE *tempfile(const char *base)
{
    FILE *f;
    size_t baselen;
    const char *dir;
    size_t dirlen;
    char *template = NULL;
    size_t templatelen;
    int fd = -1;
    int saved_errno;

    if (!base || (*base == '\0'))
    {
        base = "tmp";
    }
    /* the directory for the temp file */
    if (!(dir = getenv("TMPDIR")))
    {
        /* system dependent default location */
#ifdef W32_NATIVE
        /* there is no registry key for this (?) */
        if (!(dir = getenv("TEMP")))
        {
            if (!(dir = getenv("TMP")))
            {
                dir = "C:";
            }
        }
#elif defined DJGPP
        dir = "C:";
#else /* UNIX */
#ifdef P_tmpdir
        dir = P_tmpdir;
#else
        dir = "/tmp";
#endif
#endif /* UNIX */
    }
    dirlen = strlen(dir);

    /* the proposed file name */
    baselen = strlen(base);
#ifdef DJGPP
    /* shorten the base to two characters because of 8.3 filenames */
    if (baselen > 2)
    {
        baselen = 2;
    }
#endif

    /* build the template */
    templatelen = dirlen + 1 + baselen + 6;
    template = xmalloc((templatelen + 1) * sizeof(char));
    strncpy(template, dir, dirlen);
    if (dirlen == 0 || template[dirlen - 1] != PATH_SEP)
    {
        template[dirlen++] = PATH_SEP;
    }
    /* template is long enough */
    strncpy(template + dirlen, base, baselen);
    strcpy(template + dirlen + baselen, "XXXXXX");

    /* create the file */
#if defined(W32_NATIVE) || defined(DJGPP)
    if ((fd = mymkstemp(template, 1)) == -1)
#else /* UNIX */
    if ((fd = mkstemp(template)) == -1)
#endif /* UNIX */
    {
        goto error_exit;
    }

    /* UNIX only: set the permissions (not every mkstemp() sets them to 0600)
     * and unlink the file so that it gets deleted when the caller closes it */
#ifndef DJGPP
#ifndef W32_NATIVE
    if (fchmod(fd, S_IRUSR | S_IWUSR) == -1)
    {
        goto error_exit;
    }
    if (unlink(template) != 0)
    {
        goto error_exit;
    }
#endif /* not W32_NATIVE */
#endif /* not DJGPP */

    /* get the stream from the filedescriptor */
    if (!(f = fdopen(fd, "w+")))
    {
        goto error_exit;
    }
    free(template);

    return f;

error_exit:
    saved_errno = errno;
    if (fd >= 0)
    {
        close(fd);
    }
    if (template)
    {
        (void)remove(template);
        free(template);
    }
    errno = saved_errno;
    return NULL;
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
#elif defined DJGPP
    usleep(100000);
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
#else /* UNIX, DJGPP */
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
