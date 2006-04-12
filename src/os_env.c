/*
 * os_env.c
 *
 * This file is part of msmtp, an SMTP client.
 *
 * Copyright (C) 2004, 2005, 2006
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
extern int errno;
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#include <lmcons.h>
#include <sys/locking.h>
#include <limits.h>
#elif defined DJGPP
#include <unistd.h>
#else /* UNIX */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <pwd.h>
#endif /* UNIX */

#include "xalloc.h"
#include "timespec.h"

#include "os_env.h"


/*
 * get_prgname()
 *
 * see os_env.h
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
 * see os_env.h
 */

char *get_sysconfdir(void)
{
#ifdef _WIN32

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
 * see os_env.h
 */

char *get_username(void)
{
    char *username;
#ifdef _WIN32
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
#ifdef _WIN32
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
 * see os_env.h
 */

char *get_homedir(void)
{
#ifdef _WIN32

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
 * see os_env.h
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
 * see os_env.h
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
 * see os_env.h
 */

int check_secure(const char *pathname)
{
#if defined(_WIN32) || defined(DJGPP)
    
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
 * [DJGPP and Windows only] mkstemp_unlink()
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

#if defined(_WIN32) || defined(DJGPP)
int mkstemp_unlink(char *template)
{
    size_t templatelen;
    char *X;
    int i;
    int try;
    int ret;
    const char alnum[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"; 

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
#ifdef _WIN32
	ret = _open(template, _O_CREAT | _O_EXCL | _O_RDWR | _O_TEMPORARY | _O_BINARY, 
		_S_IREAD | _S_IWRITE);
#else /* DJGPP */
	ret = open(template, O_CREAT | O_EXCL | O_RDWR | O_TEMPORARY | _O_BINARY, 
		S_IRUSR | S_IWUSR);
#endif /* DJGPP */
    }

    return ret;
}
#endif /* _WIN32 or DJGPP */


/*
 * tempfile()
 *
 * see os_env.h
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
#ifdef _WIN32
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
#if defined(_WIN32) || defined(DJGPP)
    if ((fd = mkstemp_unlink(template)) == -1)
#else /* UNIX */
    if ((fd = mkstemp(template)) == -1)
#endif /* UNIX */
    {
	goto error_exit;
    }

    /* UNIX only: set the permissions (not every mkstemp() sets them to 0600)
     * and unlink the file so that it gets deleted when the caller closes it */
#ifndef DJGPP
#ifndef _WIN32
    if (fchmod(fd, S_IRUSR | S_IWUSR) == -1)
    {
	goto error_exit;
    }
    if (unlink(template) != 0)
    {
	goto error_exit;
    }
#endif /* not _WIN32 */
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
 * see os_env.h
 */

int lock_file(FILE *f, int lock_type, int timeout)
{
    int fd;
    int lock_success;
    struct timespec hundredth_second = { 0, 10000000 };
    int hundredth_seconds;
#ifndef _WIN32
    struct flock lock;
#endif /* not _WIN32 */

    fd = fileno(f);
#ifndef _WIN32   
    lock.l_type = (lock_type == OSENV_LOCK_WRITE) ? F_WRLCK : F_RDLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0;
#endif /* not _WIN32 */
    hundredth_seconds = 0;
    for (;;)
    {
	errno = 0;
#ifdef _WIN32
	lock_success = (_locking(fd, _LK_NBLCK, LONG_MAX) != -1);
#else /* UNIX, DJGPP */
	lock_success = (fcntl(fd, F_SETLK, &lock) != -1);
#endif
	if (lock_success || (errno != EACCES && errno != EAGAIN) 
	    || hundredth_seconds / 100 >= timeout)
	{
	    break;
	}
	else
	{
 	    nanosleep(&hundredth_second, NULL);
	    hundredth_seconds++;
	}
    }
    return (lock_success ? 0 : (hundredth_seconds / 100 >= timeout ? 1 : 2));
}
