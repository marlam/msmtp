/* This file was taken from fetchmail 6.3.26. */
/* netrc.h -- declarations for netrc.c
 * For license terms, see the file COPYING in this directory.
 */

#ifndef _NETRC_H_
#define _NETRC_H_ 1

# undef __BEGIN_DECLS
# undef __END_DECLS
#ifdef __cplusplus
# define __BEGIN_DECLS extern "C" {
# define __END_DECLS }
#else
# define __BEGIN_DECLS /* empty */
# define __END_DECLS /* empty */
#endif

#undef __P
#if defined (__STDC__) || defined (_AIX) || (defined (__mips) && defined (_SYSTYPE_SVR4)) || defined(WIN32) || defined(__cplusplus)
# define __P(protos) protos
#else
# define __P(protos) ()
#endif

/* The structure used to return account information from the .netrc. */
typedef struct _netrc_entry {
  /* The exact host name given in the .netrc, NULL if default. */
  char *host;

  /* The login name of the user. */
  char *login;

  /* Password for the account (NULL, if none). */
  char *password;

  /* Pointer to the next entry in the list. */
  struct _netrc_entry *next;
} netrc_entry;

__BEGIN_DECLS
/* Parse FILE as a .netrc file (as described in ftp(1)), and return a
   list of entries.  NULL is returned if the file could not be
   parsed. */
netrc_entry *parse_netrc __P((const char *file));

/* Return the netrc entry from LIST corresponding to HOST.  NULL is
   returned if no such entry exists. */
netrc_entry *search_netrc __P((netrc_entry *list, const char *host, const char *account));

/* Free the netrc list structure */
void free_netrc __P((netrc_entry *list));
__END_DECLS

#endif /* _NETRC_H_ */
