bin_PROGRAMS = msmtp

msmtp_SOURCES = \
	conf.c conf.h \
	list.c list.h \
	msmtp.c \
	net.c net.h \
	netrc.c netrc.h \
	readbuf.c readbuf.h \
	smtp.c smtp.h \
	stream.c stream.h \
	tools.c tools.h \
	xalloc.c xalloc.h \
	gettext.h \
	aliases.c aliases.h

if HAVE_TLS
msmtp_SOURCES += tls.c tls.h
endif

if HAVE_LIBGSASL
else
msmtp_SOURCES += base64.c base64.h md5.c md5.h md5-apps.c md5-apps.h
endif

AM_CPPFLAGS = $(tls_CFLAGS) $(libgsasl_CFLAGS) $(libidn_CFLAGS) $(libgnome_keyring_CFLAGS)

msmtp_LDADD =  $(tls_LIBS) $(libgsasl_LIBS) $(libidn_LIBS) $(libgnome_keyring_LIBS) $(LIBINTL)

DEFS += -DSYSCONFDIR=\"$(sysconfdir)\" -DLOCALEDIR=\"$(localedir)\"
