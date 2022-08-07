bin_PROGRAMS = msmtp

msmtp_SOURCES = \
	conf.c conf.h \
	eval.c eval.h \
	list.c list.h \
	md5.c md5.h \
	md5-apps.c md5-apps.h \
	msgid.c msgid.h \
	msmtp.c \
	net.c net.h \
	netrc.c netrc.h \
	readbuf.c readbuf.h \
	smtp.c smtp.h \
	stream.c stream.h \
	tools.c tools.h \
	xalloc.c xalloc.h \
	gettext.h \
	aliases.c aliases.h \
	password.c password.h \
	base64.c base64.h

if HAVE_TLS
msmtp_SOURCES += mtls.c mtls.h
endif
if HAVE_GNUTLS
msmtp_SOURCES += mtls-gnutls.c
endif
if HAVE_OPENSSL
msmtp_SOURCES += mtls-openssl.c
endif
if HAVE_LIBTLS
msmtp_SOURCES += mtls-libtls.c
endif

AM_CPPFLAGS = $(tls_CFLAGS) $(libgsasl_CFLAGS) $(libidn2_CFLAGS) $(libsecret_CFLAGS)

msmtp_LDADD =  $(tls_LIBS) $(libgsasl_LIBS) $(libidn2_LIBS) $(libsecret_LIBS) $(LIBINTL)

DEFS += -DSYSCONFDIR=\"$(sysconfdir)\" -DLOCALEDIR=\"$(localedir)\" -DBINDIR=\"$(bindir)\"

if BUILD_MSMTPD
bin_PROGRAMS += msmtpd
msmtpd_SOURCES = msmtpd.c base64.c base64.h eval.c eval.h password.c password.h tools.c tools.h xalloc.c xalloc.h netrc.c netrc.h
msmtpd_LDADD =  $(libsecret_LIBS) $(LIBINTL)
endif
