bin_PROGRAMS = msmtp

msmtp_SOURCES = \
	conf.c conf.h \
	list.c list.h \
	msmtp.c \
	net.c net.h \
	netrc.c netrc.h \
	os_env.c os_env.h \
	smtp.c smtp.h \
	stream.c stream.h

msmtp_LDADD = @LIBINTL@ @crypto_obj@ @tls_obj@ $(SSL_LIBS) $(GSASL_LIBS) ../gnulib/libgnu.a

msmtp_DEPENDENCIES = @crypto_obj@ @tls_obj@

EXTRA_msmtp_SOURCES = crypto.c crypto.h tls.c tls.h

AM_CPPFLAGS = -I$(top_srcdir)/gnulib

DEFS += -DSYSCONFDIR=\"$(sysconfdir)\"

localedir = $(datadir)/locale
DEFS += -DLOCALEDIR=\"$(localedir)\"
