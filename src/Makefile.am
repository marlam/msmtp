bin_PROGRAMS = msmtp

msmtp_SOURCES = \
	conf.c conf.h \
	list.c list.h \
	msmtp.c \
	net.c net.h \
	netrc.c netrc.h \
	smtp.c smtp.h \
	stream.c stream.h \
	tools.c tools.h

msmtp_LDADD = @tls_obj@ $(top_builddir)/gnulib/libgnu.a @LIBINTL@

msmtp_DEPENDENCIES = @tls_obj@

EXTRA_msmtp_SOURCES = tls.c tls.h

AM_CPPFLAGS = -I$(top_srcdir)/gnulib

DEFS += -DSYSCONFDIR=\"$(sysconfdir)\"

localedir = $(datadir)/locale
DEFS += -DLOCALEDIR=\"$(localedir)\"
