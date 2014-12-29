SUBDIRS = src po doc scripts
EXTRA_DIST = ChangeLog.old

# Create the ChangeLog file from the git log
dist-hook:
	if test -d "$(srcdir)/.git" && type git > /dev/null 2>&1; then \
		(cd "$(srcdir)" && git log --date=iso --stat msmtp-1.6.0rc1..HEAD) > "$(distdir)/ChangeLog"; \
	fi

# This works with GNU tar and gives cleaner package than normal 'make dist'.
# (Taken from xz-4.999.9beta/Makefile.am)
mydist:
	umask 022; \
	TAR_OPTIONS='--owner=0 --group=0 --numeric-owner --mode=u+rw,go+r-w' $(MAKE) dist-xz
