SUBDIRS = src po doc scripts
EXTRA_DIST = README.w32

# This works with GNU tar and gives cleaner package than normal 'make dist'.
# (Taken from xz-4.999.9beta/Makefile.am)
mydist:
	umask 022; \
	TAR_OPTIONS='--owner=0 --group=0 --numeric-owner --mode=u+rw,go+r-w' $(MAKE) dist-xz
