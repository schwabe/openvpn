#
#  OpenVPN -- An application to securely tunnel IP networks
#             over a single UDP port, with support for SSL/TLS-based
#             session authentication and key exchange,
#             packet encryption, packet authentication, and
#             packet compression.
#
#  Copyright (C) 2002-2023 OpenVPN Inc <sales@openvpn.net>
#  Copyright (C) 2006-2012 Alon Bar-Lev <alon.barlev@gmail.com>
#

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in

SUBDIRS = unit_tests

AM_TESTSUITE_SUMMARY_HEADER = ' for $(PACKAGE_STRING) System Tests'

if !WIN32
test_scripts = t_client.sh t_lpback.sh t_cltsrv.sh
if HAVE_SITNL
test_scripts += t_net.sh
endif
endif

TESTS_ENVIRONMENT = top_srcdir="$(top_srcdir)"
TESTS = $(test_scripts)

dist_noinst_SCRIPTS = \
	t_cltsrv.sh \
	t_cltsrv-down.sh \
	t_lpback.sh \
	t_net.sh \
	update_t_client_ips.sh

dist_noinst_DATA = \
	t_client.rc-sample
