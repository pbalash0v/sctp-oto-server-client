AM_CXXFLAGS = -std=c++14 -Wall -Werror -Wextra

AUTOMAKE_OPTIONS = subdir-objects

noinst_LTLIBRARIES = libclient.la

libclient_la_SOURCES = sctp_client.cpp \
						sctp_client_data.cpp
					
libclient_la_CPPFLAGS = -I$(srcdir)/include \
						-I$(srcdir) \
						-I$(top_srcdir)/src/sctp_common \
						-I$(top_srcdir)/src/third_party/usrsctp/usrsctplib \
						@PTHREAD_CFLAGS@ \
						@OPENSSL_INCLUDES@
				  			
libclient_la_CXXFLAGS = $(AM_CXXFLAGS)

libclient_la_LIBADD = $(top_builddir)/src/third_party/usrsctp/usrsctplib/libusrsctp.la \
					$(top_builddir)/src/sctp_common/libcommon.a




