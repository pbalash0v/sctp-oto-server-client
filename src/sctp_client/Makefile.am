AM_CXXFLAGS = -std=c++14 -Wall -Werror -Wextra -g -O0
AUTOMAKE_OPTIONS = subdir-objects

noinst_LIBRARIES = libclient.a

libclient_a_SOURCES = sctp_client.cpp
					
libclient_a_CPPFLAGS = \
					-I$(srcdir)/include \
					-I$(srcdir) \
					-I$(top_srcdir)/src/sctp_common \
					-I$(top_srcdir)/src/third_party/usrsctp/usrsctplib \
					@PTHREAD_CFLAGS@ \
					@OPENSSL_INCLUDES@
				  			
libclient_a_CXXFLAGS = $(AM_CXXFLAGS)

libclient_a_LIBADD = $(top_builddir)/src/third_party/usrsctp/usrsctplib/.libs/libusrsctp.a \
					$(top_builddir)/src/sctp_common/libcommon.a




