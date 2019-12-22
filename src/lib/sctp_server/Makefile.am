AM_CXXFLAGS = -std=c++14 -Wall -Werror -Wextra

AUTOMAKE_OPTIONS = subdir-objects
	
noinst_LTLIBRARIES = libserver.la

libserver_la_SOURCES = sctp_server.cpp \
					sctp_server_client.cpp \
					sctp_server_iclient_data.cpp
					
				
libserver_la_CPPFLAGS = -I$(srcdir)/include \
					-I$(srcdir) \
					-I$(top_srcdir)/src/lib/sctp_common \
					-I$(top_srcdir)/src/lib/third_party/usrsctp/usrsctplib \
					@PTHREAD_CFLAGS@ \
					@OPENSSL_INCLUDES@
				  			
libserver_la_CXXFLAGS = $(AM_CXXFLAGS)

libserver_la_LIBADD = $(top_builddir)/src/lib/third_party/usrsctp/usrsctplib/libusrsctp.la \
					$(top_builddir)/src/lib/sctp_common/libcommon.a

