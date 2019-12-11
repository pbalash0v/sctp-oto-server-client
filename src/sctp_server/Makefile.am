AM_CXXFLAGS = -std=c++14 -Wall -Werror -Wextra -g -O0

AUTOMAKE_OPTIONS = subdir-objects
	
noinst_LIBRARIES = libserver.a

libserver_a_SOURCES =  \
					sctp_server.cpp \
					sctp_server_client.cpp \
					sctp_server_iclient_data.cpp
					
				
libserver_a_CPPFLAGS = \
					-I$(srcdir)/include \
					-I$(srcdir) \
					-I$(top_srcdir)/src/sctp_common \
					-I$(top_srcdir)/src/third_party/usrsctp/usrsctplib \
					-I$(top_srcdir)/src/third_party/gopt-10.0 \
					@PTHREAD_CFLAGS@ \
					@OPENSSL_INCLUDES@
				  			
libserver_a_CXXFLAGS = $(AM_CXXFLAGS)

libserver_a_LIBADD = $(top_builddir)/src/third_party/usrsctp/usrsctplib/.libs/libusrsctp.a \
					$(top_builddir)/src/sctp_common/libcommon.a

