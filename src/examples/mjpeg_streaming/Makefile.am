AM_CXXFLAGS = -std=c++14 -Wall -Werror -Wextra -pedantic

AUTOMAKE_OPTIONS = subdir-objects

bin_PROGRAMS = server client

server_SOURCES = server_main.cpp

server_CXXFLAGS = $(AM_CXXFLAGS)

server_CPPFLAGS = -I$(top_srcdir)/src/sctp_server/include \
		  -I$(top_srcdir)/src/sctp_server \
		  -I$(top_srcdir)/src/sctp_common \
		  -I$(top_srcdir)/src/third_party/usrsctp/usrsctplib \
		  -I$(top_srcdir)/src/third_party/gopt-10.0 \
		  -I$(top_srcdir)/src/third_party/spdlog/include \
		  @PTHREAD_CFLAGS@ @OPENSSL_INCLUDES@
		  
server_DEPENDENCIES = $(top_builddir)/src/third_party/usrsctp/usrsctplib/libusrsctp.la \
						$(top_builddir)/src/sctp_server/libserver.la
						
server_LDADD = 	$(top_builddir)/src/sctp_server/libserver.la \
		$(top_builddir)/src/third_party/usrsctp/usrsctplib/libusrsctp.la \
		$(top_builddir)/src/third_party/gopt-10.0/libgopt.a \
		$(top_builddir)/src/sctp_common/libcommon.a \
		@OPENSSL_LIBS@ @PTHREAD_LIBS@ @PTHREAD_CFLAGS@





client_SOURCES = client_main.cpp
client_CXXFLAGS = $(AM_CXXFLAGS)
client_CPPFLAGS = -I$(top_srcdir)/src/sctp_client/include \
		  -I$(top_srcdir)/src/sctp_client \
		  -I$(top_srcdir)/src/sctp_common \
		  -I$(top_srcdir)/src/third_party/usrsctp/usrsctplib \
		  -I$(top_srcdir)/src/third_party/gopt-10.0 \
		  -I$(top_srcdir)/src/third_party/spdlog/include \
		  @OPENCV_CFLAGS@ @PTHREAD_CFLAGS@ @OPENSSL_INCLUDES@
		  
client_DEPENDENCIES = $(top_builddir)/src/third_party/usrsctp/usrsctplib/libusrsctp.la \
						$(top_builddir)/src/sctp_client/libclient.la
						
client_LDADD =	$(top_builddir)/src/sctp_client/libclient.la \
			$(top_builddir)/src/third_party/usrsctp/usrsctplib/libusrsctp.la \
			$(top_builddir)/src/third_party/gopt-10.0/libgopt.a \
			$(top_builddir)/src/sctp_common/libcommon.a \
			@OPENCV_LIBS@ @OPENSSL_LIBS@ @PTHREAD_LIBS@ @PTHREAD_CFLAGS@
	
	



