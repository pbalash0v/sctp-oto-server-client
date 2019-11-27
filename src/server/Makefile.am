AM_CXXFLAGS = -std=c++14 -Wall -Werror -Wextra -g -O0
AUTOMAKE_OPTIONS = subdir-objects	
	
bin_PROGRAMS = server
server_SOURCES = main.cpp \
				sctp_srvr/sctp_srvr_client.cpp \
				sctp_srvr/sctp_srvr.cpp

				
server_CXXFLAGS = $(AM_CXXFLAGS)

server_CPPFLAGS = -I$(srcdir)/sctp_srvr/include \
				  -I$(srcdir)/sctp_srvr \
				  -I$(srcdir)/../common \
  				  -I$(srcdir)/../third_party/usrsctp/usrsctplib \
				  -I$(srcdir)/../third_party/gopt-10.0 \
  				  -I$(srcdir)/../third_party/spdlog/include \
				  @PTHREAD_CFLAGS@ \
				  @OPENSSL_INCLUDES@


server_DEPENDENCIES = $(top_builddir)/src/third_party/usrsctp/usrsctplib/.libs/libusrsctp.la

server_LDADD = @OPENSSL_LIBS@ @PTHREAD_LIBS@ @PTHREAD_CFLAGS@ \
				$(top_builddir)/src/third_party/usrsctp/usrsctplib/.libs/libusrsctp.a \
				$(top_builddir)/src/third_party/gopt-10.0/libgopt.a \
				$(top_builddir)/src/common/libcommon.a				
 


