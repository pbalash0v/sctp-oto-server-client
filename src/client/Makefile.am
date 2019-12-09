AM_CXXFLAGS = -std=c++14 -Wall -Werror -Wextra -g -O0
AUTOMAKE_OPTIONS = subdir-objects

bin_PROGRAMS = client

client_SOURCES = main.cpp \
				sctp_client/sctp_client.cpp \
				sctp_client/include/sctp_client.h \
				tui/include/i_tui.h \
				tui/include/tui.h \
				tui/include/simple_tui.h \
				tui/tui.cpp \
				tui/simple_tui.cpp
				
client_CXXFLAGS = $(AM_CXXFLAGS)

client_CPPFLAGS = -I$(srcdir)/sctp_client/include \
				  -I$(srcdir)/sctp_client \
  				  -I$(srcdir)/tui/include \
				  -I$(srcdir)/../common \
  				  -I$(srcdir)/../third_party/usrsctp/usrsctplib \
				  -I$(srcdir)/../third_party/gopt-10.0 \
				  -I$(srcdir)/../third_party/spdlog/include \
				  @PTHREAD_CFLAGS@ \
				  @OPENSSL_INCLUDES@ 
				  ##@CURSES_CFLAGS@

client_LDADD = @OPENSSL_LIBS@ @PTHREAD_LIBS@ @PTHREAD_CFLAGS@ @CURSES_LIB@ \
				$(top_builddir)/src/third_party/usrsctp/usrsctplib/.libs/libusrsctp.a \
				$(top_builddir)/src/third_party/gopt-10.0/libgopt.a \
				$(top_builddir)/src/common/libcommon.a
				
	
	



