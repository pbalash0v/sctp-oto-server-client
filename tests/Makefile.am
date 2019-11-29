AM_CXXFLAGS = -std=c++14 -Wall -Werror -Wextra -g -O0

##$(info srcdir is $(srcdir))
##$(info abs_srcdir is $(abs_srcdir))
##$(info top_srcdir is $(top_srcdir))
##$(info abs_top_srcdir is $(abs_top_srcdir))
##$(info)
##$(info top_builddir is $(top_builddir))
##$(info abs_builddir is $(abs_builddir))
##$(info top_build_prefix is $(top_build_prefix))
##$(info abs_top_builddir is $(abs_top_builddir))

TESTS_CPPFLAGS = -DTEST_BUILD \
				-I$(top_srcdir)/src/server/sctp_srvr/include \
				-I$(top_srcdir)/src/server/sctp_srvr \
				-I$(top_srcdir)/src/client/sctp_client/include \
				-I$(top_srcdir)/src/common \
				-I$(top_srcdir)/src/third_party/usrsctp/usrsctplib \
				@PTHREAD_CFLAGS@ \
				@OPENSSL_INCLUDES@
				


## test's helper lib
check_LIBRARIES = libtest.a

libtest_a_SOURCES = ../../src/server/sctp_srvr/sctp_srvr.cpp \
					../../src/server/sctp_srvr/sctp_srvr_client.cpp \
					../../src/client/sctp_client/sctp_client.cpp
libtest_a_CXXFLAGS = $(AM_CXXFLAGS)
libtest_a_CPPFLAGS = $(TESTS_CPPFLAGS)
				

## tests
check_PROGRAMS = test1 test2 test3

TESTS = $(check_PROGRAMS)

TESTS_LDADD = $(top_builddir)/tests/libtest.a \
				$(top_builddir)/src/common/libcommon.a \
				$(top_builddir)/src/third_party/usrsctp/usrsctplib/.libs/libusrsctp.a \
				@OPENSSL_LIBS@ @PTHREAD_LIBS@ @PTHREAD_CFLAGS@
				
## test1
test1_SOURCES = test1.cpp
test1_CXXFLAGS = $(AM_CXXFLAGS)		
test1_CPPFLAGS = $(TESTS_CPPFLAGS)
test1_LDADD = 	$(TESTS_LDADD)
				
							
## test2				
test2_SOURCES = test2.cpp
test2_CXXFLAGS = $(AM_CXXFLAGS)
test2_CPPFLAGS = $(TESTS_CPPFLAGS)
test2_LDADD = 	$(TESTS_LDADD)
		
				
## test3			
test3_SOURCES = test3.cpp
test3_CXXFLAGS = $(AM_CXXFLAGS)
test3_CPPFLAGS =$(TESTS_CPPFLAGS)
test3_LDADD = 	$(TESTS_LDADD)
