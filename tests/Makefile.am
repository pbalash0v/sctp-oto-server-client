AM_CXXFLAGS = -std=c++14 -Wall -Werror -Wextra

#AUTOMAKE_OPTIONS = subdir-objects

##$(info srcdir is $(srcdir))
##$(info abs_srcdir is $(abs_srcdir))
##$(info top_srcdir is $(top_srcdir))
##$(info abs_top_srcdir is $(abs_top_srcdir))
##$(info)
##$(info top_builddir is $(top_builddir))
##$(info abs_builddir is $(abs_builddir))
##$(info top_build_prefix is $(top_build_prefix))
##$(info abs_top_builddir is $(abs_top_builddir))

LIBPATH = $(top_srcdir)/src/lib


TESTS_CPPFLAGS = -DTEST_BUILD \
				-I$(LIBPATH)/sctp_server/include \
				-I$(LIBPATH)/sctp_server \
				-I$(LIBPATH)/sctp_client/include \
				-I$(LIBPATH)/sctp_client \
				-I$(LIBPATH)/sctp_common \
				-I$(LIBPATH)/third_party/usrsctp/usrsctplib \
				@PTHREAD_CFLAGS@ \
				@OPENSSL_INCLUDES@
				


## test's helper lib
check_LIBRARIES = libtest.a

libtest_a_SOURCES = $(LIBPATH)/sctp_server/sctp_server.cpp \
					$(LIBPATH)/sctp_server/sctp_server_client.cpp \
					$(LIBPATH)/sctp_server/sctp_server_iclient_data.cpp \
					$(LIBPATH)/sctp_client/sctp_client.cpp \
					$(LIBPATH)/sctp_client/sctp_client_data.cpp

libtest_a_CXXFLAGS = $(AM_CXXFLAGS)
libtest_a_CPPFLAGS = $(TESTS_CPPFLAGS)
				

## tests
check_PROGRAMS = test1 test2 test3 test4 test5 test6
check_PROGRAMS_FAIL = test5

AM_DEFAULT_SOURCE_EXT = .cpp

TESTS = $(check_PROGRAMS)
XFAIL_TESTS = $(check_PROGRAMS_FAIL)

TESTS_LDADD = $(top_builddir)/tests/libtest.a \
			$(top_builddir)/src/lib/sctp_common/libcommon.a \
			$(top_builddir)/src/lib/third_party/usrsctp/usrsctplib/.libs/libusrsctp.a \
			@OPENSSL_LIBS@ @PTHREAD_LIBS@ @PTHREAD_CFLAGS@
							
## test1
test1_CXXFLAGS = $(AM_CXXFLAGS)		
test1_CPPFLAGS = $(TESTS_CPPFLAGS)
test1_LDADD = 	$(TESTS_LDADD)
				
## test2				
test2_CXXFLAGS = $(AM_CXXFLAGS)
test2_CPPFLAGS = $(TESTS_CPPFLAGS)
test2_LDADD = 	$(TESTS_LDADD)
		
## test3			
test3_CXXFLAGS = $(AM_CXXFLAGS)
test3_CPPFLAGS =$(TESTS_CPPFLAGS)
test3_LDADD = 	$(TESTS_LDADD)

## test4			
test4_CXXFLAGS = $(AM_CXXFLAGS)
test4_CPPFLAGS =$(TESTS_CPPFLAGS)
test4_LDADD = 	$(TESTS_LDADD)

## test5	
test5_CXXFLAGS = $(AM_CXXFLAGS)
test5_CPPFLAGS =$(TESTS_CPPFLAGS)
test5_LDADD = 	$(TESTS_LDADD)

## test6	
test6_CXXFLAGS = $(AM_CXXFLAGS)
test6_CPPFLAGS =$(TESTS_CPPFLAGS)
test6_LDADD = 	$(TESTS_LDADD)

