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
		  @PTHREAD_CFLAGS@ \
		  @OPENSSL_INCLUDES@
		  
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
		  -I/usr/include/opencv \
		  @PTHREAD_CFLAGS@ \
		  @OPENSSL_INCLUDES@
		  
client_DEPENDENCIES = $(top_builddir)/src/third_party/usrsctp/usrsctplib/libusrsctp.la \
						$(top_builddir)/src/sctp_client/libclient.la
						
client_LDADD =	$(top_builddir)/src/sctp_client/libclient.la \
			$(top_builddir)/src/third_party/usrsctp/usrsctplib/libusrsctp.la \
			$(top_builddir)/src/third_party/gopt-10.0/libgopt.a \
			$(top_builddir)/src/sctp_common/libcommon.a \
			-lopencv_shape -lopencv_stitching -lopencv_superres -lopencv_videostab \
			-lopencv_aruco -lopencv_bgsegm -lopencv_bioinspired -lopencv_ccalib \
			-lopencv_datasets -lopencv_dpm -lopencv_face -lopencv_freetype -lopencv_fuzzy \
			-lopencv_hdf -lopencv_line_descriptor -lopencv_optflow -lopencv_video -lopencv_plot \
			-lopencv_reg -lopencv_saliency -lopencv_stereo -lopencv_structured_light \
			-lopencv_phase_unwrapping -lopencv_rgbd -lopencv_viz -lopencv_surface_matching \
			-lopencv_text -lopencv_ximgproc -lopencv_calib3d -lopencv_features2d -lopencv_flann \
			-lopencv_xobjdetect -lopencv_objdetect -lopencv_ml -lopencv_xphoto -lopencv_highgui \
			-lopencv_videoio -lopencv_imgcodecs -lopencv_photo -lopencv_imgproc -lopencv_core \
			@OPENSSL_LIBS@ @PTHREAD_LIBS@ @PTHREAD_CFLAGS@
	
	



