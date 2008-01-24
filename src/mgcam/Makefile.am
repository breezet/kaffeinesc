noinst_LTLIBRARIES = libmgcam.la
INCLUDES = $(all_includes)
libmgcam_la_METASOURCES = AUTO
libmgcam_la_SOURCES = seca.c \
	irdeto.c \
	viaccess.cpp \
	nagra.cpp \
	crypto.cpp \
	misc.cpp \
	cryptoworks.cpp \
	st20.cpp

noinst_HEADERS = irdeto.h \
	mgcam.h \
	README \
	seca.h \
	viaccess.h \
	nagra.h \
	crypto.h \
	misc.h \
	openssl-compat.h \
	st20.h \
	cryptoworks.h

AM_CFLAGS =  -O2
