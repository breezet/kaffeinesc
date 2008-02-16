SUBDIRS = mgcam FFdecsa

INCLUDES    = $(all_includes)
METASOURCES = AUTO

KDE_ICON = AUTO

kde_module_LTLIBRARIES = libkaffeinedvbsc.la

noinst_HEADERS = kaffeinesc.h \
	cardclient.h \
	dvbscam.h \
	tpsau.h \
	dvbsection.h \
	emm.h

libkaffeinedvbsc_la_SOURCES = scconfigdialogui.ui \
	kaffeinesc.cpp \
	cardclient.cpp \
	dvbscam.cpp \
	tpsau.cpp \
	dvbsection.cpp \
	emm.cpp

libkaffeinedvbsc_la_LIBADD = \
	./mgcam/libmgcam.la \
	-lssl -lcrypt \
	./FFdecsa/libFFdecsa.a

libkaffeinedvbsc_la_LDFLAGS =

# this is where the desktop file will go
partdesktopdir   = $(kde_servicesdir)
partdesktop_DATA = kaffeinedvbsc.desktop
