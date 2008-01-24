#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include <qstring.h>

#include "dvbsection.h"



DVBsection::DVBsection( int anum, int tnum )
{
	adapter = anum;
	tuner = tnum;
	QString s = QString("/dev/dvb/adapter%1/demux%2").arg( anum ).arg( tnum );

	if ((fdDemux = open( s.ascii(), O_RDWR | O_NONBLOCK )) < 0) {
		perror ("open failed");
	}
	else {
		pf[0].fd = fdDemux;
		pf[0].events = POLLIN;
	}

	isRunning = false;
}



DVBsection::DVBsection()
{
	isRunning = false;
}



DVBsection::~DVBsection()
{
	close( fdDemux );
}



bool DVBsection::openFilter( int pid, int tid, int timeout, bool checkcrc )
{
	QString s = QString("/dev/dvb/adapter%1/demux%2").arg( adapter ).arg( tuner );
	if ((fdDemux = open( s.ascii(), O_RDWR | O_NONBLOCK )) < 0) {
		perror ("open failed");
		return false;
	}
	if ( !setFilter( pid, tid, timeout, checkcrc ) )
		return false;
	pf[0].fd = fdDemux;
	pf[0].events = POLLIN;
	return true;
}



bool DVBsection::setFilter( int pid, int tid, int timeout, bool checkcrc )
{
	struct dmx_sct_filter_params sctfilter;

	memset( &sctfilter, 0, sizeof( sctfilter ) );

	sctfilter.pid = pid;
	if ( tid<256 && tid>0 ) {
		sctfilter.filter.filter[0] = tid;
		sctfilter.filter.mask[0] = 0xff;
	}
	sctfilter.flags = DMX_IMMEDIATE_START;
	if ( checkcrc )
		sctfilter.flags|= DMX_CHECK_CRC;
	sctfilter.timeout = timeout;

	if ( ioctl( fdDemux, DMX_SET_FILTER, &sctfilter ) < 0 ) {
		perror ( "ioctl DMX_SET_FILTER failed" );
		return false;
	}
	return true;
}



void DVBsection::closeFilter()
{
	ioctl( fdDemux, DMX_STOP );
	close( fdDemux );
}



void DVBsection::stopFilter()
{
	ioctl( fdDemux, DMX_STOP );
}



unsigned int DVBsection::getBits( unsigned char *b, int offbits, int nbits )
{
	int i, nbytes;
	unsigned int ret = 0;
	unsigned char *buf;

	buf = b+(offbits/8);
	offbits %=8;
	nbytes = (offbits+nbits)/8;
	if ( ((offbits+nbits)%8)>0 )
		nbytes++;
	for ( i=0; i<nbytes; i++ )
		ret += buf[i]<<((nbytes-i-1)*8);
	i = (4-nbytes)*8+offbits;
	ret = ((ret<<i)>>i)>>((nbytes*8)-nbits-offbits);

	return ret;
}

#include "dvbsection.moc"
