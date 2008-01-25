#ifndef DVBSECTION_H
#define DVBSECTION_H

#include <sys/poll.h>
#include <linux/dvb/dmx.h>

#include <qobject.h>
#include <qthread.h>

#define SECA_CA_SYSTEM      		0x100
#define CCETT_CA_SYSTEM			0x200
#define DEUTSCHE_TELECOM_CA_SYSTEM	0x300
#define EURODEC_CA_SYSTEM		0x400
#define VIACCESS_CA_SYSTEM  		0x500
#define IRDETO_CA_SYSTEM    		0x600
#define JERROLD_CA_SYSTEM		0x700
#define MATRA_CA_SYSTEM			0x800
#define NDS_CA_SYSTEM 			0x900
#define NOKIA_CA_SYSTEM			0x0A00
#define CONAX_CA_SYSTEM 		0x0B00
#define NTL_CA_SYSTEM			0x0C00
#define CRYPTOWORKS_CA_SYSTEM  		0xD00
#define POWERVU_CA_SYSTEM		0x0E00
#define SONY_CA_SYSTEM			0x0F00
#define TANDBERG_CA_SYSTEM		0x1000
#define THOMPSON_CA_SYSTEM		0x1100
#define TVCOM_CA_SYSTEM			0x1200
#define HPT_CA_SYSTEM			0x1300
#define HRT_CA_SYSTEM			0x1400
#define IBM_CA_SYSTEM			0x1500
#define NERA_CA_SYSTEM			0x1600
#define BETA_CA_SYSTEM     		0x1700
#define NAGRA_CA_SYSTEM    		0x1800
#define TITAN_CA_SYSTEM			0x1900
#define TELEFONICA_CA_SYSTEM		0x2000
#define STENTOR_CA_SYSTEM		0x2100
#define TADIRAN_SCOPUS_CA_SYSTEM	0x2200
#define BARCO_AS_CA_SYSTEM		0x2300
#define STARGUIDE_CA_SYSTEM		0x2400
#define MENTOR_CA_SYSTEM		0x2500
#define BISS_CA_SYSTEM 			0x2600
// EBU ?
#define DREAMCRYPT_CA_SYSTEM   	    	0x4A70
#define DREAMCRYPT_CA_SYSTEM_LAST   	0x4A7F

#define GI_CA_SYSTEM			0x4700
#define TELEMANN_CA_SYSTEM		0x4800


class DVBsection : public QObject, public QThread
{
	Q_OBJECT

public:

	DVBsection( int anum, int tnum );
	DVBsection();
	~DVBsection();

protected:

	virtual void run() {}
	void stopFilter();
	void closeFilter();
	bool openFilter( int pid, int tid, int timeout=5000, bool checkcrc=true );
	bool setFilter( int pid, int tid, int timeout=5000, bool checkcrc=true );
	unsigned int getBits( unsigned char *b, int offbits, int nbits );

	int fdDemux;
	bool isRunning;
	int adapter;
	int tuner;
	struct pollfd pf[1];
	unsigned char sbuf[4096];
	int sbufLen;
};

#endif /* DVBSECTION_H */
