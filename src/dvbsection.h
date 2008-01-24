#ifndef DVBSECTION_H
#define DVBSECTION_H

#include <sys/poll.h>
#include <linux/dvb/dmx.h>

#include <qobject.h>
#include <qthread.h>

#define SECA_CA_SYSTEM      0x100
#define VIACCESS_CA_SYSTEM  0x500
#define IRDETO_CA_SYSTEM    0x600
#define BETA_CA_SYSTEM     0x1700
#define NAGRA_CA_SYSTEM    0x1800
#define CRYPTOWORKS_CA_SYSTEM  0xD00
#define DREAMCRYPT_CA_SYSTEM   0x4A70
#define DREAMCRYPT_CA_SYSTEM_LAST   0x4A7F
#define CONAX_CA_SYSTEM 0x0B00
#define NDS_CA_SYSTEM 0x900



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
