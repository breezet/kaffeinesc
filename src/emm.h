#ifndef EMM_H
#define EMM_H


#include <linux/dvb/dmx.h>

#include <qstring.h>
#include <qmutex.h>
#include <qthread.h>
#include <qobject.h>
#include <qptrlist.h>
#include <qvaluelist.h>

#include "mgcam/mgcam.h"
#include "dvbsection.h"



class IrdetoCard
{
public:
	unsigned int serial, prov, provid;
	unsigned char hmk[10];
	unsigned char pmk[8];
};

class IrdetoKID
{
public:
	void load();
	~IrdetoKID();
	QPtrList<IrdetoCard> cards;
};



class ViaccessCard
{
public:
	unsigned int provid, mknum, sa;
	unsigned char ua[5];
	unsigned char mk[8];
	cProviderViaccess pv;
	cViaccess cv;
};

class ViaccessKID
{
public:
	void load();
	~ViaccessKID();
	QPtrList<ViaccessCard> cards;
};

class Nagra2Key
{
public:
	int provid, keynr;
	cBN big;
	unsigned char key[24];
	int keyLen;
};

class Emm : public DVBsection
{
	Q_OBJECT
public:
	Emm( int sys, int p, int anum, int tnum );
	~Emm();
	int getPid() { return pid; }
	void stop();
	void getNagra2Keys();

protected:
	virtual void run();
	bool getSection( int timeout );
	void process();
	int system;
	int pid;

	void Nagra2( unsigned char *buffer );
	Nagra2Key* findKey( int id, int knr, int len );
	QPtrList<Nagra2Key> nkeys;

	void Irdeto( unsigned char *buffer );
	unsigned char lastKey;
	IrdetoKID irdkid;

	void Viaccess( unsigned char *buffer );
	ViaccessKID viakid;

signals:
	void newKey( const QStringList & );
};



class CatParser : public DVBsection
{
	Q_OBJECT
public:

	CatParser( int anum, int tnum );
	~CatParser();
	bool go();
	void reset();
	int getAdapter() { return adapter; }
	int getTuner() { return tuner; }

protected:

	virtual void run();
	bool getSection( int pid, int tid, int timeout=5000, bool checkcrc=true );
	bool parseCAT();

	QPtrList<Emm> emm;

signals:
	void newKey( const QStringList & );

};
#endif
