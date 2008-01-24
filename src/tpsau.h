#ifndef TPSAU_H
#define TPSAU_H

#include <qptrlist.h>

#include "dvbsection.h"
#include "mgcam/viaccess.h"


class cOpenTVModule;


class tpsKey
{
public:
	tpsKey() {}
	~tpsKey() {}
	void set( unsigned char* buf );
	unsigned char timestamp[4];
	unsigned char key[3][16];
	unsigned char step[4];
};



class TpsAu : public DVBsection, protected cTPS
{

public:
	TpsAu();
	~TpsAu();
	void go( int anum, int tnum );

protected:
	bool getSection( int timeout );
	void save();
	virtual void run();
	bool processAU( const cOpenTVModule *mod );
	void DumpAlgo3();

private:
	QPtrList<tpsKey> keys;
};
#endif
