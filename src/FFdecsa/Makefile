##### compiling with g++ gives a little more speed
# !!!!!!!!!!! be aware that gcc=>4 gives half speed than gcc=>3.3.3 on 32bit cpu !!!!!!!!!!!!
#COMPILER=g++
COMPILER=g++-3.4

# !!!!!!!!!!! Adapt the following flags to your cpu !!!!!!!!!!!!!!!!!!!!!!!!!!
FLAGS=-O3 -fPIC -fexpensive-optimizations -funroll-loops -Wall -Winline -fomit-frame-pointer
#FLAGS += -march=pentium-mmx
#FLAGS += -march=pentium2
#FLAGS += -march=pentium3
#FLAGS += -march=pentium4
#FLAGS += -march=prescott
#FLAGS += -march=athlon
FLAGS += -march=athlon-xp
#FLAGS += -march=athlon64

H_FILES = FFdecsa.h \
          parallel_generic.h \
          parallel_032_4char.h \
          parallel_032_int.h \
          parallel_064_2int.h \
          parallel_064_8charA.h \
          parallel_064_8char.h \
          parallel_064_long.h \
          parallel_064_mmx.h \
          parallel_128_16charA.h \
          parallel_128_16char.h \
          parallel_128_2long.h \
          parallel_128_2mmx.h \
          parallel_128_4int.h \
          parallel_128_sse.h

install: all

all: FFdecsa_test libFFdecsa.a

libFFdecsa.a: FFdecsa.o
	rm -f libFFdecsa.a
	ar cru libFFdecsa.a FFdecsa.o
	ranlib libFFdecsa.a

FFdecsa_test:	FFdecsa_test.o FFdecsa.o
	$(COMPILER) $(FLAGS) -o FFdecsa_test FFdecsa_test.o FFdecsa.o

FFdecsa_test.o: FFdecsa_test.c  FFdecsa.h FFdecsa_test_testcases.h
	$(COMPILER) $(FLAGS) -c FFdecsa_test.c

FFdecsa.o: tmp_autogenerated_stuff_FFdecsa.c tmp_autogenerated_stuff_stream.c  $(H_FILES)
	$(COMPILER) $(FLAGS)  -c tmp_autogenerated_stuff_FFdecsa.c -o FFdecsa.o


# the grep discards all the debugging stuff before compilation
tmp_autogenerated_stuff_FFdecsa.c: FFdecsa.c
	grep -v DBG FFdecsa.c >tmp_autogenerated_stuff_FFdecsa.c

tmp_autogenerated_stuff_stream.c: stream.c
	grep -v DBG stream.c >tmp_autogenerated_stuff_stream.c


clean:
	rm -f FFdecsa_test *.o tmp_autogenerated_stuff_*.c *.a || true

test:
	sync;clear;usleep 200000;nice --19 ./FFdecsa_test;usleep 200000;nice --19 ./FFdecsa_test;usleep 200000;nice --19 ./FFdecsa_test

test1:
	sync;clear;usleep 200000;nice --19 ./FFdecsa_test

uninstall:
