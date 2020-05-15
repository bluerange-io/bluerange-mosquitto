OBJS = auth-plug.o dep/cJSON.o dep/log.o

OSSLINC = -I/usr/include
OSSLIBS = -L/usr/lib -lcrypto

CFLAGS := -fPIC -Wall -Werror
CFLAGS += -I$(MOSQ)/src -Idep -DDEBUG=1 $(OSSLINC)

LDFLAGS = -L$(MOSQUITTO_SRC)/lib/
LDADD = -lcurl $(OSSLIBS) -lmosquitto

all: auth-plug.so

auth-plug.so : $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -fPIC -shared -o $@ $(OBJS) $(LDADD)

auth-plug.o: auth-plug.c Makefile
log.o: log.c log.h Makefile

clean :
	rm -f *.o *.so np
