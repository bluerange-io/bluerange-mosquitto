MOSQUITTO_SRC ?= ../mosquitto

OBJS = auth-plug.o dep/cJSON.o dep/log.o dep/metrics.c

OSSLINC = -I/usr/include
OSSLIBS = -L/usr/lib -lcrypto

CFLAGS := -fPIC -Wall -Werror
CFLAGS += -I$(MOSQUITTO_SRC)/include -I$(MOSQ)/src -Idep -DDEBUG=1 $(OSSLINC)

LDFLAGS = -L$(MOSQUITTO_SRC)/lib/
LDADD = -lcurl $(OSSLIBS) -lmosquitto

all: auth-plug.so

auth-plug.so : $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -fPIC -shared -o $@ $(OBJS) $(LDADD)

auth-plug.o: auth-plug.c Makefile
cJSON.o: cJSON.c cJSON.h Makefile
log.o: log.c log.h Makefile
metrics.o: metrics.c metrics.h Makefile

clean :
	rm -f *.o *.so np
