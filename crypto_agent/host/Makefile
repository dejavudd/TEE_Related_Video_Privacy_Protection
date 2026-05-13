
CC      = $(CROSS_COMPILE)gcc
LD      = $(CROSS_COMPILE)ld
AR      = $(CROSS_COMPILE)ar
NM      = $(CROSS_COMPILE)nm
OBJCOPY = $(CROSS_COMPILE)objcopy
OBJDUMP = $(CROSS_COMPILE)objdump
READELF = $(CROSS_COMPILE)readelf

SRCS1 = crypto_gm.c
OBJS1 = $(SRCS1:.c=.o)

SRCS2 = crypto_agent.c
OBJS2 = $(SRCS2:.c=.o)

CFLAGS += -Wall -I../ta/include -I$(TEEC_EXPORT)/include -D BINARY_PREFIX=\"crypto_gm\" -g -fPIC
LDADD += -lteec -L$(TEEC_EXPORT)/lib -lpthread

.PHONY: all
all:  crypto_gm libphytiumcrypto.so

crypto_gm: $(OBJS1)
	mkdir -p bin
	$(CC) -o bin/$@ $^ $(LDADD)

libphytiumcrypto.so: $(OBJS2)
	mkdir -p bin
	$(CC) $(CFLAGS) -shared -o bin/$@ $^ $(LDADD)

.PHONY: clean
clean:
	rm -rf bin $(OBJS1)
