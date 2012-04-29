CC := gcc
CFLAGS := -Wall -W -O2
LDFLAGS :=
TEST_OBJS := remocon-test.o
OBJS := lemon_corn.o lemon_corn_data.o remocon_format.o file_util.o string_util.o

CFLAGS += -DAPP_DEBUG
CFLAGS += -DDEBUG_LEVEL_REMOCON_TEST=0
CFLAGS += -DDEBUG_LEVEL_LEMON_CORN=0
CFLAGS += -DDEBUG_LEVEL_REMOCON_FORMAT=0

all: lemon_corn remocon-test

clean:
	-rm lemon_corn remocon-test *.o

check:
	@echo "valid check commands are [ recv_check | trans_check ]"
recv_check: remocon-test
	./remocon-test -s /dev/ttyUSB0 -r
trans_check: remocon-test
	./remocon-test -s /dev/ttyUSB0 example

remocon-test: $(TEST_OBJS)
lemon_corn: $(OBJS)

remocon-test.o: remocon-test.c PC-OP-RS1.h debug.h
lemon_corn.o: \
	lemon_corn.c PC-OP-RS1.h lemon_corn_data.h remocon_format.h \
	debug.h file_util.h string_util.h
lemon_corn_data.o: lemon_corn_data.c lemon_corn_data.h
remocon_format.o: remocon_format.c string_util.h
file_util.o: file_util.c
string_util.o: string_util.c
