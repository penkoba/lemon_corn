include include.mk

TEST_OBJS := remocon-test.o
OBJS := lemon_corn.o lemon_corn_data.o \
	format/analyzer.o format/forger_common.o \
	format/aeha.o format/nec.o format/sony.o \
	format/daikin.o format/koizumi.o \
	file_util.o string_util.o

SUBDIRS := format

.PHONY: all subdirs_all

all: subdirs_all lemon_corn remocon-test

subdirs_all:
	@for i in $(SUBDIRS); do \
		if (! make -C $$i all); then \
			exit 1; \
		fi \
	done

.PHONY: clean subdirs_clean

clean: subdirs_clean
	-rm lemon_corn remocon-test *.o

subdirs_clean:
	@for i in $(SUBDIRS); do \
		if (! make -C $$i clean); then \
			exit 1; \
		fi \
	done

check:
	@echo "valid check commands are [ recv_check | trans_check ]"
recv_check: remocon-test
	./remocon-test -s /dev/ttyUSB0 -r
trans_check: remocon-test
	./remocon-test -s /dev/ttyUSB0 example

remocon-test: $(TEST_OBJS)
lemon_corn: $(OBJS)

remocon-test.o: \
	remocon-test.c PC-OP-RS1.h debug.h
lemon_corn.o: \
	lemon_corn.c PC-OP-RS1.h lemon_corn_data.h format/remocon_format.h \
	debug.h file_util.h string_util.h
lemon_corn_data.o: \
	lemon_corn_data.c lemon_corn_data.h
file_util.o: \
	file_util.c
string_util.o: \
	string_util.c
