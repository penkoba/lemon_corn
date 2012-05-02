include ../include.mk

OBJS := forger_common.o aeha.o nec.o sony.o daikin.o koizumi.o

all: $(OBJS)

analyzer.o: \
	analyzer.c format_util.h analyzer_common.h \
	analyzer_config.h \
	string_util.h
forger_common.o: \
	forger_common.c forger_common.h format_util.h
nec.o: \
	nec.c analyzer_common.h forger_common.h format_util.h
aeha.o: \
	aeha.c analyzer_common.h forger_common.h format_util.h
sony.o: \
	sony.c analyzer_common.h forger_common.h format_util.h
daikin.o: \
	daikin.c analyzer_common.h forger_common.h format_util.h
koizumi.o: \
	koizumi.c analyzer_common.h forger_common.h format_util.h

clean:
	-rm *.o
