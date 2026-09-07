CLANG ?= clang
CFLAGS ?= -O2 -g -target bpf -I include -Wno-pass-failed

all: sensor.o

sensor.o: src/sensor.c include/telemetry_events.h
	$(CLANG) $(CFLAGS) -c src/sensor.c -o sensor.o

clean:
	rm -f sensor.o

.PHONY: all clean
