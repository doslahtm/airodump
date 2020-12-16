LDLIBS=-lpcap

all: airodump

airodump: main.o airodump.o mac.o
		$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
		rm -f airodump *.o
