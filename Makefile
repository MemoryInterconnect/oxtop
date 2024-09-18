.PHONY: default
default: all ;

all: oxtop

SRC=oxtop.c ox_common.c

oxtop: $(SRC) Makefile ox_common.h
	cc $(SRC) -o oxtop -lpcap -lncurses 
	sudo setcap cap_net_raw+ep oxtop

.PHONY: clean

clean:
	rm oxtop
