.PHONY: default
default: all ;

all: oxtop oxpro

SRC1=oxtop.c ox_common.c
SRC2=oxpro.c ox_common.c

oxtop: $(SRC1) Makefile ox_common.h
	cc $(SRC1) -g -o $@ -lpcap -lncurses -lpthread
	sudo setcap cap_net_raw+ep $@

oxpro: $(SRC2) Makefile ox_common.h
	cc $(SRC2) -g -o $@ -lpcap -lncurses -lpthread
	sudo setcap cap_net_raw+ep $@

.PHONY: clean

clean:
	rm oxtop oxpro
