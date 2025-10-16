.PHONY: default
default: all ;

all: oxtop oxtop_cc cc_protocol_viewer

SRC1=oxtop.c ox_common.c
SRC2=cc_protocol_viewer.c ox_common.c

oxtop: $(SRC1) Makefile ox_common.h
	cc $(SRC1) -g -o $@ -lpcap -lncurses 
	sudo setcap cap_net_raw+ep $@

cc_protocol_viewer: $(SRC2) Makefile ox_common.h
	cc $(SRC2) -g -o $@ -lpcap -lncurses 
	sudo setcap cap_net_raw+ep $@

.PHONY: clean

clean:
	rm oxtop cc_protocol_viewer
