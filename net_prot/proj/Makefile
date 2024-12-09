.PHONY: all clean pcapplusplus src

ROOT_DIR ?= $(CURDIR)


all: pcapplusplus src

pcapplusplus:
	$(MAKE) -C pcapplusplus ROOT_DIR=$(ROOT_DIR)

src:
	rm -rf bin/net_prot
	$(MAKE) -C src ROOT_DIR=$(ROOT_DIR)

clean:
	$(MAKE) -C pcapplusplus clean
	$(MAKE) -C src clean
	rm -rf bin
