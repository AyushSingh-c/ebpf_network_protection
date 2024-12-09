BPF_CFLAGS = -target bpf -D__TARGET_ARCH_x86 -ggdb -O1 -I$(ROOT_DIR)
BPF_SRCS = $(wildcard *.bpf.c)
BPF_OBJS = $(patsubst %.bpf.c,$(ROOT_DIR)/bin/src/kern_code/%.bpf.o,$(BPF_SRCS))

all: $(BPF_OBJS)

$(ROOT_DIR)/bin/src/kern_code/%.bpf.o: %.bpf.c
	mkdir -p $(ROOT_DIR)/bin/src/kern_code
	clang $(BPF_CFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -f $(ROOT_DIR)/bin/src/kern_code