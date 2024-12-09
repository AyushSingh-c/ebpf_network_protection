CXX = clang++
LIB_DIR = $(ROOT_DIR)/bin/pcapplusplus
PACKET_LIBRARY = $(LIB_DIR)/libpcapplusplus.a
BPF_CFLAGS = -target bpf -D__TARGET_ARCH_x86 -ggdb -O1 -I$(ROOT_DIR)
CXXFLAGS = -Wall -ggdb -O1 -std=c++17 -I$(ROOT_DIR) -I$(ROOT_DIR)/pcapplusplus/Packet++/header -I$(ROOT_DIR)/pcapplusplus/Common++/header
BPF_SRCS = $(wildcard *.bpf.c)
BPF_OBJS = $(patsubst %.bpf.c,$(ROOT_DIR)/bin/src/%.bpf.o,$(BPF_SRCS))
CPP_SRCS = $(wildcard *.cpp)
CPP_OBJS = $(patsubst %.cpp,$(ROOT_DIR)/bin/src/%.o,$(CPP_SRCS))
LDFLAGS = -lbpf -lstdc++ -lpthread -g -L$(LIB_DIR) -lpcapplusplus -lelf
UTIL_SRC_DIR = $(ROOT_DIR)/src/utilities
UTIL_SRC_OBJS = $(patsubst $(UTIL_SRC_DIR)/%.cpp,$(ROOT_DIR)/bin/src/utilities/%.o,$(wildcard $(UTIL_SRC_DIR)/*.cpp))
TARGET = $(ROOT_DIR)/bin/net_prot

all: utilities kern_code $(BPF_OBJS) $(TARGET)

utilities:
	$(MAKE) -C utilities ROOT_DIR=$(ROOT_DIR)
kern_code:
	$(MAKE) -C kern_code ROOT_DIR=$(ROOT_DIR)

$(ROOT_DIR)/bin/src/%.bpf.o: %.bpf.c
	mkdir -p $(ROOT_DIR)/bin/src
	clang $(BPF_CFLAGS) -c -o $@ $<

$(ROOT_DIR)/bin/src/%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(TARGET): $(CPP_OBJS) $(PACKET_LIBRARY)
	$(CXX) $(CPP_OBJS) $(PARSER_SRC_OBJS) $(UTIL_SRC_OBJS) $(LDFLAGS) -o $@

.PHONY: utilities kern_code clean
clean:
	$(MAKE) -C utilities clean
	$(MAKE) -C kern_code clean
	rm -f $(BPF_OBJS) $(CPP_OBJS) $(TARGET)
