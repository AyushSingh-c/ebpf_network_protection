.PHONY: all clean 3rdparty Common++ Packet++

ROOT_DIR ?= $(CURDIR)

FINAL_LIB = $(ROOT_DIR)/bin/pcapplusplus/libpcapplusplus.a
3RDPARTY_SRCS = $(wildcard $(ROOT_DIR)/pcapplusplus/3rdparty/src/*.cpp)
3RDPARTY_OBJS = $(patsubst $(ROOT_DIR)/pcapplusplus/3rdparty/src/%.cpp,$(ROOT_DIR)/bin/pcapplusplus/3rdparty/src/%.o,$(3RDPARTY_SRCS))
PACKET_SRCS = $(wildcard $(ROOT_DIR)/pcapplusplus/Packet++/src/*.cpp)
PACKET_OBJS = $(patsubst $(ROOT_DIR)/pcapplusplus/Packet++/src/%.cpp,$(ROOT_DIR)/bin/pcapplusplus/Packet++/src/%.o,$(PACKET_SRCS))
COMMON_SRCS = $(wildcard $(ROOT_DIR)/pcapplusplus/Common++/src/*.cpp)
COMMON_OBJS = $(patsubst $(ROOT_DIR)/pcapplusplus/Common++/src/%.cpp,$(ROOT_DIR)/bin/pcapplusplus/Common++/src/%.o,$(COMMON_SRCS))

INDIVIDUAL_OBJS = $(3RDPARTY_OBJS) $(COMMON_OBJS) $(PACKET_OBJS)
$(info INDIVIDUAL_OBJS = $(INDIVIDUAL_OBJS))

all: 3rdparty Common++ Packet++ $(FINAL_LIB)

3rdparty:
	$(MAKE) -C 3rdparty ROOT_DIR=$(ROOT_DIR)

Common++:
	$(MAKE) -C Common++ ROOT_DIR=$(ROOT_DIR)

Packet++:
	$(MAKE) -C Packet++ ROOT_DIR=$(ROOT_DIR)

$(FINAL_LIB): $(INDIVIDUAL_OBJS)
	ar rcs $@ $^

clean:
	$(MAKE) -C 3rdparty clean
	$(MAKE) -C Common++ clean
	$(MAKE) -C Packet++ clean
	rm -rf bin/pcapplusplus
