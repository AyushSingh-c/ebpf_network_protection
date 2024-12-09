CXX = clang++
CXXFLAGS = -Wall -ggdb -O1 -std=c++17 -O1 -I$(ROOT_DIR) -I$(ROOT_DIR)/pcapplusplus/Packet++/header -I$(ROOT_DIR)/pcapplusplus/Common++/header
CPP_SRCS = $(wildcard *.cpp)
CPP_OBJS = $(patsubst %.cpp,$(ROOT_DIR)/bin/src/utilities/%.o,$(CPP_SRCS))

all: $(CPP_OBJS)

$(ROOT_DIR)/bin/src/utilities/%.o: %.cpp
	mkdir -p $(ROOT_DIR)/bin/src/utilities
	$(CXX) $(CXXFLAGS) -c -o $@ $^

.PHONY: clean
clean:
	rm -f $(CPP_OBJS)
