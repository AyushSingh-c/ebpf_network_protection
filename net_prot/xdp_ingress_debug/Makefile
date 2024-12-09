# Variables
CXX = clang++
BPF_CFLAGS = -target bpf -I/usr/include/$(shell uname -m)-linux-gnu -g -O2
CXXFLAGS = -Wall
BPF_SRCS = $(wildcard *.bpf.c)
BPF_OBJS = $(BPF_SRCS:.bpf.c=.bpf.o)
CPP_SRCS = $(wildcard *.cpp)
CPP_OBJS = $(CPP_SRCS:.cpp=.o)
LDFLAGS = -lbpf -lxdp -lstdc++ -lpthread
TARGET = my_program

# Default target
all: $(BPF_OBJS) $(TARGET)

# Rule to build .bpf.o files from .bpf.c files
%.bpf.o: %.bpf.c
	clang $(BPF_CFLAGS) -c -o $@ $<

# Rule to build .o files from .cpp files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

# Rule to build the target executable
$(TARGET): $(CPP_OBJS)
	$(CXX) $(CPP_OBJS) $(LDFLAGS) -o $@

# Clean rule
.PHONY: clean
clean:
	rm -f $(BPF_OBJS) $(CPP_OBJS) $(TARGET)
