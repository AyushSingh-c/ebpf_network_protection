CXX = clang++
BPF_CFLAGS = -target bpf -D__TARGET_ARCH_x86 -g -O2
CXXFLAGS = -Wall -Wno-unknown-attributes 
BPF_SRCS = $(wildcard *.bpf.c)
BPF_OBJS = $(BPF_SRCS:.bpf.c=.bpf.o)
CPP_SRCS = $(wildcard *.cpp)
CPP_OBJS = $(CPP_SRCS:.cpp=.o)
LDFLAGS = -lbpf -lxdp -lstdc++ -lpthread
TARGET = my_program

all: $(BPF_OBJS) $(TARGET)

%.bpf.o: %.bpf.c
	clang $(BPF_CFLAGS) -c -o $@ $<

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(TARGET): $(CPP_OBJS)
	$(CXX) $(CPP_OBJS) $(LDFLAGS) -o $@

.PHONY: clean
clean:
	rm -f $(BPF_OBJS) $(CPP_OBJS) $(TARGET)
