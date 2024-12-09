CXX = clang++
CXXFLAGS = -Wall -ggdb -O1 -std=c++17 -O1 -I$(ROOT_DIR)/pcapplusplus/3rdparty/header
SRC_DIR = $(ROOT_DIR)/pcapplusplus/3rdparty/src
BUILD_DIR = $(ROOT_DIR)/bin/pcapplusplus/3rdparty/src

SRC_FILES = $(wildcard $(addsuffix /*.cpp, $(SRC_DIR)))
OBJ_FILES = $(SRC_FILES:$(SRC_DIR)/%.cpp=$(BUILD_DIR)/%.o)

TARGET_LIB = $(BUILD_DIR)/lib3rdparty.a

$(info SRC_FILES = $(SRC_FILES))
$(info OBJ_FILES = $(OBJ_FILES))

all: $(TARGET_LIB)

$(TARGET_LIB): $(OBJ_FILES)
	@mkdir -p $(BUILD_DIR)
	ar rcs $@ $^

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(BUILD_DIR)

.PHONY: all clean
