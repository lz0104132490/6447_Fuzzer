CC = gcc
CFLAGS = -Wall -Wextra -O3 -m64 -march=native -Iinclude -D_GNU_SOURCE
LDFLAGS = -lmagic 

# Directories
SRC_DIR = src
SHARED_DIR = shared
INC_DIR = include
BUILD_DIR = build

# Source files
SRCS = $(SRC_DIR)/main.c $(SRC_DIR)/util.c $(SRC_DIR)/mutate.c \
       $(SRC_DIR)/fs.c $(SRC_DIR)/json_fuzz.c
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

# Shared library
SHARED_SRC = $(SHARED_DIR)/shared.c
SHARED_LIB = shared.so

# Target binary
TARGET = fuzzer

.PHONY: all clean

all: $(TARGET) $(SHARED_LIB)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

$(SHARED_LIB): $(SHARED_SRC)
	$(CC) -shared -fPIC -o $@ $<

clean:
	rm -rf $(BUILD_DIR) $(TARGET) $(SHARED_LIB) bad_*.txt

run-test: all
	@echo "Build complete. Run with:"
	@echo "  ./$(TARGET) -b <target_binary> -i <input.json> -n <iterations>"
