CC = gcc
CFLAGS = -Wall -Wextra -O3 -m64 -march=native -Iinclude -Ilibs/json_parser -D_GNU_SOURCE
LDFLAGS = -lmagic 

# Directories
SRC_DIR = src
SHARED_DIR = shared
INC_DIR = include
BUILD_DIR = build

# Source files
SRCS = $(SRC_DIR)/fuzzer.c $(SRC_DIR)/util.c $(SRC_DIR)/mutate.c \
       $(SRC_DIR)/fs.c $(SRC_DIR)/json_fuzz.c $(SRC_DIR)/csv_fuzz.c \
       $(SRC_DIR)/format_detection.c $(SRC_DIR)/save_result.c \
       $(SRC_DIR)/safe_wrapper.c $(SRC_DIR)/format_handlers.c
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

# cJSON library object
CJSON_OBJ = $(BUILD_DIR)/cjson.o

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

$(TARGET): $(OBJS) $(CJSON_OBJ)
	$(CC) $(OBJS) $(CJSON_OBJ) -o $@ $(LDFLAGS)

$(CJSON_OBJ): libs/json_parser/CJSON.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(SHARED_LIB): $(SHARED_SRC)
	$(CC) -m64 -shared -fPIC -o $@ $<

clean:
	rm -rf $(BUILD_DIR) $(TARGET) $(SHARED_LIB) bad_*.txt hang_*.txt

run-test: all
	@echo "Build complete. Run with:"
	@echo "  ./$(TARGET) -b <target_binary> -i <input.json> -n <iterations>"
