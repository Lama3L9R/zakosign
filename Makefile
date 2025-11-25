# Toolchain
CC ?= clang
LD ?= ld.lld

# path macros
BIN_PATH := bin
OBJ_PATH := obj
SRC_PATH := src
DBG_PATH := debug

# flags
CFLAGS := -I$(SRC_PATH) -fPIC -Wno-deprecated-declarations -Werror -c $(CFLAGS)
LDFLAGS := -Wall $(LDFLAGS) -Wfuse-ld=$(LD)

# compile macros
TARGET_NAME_DYNAMIC := zakosign

ifeq ($(DEBUG_MODE),1)
	CFLAGS := -DBUILD_DEBUG=1 -O0 -g $(CFLAGS)
	LDFLAGS := -O0 -g $(LDFLAGS)
else
	CFLAGS := $(CFLAGS) -O3
	LDFLAGS := $(LDFLAGS) -O3
endif
ifeq ($(shell uname -s),Darwin)
    LDFLAGS := $(LDFLAGS) \
		-Lboringssl/build \
		-lcrypto \
		-lssl
else
	LDFLAGS := $(LDFLAGS) \
		-Lboringssl/build \
		-l:libcrypto.a \
		-l:libssl.a
endif


CFLAGS := \
	-Iboringssl/include \
	$(CFLAGS)

TARGET_DYNAMIC := $(BIN_PATH)/lib$(TARGET_NAME_DYNAMIC).so
TARGET_CLI := $(BIN_PATH)/$(TARGET_NAME_DYNAMIC)

# src files & obj files
SRC := utils.c \
	syscall.c \
	sys_linux.c \
	sys_osx.c \
	esignature/hasher.c \
	esignature/file_helper.c \
	esignature/esignature.c \
	esignature/ed25519_sign.c \
	esignature/cert_helper.c

SRC_CLI := $(SRC) \
	cli.c \
	param.c

OBJ := $(patsubst %.c, $(OBJ_PATH)/%.o, $(SRC))
OBJ_CLI := $(patsubst %.c, $(OBJ_PATH)/%.o, $(SRC_CLI))

# Find all .bin files in SRC_PATH and its subdirectories
BIN_FILES := $(shell find $(SRC_PATH) -name '*.bin')
# Generate corresponding .o files for the bin files
BIN_OBJ := $(patsubst $(SRC_PATH)/%.bin, $(OBJ_PATH)/bin_%.o, $(BIN_FILES))

# Add BIN_OBJ to the main OBJ list to ensure they are compiled and linked
OBJ += $(BIN_OBJ)
OBJ_CLI += $(BIN_OBJ)

# clean files list
DISTCLEAN_LIST := $(OBJ_CLI)
CLEAN_LIST := $(TARGET_DYNAMIC) \
			  $(TARGET_CLI) \
			  $(DISTCLEAN_LIST)

# default rule
default: makedir all

$(TARGET_DYNAMIC): $(OBJ)
	$(info $(NULL)  ELF     $(TARGET_DYNAMIC))
	@$(CC) -shared -o $@ $(OBJ) $(LDFLAGS)

$(TARGET_CLI): $(OBJ_CLI)
	$(info $(NULL)  ELF     $(TARGET_CLI))
	@$(CC) -o $@ $(OBJ_CLI) $(LDFLAGS)

$(OBJ_PATH)/%.o: $(SRC_PATH)/%.c
	$(info $(NULL)  CC      $< $@)
	@$(CC) $(CFLAGS) -o $@ $<

$(OBJ_PATH)/bin_%.o: $(SRC_PATH)/%.bin
	$(info $(NULL)  BIN2OBJ $< $@)
	@CC=$(CC) tools/bin2obj $< $@ "$(CFLAGS)"

# phony rules
.PHONY: envinfo
envinfo:

$(info Platform: $(shell uname -a))
$(info CC: $(CC))
$(info CFlags : $(CFLAGS))
$(info LDFlags: $(LDFLAGS))
$(info Targets: $(TARGET_DYNAMIC)) 

.PHONY: makedir
makedir:
	@mkdir -p $(BIN_PATH) $(OBJ_PATH)
	@mkdir -p $(sort $(dir $(OBJ))) $(BIN_PATH)

.PHONY: all
all: envinfo $(TARGET_DYNAMIC) $(TARGET_CLI)

.PHONY: clean
clean:
	@echo "  CLEAN $(CLEAN_LIST)"
	@rm -rf $(CLEAN_LIST)

