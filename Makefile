CC:=$(shell which gcc)

CFLAGS:=-Wall -Werror -Wextra \
-pedantic -fsanitize=address -DDEBUG \
-fanalyzer -O3 -g -std=gnu11

INCLUDE:=include/
LDFLAGS:=-lm -pthread

SRC_DIR:=src
SRC:=$(wildcard $(SRC_DIR)/*.c)
OUT_DIR:=out

VALID_TARGETS:=build clean help

EXECUTABLES:=$(SRC:$(SRC_DIR)/%.c=%)

all: $(EXECUTABLES)

$(EXECUTABLES): % : $(SRC_DIR)/%.c
	@mkdir -p $(OUT_DIR)
	$(CC) $(LDFLAGS) $(CFLAGS) -I$(INCLUDE) -o $(OUT_DIR)/$@ $(SRC)

.PHONY:
clean:
	$(info Removing $(OUT_DIR))
	@rm -rf $(OUT_DIR)

.PHONY:
help: ;
	$(info Valid targets: $(VALID_TARGETS))
