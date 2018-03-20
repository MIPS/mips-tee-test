CROSS_COMPILE = mips-mti-linux-gnu-
CC = $(CROSS_COMPILE)gcc
AR = $(CROSS_COMPILE)ar
OBJ = starter.o

LIBTEEC_INCLUDE_DIR=$(STAGING_DIR)/usr/include
LIBTEEC_LIB_DIR=$(STAGING_DIR)/lib

CFLAGS := -Wall -Wbad-function-cast -Wcast-align \
		-Werror-implicit-function-declaration -Wextra \
		-Wfloat-equal -Wformat-nonliteral -Wformat-security \
		-Wformat=2 -Winit-self -Wmissing-declarations \
		-Wmissing-format-attribute -Wmissing-include-dirs \
		-Wmissing-noreturn -Wmissing-prototypes -Wnested-externs \
		-Wpointer-arith -Wshadow -Wstrict-prototypes \
		-Wswitch-default -Wunsafe-loop-optimizations \
		-Wwrite-strings -Werror
CFLAGS += -fPIC -I $(LIBTEEC_INCLUDE_DIR)

.phony: all clean

all: starter

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

starter: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) -L$(LIBTEEC_LIB_DIR) -lteec

clean:
	rm -rf *.o starter
