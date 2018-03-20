#
# Copyright (c) 2016-2018, MIPS Tech, LLC and/or its affiliated group companies
# (“MIPS”).
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#

#LIBTEEC_CLIENT_EXPORT ?= ../libteec/out/export

CC := $(CROSS_COMPILE)gcc
CPP := $(CROSS_COMPILE)cpp
LD := $(CROSS_COMPILE)ld
AR := $(CROSS_COMPILE)ar
NM := $(CROSS_COMPILE)nm
OBJCOPY	:= $(CROSS_COMPILE)objcopy
OBJDUMP	:= $(CROSS_COMPILE)objdump
READELF	:= $(CROSS_COMPILE)readelf

SRCS +=	xtest_1000.c \
	xtest_1000_extra.c \
	xtest_5000.c \
	xtest_80000_extra.c \
	xtest_helpers.c \
	xtest_main.c \
	xtest_test.c \
	adbg/src/adbg_case.c \
	adbg/src/adbg_enum.c \
	adbg/src/adbg_expect.c \
	adbg/src/adbg_log.c \
	adbg/src/adbg_mts.c \
	adbg/src/adbg_run.c \
	adbg/src/adbg_util.c \
	adbg/src/r_list_genutil.c \
	adbg/src/security_utils_hex.c \
	adbg/src/security_utils_mem.c \

#ifeq ($(BR2_PACKAGE_XTEST_GP),y)
-include rules_xtest.generated.mk
#endif

OBJDIR := out

OBJS := $(patsubst %.c,%.o, $(SRCS))

CFLAGS += -DUSER_SPACE -DWITH_REE
CFLAGS += -I./
CFLAGS += -I./adbg/include
CFLAGS += -I./xml/include
#CFLAGS += -I$(LIBTEEC_CLIENT_EXPORT)/include
CFLAGS += -I$(STAGING_DIR)/usr/include
CFLAGS += -DWITH_CONCURRENT_TEST=1

CFLAGS += -Wall -Wcast-align -Werror \
	  -Werror-implicit-function-declaration -Wextra -Wfloat-equal \
	  -Wformat-nonliteral -Wformat-security -Wformat=2 -Winit-self \
	  -Wmissing-declarations -Wmissing-format-attribute \
	  -Wmissing-include-dirs -Wmissing-noreturn \
	  -Wmissing-prototypes -Wnested-externs -Wpointer-arith \
	  -Wshadow -Wstrict-prototypes -Wswitch-default \
	  -Wwrite-strings \
	  -Wno-missing-field-initializers -Wno-format-zero-length

CFLAGS += -g3

LDFLAGS += -L$(STAGING_DIR)/lib -lteec
LDFLAGS += -lpthread -lm -lcrypto

.PHONY: all
all: xtest

xtest: $(OBJS)
	@echo "  LD      $(OBJDIR)/$@"
	@$(CC) -o $@ $+ $(LDFLAGS)
	rm -rf $(OBJS)

%.o: %.c
	@echo '  $(CC)      $<'
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	@echo '  CLEAN $(O)'

