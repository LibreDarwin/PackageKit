# Copyright (C) 2026, LibreDarwin
# SPDX-License-Identifier: BSD-3-Clause
# Reimplementation of Apple's PackageKit command-line tools:
# pkgbuild(1) and productbuild(1).
#
# Build layout: every artifact lives under build/; final tools go to
# build/release/ or build/debug/ per CONFIG.
#
# Portable to both GNU make and BSD make (bmake): no pattern rules, no
# ifeq/ifdef/.if conditionals and no $(if)/$(shell) functions.  Per-config
# flags come from make/<CONFIG>.mk so both make variants behave identically.

CONFIG ?= release
SDK    ?= /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk
CC     := /Users/sunneva/xnuports-root/devel/xcode-tools/build/release/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang

-include make/$(CONFIG).mk

BUILD_DIR := build/$(CONFIG)
OBJDIR    := $(BUILD_DIR)/obj

CFLAGS := $(OPT) -std=c11 -D_DARWIN_C_SOURCE -isysroot "$(SDK)" -Wall -Wextra
LDLIBS := -lz

PKG  := $(BUILD_DIR)/pkgbuild
PKG_OBJS := $(OBJDIR)/pkgbuild/pkgbuild.o $(OBJDIR)/pkgbuild/analyze.o \
	$(OBJDIR)/pkgbuild/bom.o $(OBJDIR)/pkgbuild/payload.o \
	$(OBJDIR)/pkgbuild/xar.o

PROD := $(BUILD_DIR)/productbuild
PROD_OBJS := $(OBJDIR)/productbuild/productbuild.o \
	$(OBJDIR)/productbuild/analyze.o $(OBJDIR)/productbuild/bom.o \
	$(OBJDIR)/productbuild/dist.o $(OBJDIR)/productbuild/payload.o \
	$(OBJDIR)/productbuild/xar.o

PREFIX  ?= /usr/local
DESTDIR ?=

all: $(PKG) $(PROD)

$(PKG): $(PKG_OBJS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $(PKG_OBJS) $(LDLIBS)

$(PROD): $(PROD_OBJS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $(PROD_OBJS) $(LDLIBS)

# pkgbuild

$(OBJDIR)/pkgbuild/pkgbuild.o: Sources/pkgbuild/pkgbuild.c Sources/pkgbuild/xar.h Sources/pkgbuild/analyze.h Sources/pkgbuild/payload.h Sources/pkgbuild/bom.h
	@mkdir -p $(OBJDIR)/pkgbuild
	$(CC) $(CFLAGS) -c -o $@ Sources/pkgbuild/pkgbuild.c

$(OBJDIR)/pkgbuild/analyze.o: Sources/pkgbuild/analyze.c Sources/pkgbuild/analyze.h
	@mkdir -p $(OBJDIR)/pkgbuild
	$(CC) $(CFLAGS) -c -o $@ Sources/pkgbuild/analyze.c

$(OBJDIR)/pkgbuild/bom.o: Sources/pkgbuild/bom.c Sources/pkgbuild/bom.h
	@mkdir -p $(OBJDIR)/pkgbuild
	$(CC) $(CFLAGS) -c -o $@ Sources/pkgbuild/bom.c

$(OBJDIR)/pkgbuild/payload.o: Sources/pkgbuild/payload.c Sources/pkgbuild/payload.h
	@mkdir -p $(OBJDIR)/pkgbuild
	$(CC) $(CFLAGS) -c -o $@ Sources/pkgbuild/payload.c

$(OBJDIR)/pkgbuild/xar.o: Sources/pkgbuild/xar.c Sources/pkgbuild/xar.h
	@mkdir -p $(OBJDIR)/pkgbuild
	$(CC) $(CFLAGS) -c -o $@ Sources/pkgbuild/xar.c

# productbuild

$(OBJDIR)/productbuild/productbuild.o: Sources/productbuild/productbuild.c Sources/productbuild/xar.h Sources/productbuild/analyze.h Sources/productbuild/payload.h Sources/productbuild/bom.h Sources/productbuild/dist.h
	@mkdir -p $(OBJDIR)/productbuild
	$(CC) $(CFLAGS) -c -o $@ Sources/productbuild/productbuild.c

$(OBJDIR)/productbuild/analyze.o: Sources/productbuild/analyze.c Sources/productbuild/analyze.h
	@mkdir -p $(OBJDIR)/productbuild
	$(CC) $(CFLAGS) -c -o $@ Sources/productbuild/analyze.c

$(OBJDIR)/productbuild/bom.o: Sources/productbuild/bom.c Sources/productbuild/bom.h
	@mkdir -p $(OBJDIR)/productbuild
	$(CC) $(CFLAGS) -c -o $@ Sources/productbuild/bom.c

$(OBJDIR)/productbuild/dist.o: Sources/productbuild/dist.c Sources/productbuild/dist.h
	@mkdir -p $(OBJDIR)/productbuild
	$(CC) $(CFLAGS) -c -o $@ Sources/productbuild/dist.c

$(OBJDIR)/productbuild/payload.o: Sources/productbuild/payload.c Sources/productbuild/payload.h
	@mkdir -p $(OBJDIR)/productbuild
	$(CC) $(CFLAGS) -c -o $@ Sources/productbuild/payload.c

$(OBJDIR)/productbuild/xar.o: Sources/productbuild/xar.c Sources/productbuild/xar.h
	@mkdir -p $(OBJDIR)/productbuild
	$(CC) $(CFLAGS) -c -o $@ Sources/productbuild/xar.c

# Smoke test: both tools must at least parse their own option tables and
# report their version.  Behavioral parity against the system oracles
# (/usr/bin/pkgbuild, /usr/bin/productbuild) lands in tests/ later.
test: all
	@$(PKG) --tool-version >/dev/null
	@$(PROD) --tool-version >/dev/null
	@echo "pkgbuild/productbuild smoke OK"

install: all
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(PKG) $(DESTDIR)$(PREFIX)/bin/pkgbuild
	install -m 0755 $(PROD) $(DESTDIR)$(PREFIX)/bin/productbuild

clean:
	rm -rf build

.PHONY: all test install clean
