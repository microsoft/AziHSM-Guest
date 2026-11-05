# Copyright (C) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# Shared build rules for the KMPP C++ samples. Each program folder's Makefile
# sets PROGRAM (its folder / source / binary name) and includes this file:
#
#   <PROGRAM>/<PROGRAM>.cpp  ->  <PROGRAM>/bin/<PROGRAM>
#
# The shared code is header-only (include/Kmpp), so every program is a single
# translation unit. OpenSSL 3 libcrypto is located with pkg-config. libkmpp is
# NOT linked: it is loaded at run time with dlopen, so the KMPP development
# package is not needed to build.
#
# Knobs (all overridable on the command line, e.g. `make CXX=clang++`):
#   CXX, CXXFLAGS        compiler + flags (C++17 is always enforced)
#   PKG_CONFIG           pkg-config binary used to locate OpenSSL
#   OPENSSL_CFLAGS       override the OpenSSL include flags (skips pkg-config)
#   OPENSSL_LIBS         override the OpenSSL link flags   (skips pkg-config)

ifndef PROGRAM
  $(error PROGRAM must be set by the including Makefile)
endif

# Directory of this file (with a trailing slash), relative to the program folder.
KMPP_ROOT := $(dir $(lastword $(MAKEFILE_LIST)))

CXXFLAGS   ?= -Wall -Wextra -O2
PKG_CONFIG ?= pkg-config

OPENSSL_CFLAGS ?= $(shell $(PKG_CONFIG) --cflags libcrypto 2>/dev/null)
OPENSSL_LIBS   ?= $(or $(shell $(PKG_CONFIG) --libs libcrypto 2>/dev/null),-lcrypto)

CXXSTD   := -std=c++17
CPPFLAGS += -I$(KMPP_ROOT)include $(OPENSSL_CFLAGS)
LDLIBS   += $(OPENSSL_LIBS) -ldl

HEADERS := $(wildcard $(KMPP_ROOT)include/Kmpp/*.h)
BINDIR  := bin
TARGET  := $(BINDIR)/$(PROGRAM)

all: $(TARGET)

$(TARGET): $(PROGRAM).cpp $(HEADERS) | $(BINDIR)
	$(CXX) $(CXXSTD) $(CPPFLAGS) $(CXXFLAGS) $< -o $@ $(LDFLAGS) $(LDLIBS)

# Create the output directory on demand (order-only prerequisite).
$(BINDIR):
	mkdir -p $@

clean:
	rm -rf $(BINDIR)

.PHONY: all clean
