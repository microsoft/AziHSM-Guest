# Copyright (C) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# Device-free tests for the shared helpers: `make check` builds and runs
# bin/KmppTests. Needs OpenSSL only (no KMPP, no AziHSM device). See ../common.mk.

PROGRAM := KmppTests
include ../common.mk

check: all
	./$(TARGET)

.PHONY: check
