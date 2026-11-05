# Copyright (C) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# Umbrella build (the analog of the KSP `cpp-samples.sln` / the Rust workspace).
#
#   make          build every sample
#   make check    build and run the device-free tests (OpenSSL only)
#   make clean    remove every bin/ folder
#
# Each sample folder also builds on its own (`make -C RSA-SIGN-VERIFY`); they
# share only the header-only helpers in include/Kmpp. Variables given on the
# command line (CXX, CXXFLAGS, OPENSSL_*) are passed through to every sample.

SAMPLES := RSA-ENCRYPT-DECRYPT RSA-SIGN-VERIFY
TESTS   := tests

all: $(SAMPLES)

$(SAMPLES):
	$(MAKE) -C $@

check:
	$(MAKE) -C $(TESTS) check

clean:
	for dir in $(SAMPLES) $(TESTS); do $(MAKE) -C $$dir clean || exit 1; done

.PHONY: all check clean $(SAMPLES)