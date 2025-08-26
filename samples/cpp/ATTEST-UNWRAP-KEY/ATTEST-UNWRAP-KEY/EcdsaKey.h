// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

// A randomly generated P256 ECC Key in PKCS#8 format, DER encoded.
// We will use this key to demonstrate ECDSA signing and verification
// This will be the private key user want to import into AziHSM
const unsigned char PRIVATE_KEY_ECDSA[] = {
    48,  129, 135, 2,   1,   0,   48,  19,  6,   7,   42,  134, 72,  206, 61,  2,   1,   6,   8,   42,  134, 72,  206,
    61,  3,   1,   7,   4,   109, 48,  107, 2,   1,   1,   4,   32,  71,  202, 216, 226, 30,  43,  228, 239, 175, 5,
    185, 252, 43,  196, 162, 107, 104, 176, 205, 34,  218, 40,  165, 150, 194, 109, 63,  238, 194, 222, 177, 135, 161,
    68,  3,   66,  0,   4,   137, 128, 198, 163, 224, 78,  3,   20,  164, 123, 33,  117, 226, 186, 129, 145, 242, 141,
    221, 47,  145, 77,  79,  80,  103, 37,  7,   20,  254, 64,  160, 134, 158, 198, 238, 12,  49,  112, 47,  78,  72,
    49,  23,  44,  38,  76,  217, 236, 126, 205, 49,  136, 111, 170, 233, 154, 0,   228, 144, 183, 143, 54,  48,  51,
};
const unsigned char MESSAGE_ECDSA[] = "Hello, World!";
