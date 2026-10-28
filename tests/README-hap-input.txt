Minimal TCP-read framing reproduction
====================================

Run from this PR checkout. The test uses native localhost TCP sockets and
extracts the production processRequest() and badRequestError() implementations.
No ESP32 or installation is contacted. Endpoint callbacks are stubbed; this
checks delivery of a complete request to the dispatcher, not a complete pairing
exchange. The plaintext case does not call the cryptographic stub.

The request is one 127-byte HTTP POST /pair-verify containing a 37-byte M1 TLV
body: State=1 and a 32-byte X25519 public key (the standard base point).
The same bytes are sent either together, or with the receiver polled after
only the first 20 or 126 bytes have arrived. No second HTTP request is created.

Unchanged implementation:

  git show 107ffc07f4455754ea89068d8cf2e992de3583e6:src/HAP.cpp > /tmp/original-HAP.cpp
  HAP_TEST_MINIMAL=1 HAP_TEST_SOURCE=/tmp/original-HAP.cpp python3 tests/test_hap_input.py

Expected: whole request PASS; both split deliveries FAIL with HTTP400=1 and
no endpoint dispatch. The command intentionally exits nonzero.

Patched implementation:

  HAP_TEST_MINIMAL=1 python3 tests/test_hap_input.py

Expected: all three PASS, one dispatch each, exit zero.

The original failure occurs before endpoint validation: processRequest() treats
client.available() as a complete message and closes on an incomplete header or
body. All cases are far below the 8096-byte limit.

Sanitizer option for either command:

  CXXFLAGS="-Wall -Wextra -Werror -Wno-sign-compare -fsanitize=address,undefined -g"

-Wno-sign-compare preserves the original production function without editing
its existing signed/unsigned comparisons for this host test.

This is a synthetic TCP test. It does not establish that this receive defect
caused the earlier installation slowdown, which resolved after HomeKit was
re-paired. It requires no change to HAP message semantics or Apple's protocol.
