# The Recurring Decoder Bug

**A decoder that memorises what one system happened to send.**

This is the mistake this codebase keeps making. Every instance below looked like careful
code when it was written. Several were written *because* the author was being careful:
an observed value was recorded faithfully and then treated as a law of the protocol.

If you are fixing a bug here, check for this first. If you are adding a decoder or an
encoder, this is the review it will get. It is the concrete form of two project rules:
never hardcode anything per function module, and never ship a wire value without a
capture, a probe, or an `[ASSUMED]` label (see the Pull Requests section of
`CONTRIBUTING.md`).

## Why it happens here

RFC has no public specification. You learn a structure by looking at what a system
sends, and the most natural way to write that down is to encode exactly what you saw:

```python
# The row is 402 bytes.
rows = [data[i : i + 402] for i in range(0, len(data), 402)]
```

That is a faithful record of one observation and a false claim about the protocol. The
row is 402 bytes *for the function module you measured*. The next one has a different
row type, and the slice returns the right number of rows with the wrong contents.

**The tell** is a comparison against a literal, a fixed list of accepted shapes, or a
normalisation rule, applied to something that varies by peer, release, function module
or configuration.

**The symptom** is "works on my system", or worse, plausible values that are wrong.
Unlike a crash, a wrong row width, sign or language produces data that looks fine.

## The instances so far

| What was pinned | What it broke | How it was found | Fixed in |
|---|---|---|---|
| Row widths `_GFI_ROW_BYTES = 402`, `_DFIES_ROW_BYTES = 138`, two modules' result rows, as a floor for slicing any table | Every table whose row type has another width | Removed in v0.1.5 with the fix below | Width from the buffer and the row count |
| A TABLE's row width from `TypeDesc.uc_size`, then from `0x0302`'s `row_size` | The same row type arrives packed on one path and padded to 4 bytes on the other: `RFC_GET_FUNCTION_INTERFACE` for `BAPI_USER_GET_DETAIL` returned 44 rows, 40 of them corrupt | A live call (v0.1.5) | `codec._decode_table`: `len(data) // row_count` |
| SAProuter service as a fixed 6-byte NUL-padded field | Any service *name* longer than 5 characters | Right by coincidence for 4-digit ports (`message_server.md`) | Route built from the actual lengths |
| Message server port as `36<NN>` | Every system installed after NetWeaver 7.0, where the port is free | Live scan (`message_server.md`, "Ports") | No formula; the port is supplied or resolved |
| Packed sign nibble `0xB` read as positive, `0xA`/`0xE` refused (#70) | A negative amount with sign `0xB` arrived positive | Capture of every nibble (`bcd_sign_nibbles.json`) | The table the capture shows |
| Packed field of all zero bytes refused (#69) | A field that is zero to the reference client | Same capture | Read as zero |
| One-character logon language uppercased (#66) | `a` (Afrikaans) logged on as `A` (Arabic) | Capture of the logon (`handshake.md`) | Sent as given |
| XML character reference read with an 11-character lookahead (#74) | A reference padded past eight digits stayed as text | XML grammar; the capture showed none | Decided by value, digit run bounded |
| Packed rounding half-to-even, digits through a 28-digit context (#71) | 1.005 sent as 1.00; values over 28 digits silently rounded | Reference client's bytes (`bcd_rounding.json`) | Exact integer arithmetic, rounding as observed |

## What the fix looks like

**Bound what varies by nature; keep every structural check strict.** Widening a bound is
not permission to accept malformed input.

**Measure, don't remember.** Take a length from the wire or from what the server
declares, then check it:

- A TABLE's row width is `len(data) // row_count`, from the bytes and the row count the
  server sent (`codec._decode_table`), not from either of the two descriptor fields that
  are each right for only one path.

**Decide by value, not by spelling.** If the thing has many legal spellings, normalise
it and check the result:

- An XML character reference is parsed to its integer and accepted when that integer is
  a Unicode scalar value, whatever its zero padding (`invoke._xml_unescape`).

**Record the whole observed set, and refuse the rest.** When a capture shows a closed
set of values, encode exactly that set and keep refusing what it does not cover:

- Sign nibbles `0xA`–`0xF` and the all-zero field come from one capture; a digit in the
  sign position is still refused because nothing shows how it reads
  (`serialization.md`, Known Gaps).

**Never add another memorised case.** Accepting a seventh layout because the sixth did
not match is the bug repeating, not a fix.

## When a bound is correct

Not every literal is this bug. Fixed-width fields, limits against resource exhaustion
and fail-closed guards are legitimate, and removing one to make a test pass is a worse
bug than the one you started with. Current examples, each with its reason in a comment:

- `_XML_REF_MAX_DIGITS = 32`: bounds the scan of a character reference; XML allows any
  padding, so this limits work, not legal input of any realistic size.
- `_LZ4_MAX_EXPANSION = 255`: follows from the LZ4 block format, where each
  length-extension byte adds at most 255.
- `_BASXML_MAX_BYTES`: refuses absurd payloads before they are decoded.

The question is not "is there a literal here" but **"does the thing this literal
describes vary by peer, release, function module or configuration?"** If it does not,
pin it and say why in a comment. If you cannot tell, say so, label it `[ASSUMED]` with
what would settle it, and prefer a capture to a decision.

## The test that catches it

**A property test over the full legal range of whatever the peer controls**: every
length, every value, every ordering, not one example. For instance, from
`tests/test_xml_character_references.py`:

```python
@given(SCALARS, st.integers(min_value=0, max_value=_XML_REF_MAX_DIGITS))
def test_a_reference_decodes_the_same_at_every_padded_width(code, width):
    assert _xml_unescape(f"&#{str(code).rjust(width, '0')};") == chr(code)
```

For the decoders that read the peer's bytes (NI framing, the tag stream, the gateway
and logon frames, packed BCD, the router and message-server replies),
`tests/test_fuzz_decoders.py` holds the three standing properties: round trip across
every length-form boundary, the same result however the stream is chunked, and hostile
input (mutated golden frames) raising only the decoder's typed error. A new decoder
belongs there too.

Pair it with a **fail-closed regression** proving malformed input is still refused:
unknown values, truncation, out of range, the wrong order.

Then **control-test both**: revert the fix (`git stash push -- src/`) and run the new tests
again.

- The property or capture-replay test **must fail** without the fix. If it passes, it
  tests nothing.
- The fail-closed tests usually pass in both states. That is correct: they guard the
  bound, not the fix.
- If a fail-closed test *also* fails without the fix, the old code refused that input
  for the wrong reason. Worth recording: an incidental refusal is one you cannot rely on.

Where a live system is available, the strongest version of the property is the capture
itself: replay what the reference client and the server actually exchanged
(`tests/golden/`), and compare saprfclib's bytes with the reference client's.
