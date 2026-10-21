# One-shot document parsing contracts

These scenarios cover `LexPat.parseDocument`, the pure one-shot entry point that
decodes a complete byte sequence and parses it under explicit budgets.

### S1 — An earlier certain tag mismatch wins over a later invalid byte

**Actor.** A Lean library client.

**Given.** The literal bytes `3C 72 3E 3C 2F 73 3E C3 28` (`<r></s>` followed by
the invalid UTF-8 continuation `C3 28`) and the default `Limits`.

**When.** The client calls the public `LexPat.parseDocument` once on those bytes.

**Then.** The result is `Except.error e`, with `e.code` equal to `.tagMismatch`
and `e.reason` equal to `"tagMismatch"`, both read from the same returned error
object; a failed parse returns no event array.

**Why.** A tag mismatch the parser has already determined must be reported ahead
of an encoding failure that appears later in the input.
