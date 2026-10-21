# C ABI parse contracts

These scenarios cover the C entry points declared in `include/expat.h` and
implemented by the candidate `liblexpat.so.1`: parser creation and user data,
handler registration, and `XML_Parse`. Each scenario runs as its own client
process against the locally built shared object and the checked-in header:

```sh
nix develop -c bash tests/c-abi-contract.sh A1
nix develop -c bash tests/c-abi-contract.sh A2
nix develop -c bash tests/c-abi-contract.sh
```

### A1 — A parser delivers ordered element callbacks during XML_Parse

**Actor.** A C application linked against `liblexpat.so.1`.

**Given.** A fresh parser from `XML_ParserCreate(NULL)`, a user-data record of
its own installed with `XML_SetUserData`, start and end element handlers
registered through `XML_SetStartElementHandler` and `XML_SetEndElementHandler`,
and the literal bytes `<r><child/></r>`.

**When.** The application calls `XML_Parse(parser, bytes, length, 1)` exactly
once on that parser.

**Then.** That call returns `XML_STATUS_OK`, and the handlers have recorded
exactly four callbacks in document order: start `r`, start `child`, end
`child`, end `r`. Inside each callback the `userData` argument equals the
pointer registered for this parser, and the application's parse-active marker
is set, so every callback is delivered before `XML_Parse` returns.

**Why.** The C route is the unit of integration; a successful status without
the parser's own handlers observing the document would not be a working parse
boundary.

### A2 — An unsupported external-entity handler fails the parser closed

**Actor.** A C application linked against `liblexpat.so.1`.

**Given.** Two fresh parsers, each with its own user-data record. The same
start/end detector is registered on both through `XML_SetElementHandler`; the
affirmative-control parser first parses `<r/>` and records one start and one
end callback. The candidate parser has a non-NULL
`XML_ExternalEntityRefHandler` registered with `XML_SetExternalEntityRefHandler`
whose locally defined callback returns 0 without touching the filesystem or
network.

**When.** The application calls `XML_Parse(candidate, "<r/>", length, 1)` once
on the candidate parser.

**Then.** That candidate call returns `XML_STATUS_ERROR`,
`XML_GetErrorCode(candidate)` is exactly `XML_ERROR_UNSUPPORTED_FEATURE`, and
the candidate detector has recorded zero start and zero end callbacks while the
control detector still holds one of each. The control detector is the same
function, so it demonstrates that the run can observe element callbacks the
candidate did not receive.

**Why.** Registration of an unsupported entity-resolving handler must refuse the
parser deterministically before any input is read, rather than accept the
handler and later attempt resolution.
