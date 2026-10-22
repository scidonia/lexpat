# C ABI parse contracts

These scenarios cover the C entry points declared in `include/expat.h` and
implemented by the candidate `liblexpat.so.1`: parser creation and user data,
handler registration, and `XML_Parse`. Each scenario runs as its own client
process against the locally built shared object and the checked-in header:

```sh
nix develop -c bash tests/c-abi-contract.sh A1
nix develop -c bash tests/c-abi-contract.sh A2
nix develop -c bash tests/c-abi-contract.sh
nix develop -c bash tests/c-abi-oom-contract.sh A3
```

A1 and A2 load the locally built shared object. A3 links `cabi/expat.c` and
the Lean module objects directly into a test-only executable, so the allocator
wrapper placed with `-Wl,--wrap=malloc` covers the shim's own allocations;
wrapping the prebuilt shared object at run time would not intercept them.

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

### A3 — A failed shim allocation during XML_Parse is reported as NO_MEMORY

**Actor.** A C application linked to a test-only direct-linked build of
`cabi/expat.c` and the Lean module objects, with a deterministic allocator
wrapper.

**Given.** Two fresh parsers. The same start/end detector is registered on
both through `XML_SetUserData` and `XML_SetElementHandler`. The
affirmative-control parser first parses `<r/>` with the allocator intact and
records one start callback, which also warms the Lean runtime. A fresh
candidate parser is then created, its detector registered, and the allocator
wrapper is armed to fail the first `malloc` the linked shim makes during the
candidate parse.

**When.** The application calls `XML_Parse(candidate, "<r/>", 4, 1)` once on
the candidate parser.

**Then.** That call returns `XML_STATUS_ERROR`, `XML_GetErrorCode(candidate)`
equals `XML_ERROR_NO_MEMORY`, and the candidate detector has recorded zero
start callbacks while the control detector holds one. The status, the error
code and the callback count are read from the same candidate parser the
failed allocation belongs to.

**Why.** An allocation the shim cannot satisfy while dispatching a callback is
an out-of-memory condition, not a malformed wire frame; reporting it as
`XML_ERROR_NO_MEMORY` keeps the failure attributable to resource exhaustion.
