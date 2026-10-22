# Security corpus sources

Every input in `cve-cases.json` is generated locally by `tests/security-cve.py`.
No upstream file, issue attachment or proof-of-concept byte is copied into this
repository, and no check reads an upstream file or contacts the network at run
time. This page records what each class cites and why the disposition is what it
is.

## CVE-2023-52425 — large-token reparsing

- Source: libexpat tag `R_2_9_0`, file `expat/tests/basic_tests.c`, function
  `test_big_tokens_scale_linearly`, lines 6525–6535.
- Raw URL: `https://raw.githubusercontent.com/libexpat/libexpat/R_2_9_0/expat/tests/basic_tests.c`
- Revision: `a76b1174c1ea52abb639a4c69d52b630a8a106a2`.
- License: the Expat license (MIT-like) with the Thai Open Source Software
  Center/Clark Cooper and Expat maintainers notices, `expat/COPYING` in that
  revision.
- Disposition: the generator is original; the upstream test is cited as the
  source of the supported large-token class on the supported surface. Its code
  is not copied.

## CVE-2018-20843 — colon-heavy XML names

- Source class: NVD entry `https://nvd.nist.gov/vuln/detail/CVE-2018-20843`.
- No upstream fixture or license was verified for import.
- Disposition: an original colon-dense raw-name generator (`a` + repeated `:` +
  `b`) at named sizes. It asserts the exact callback name and measures cost; it
  is not a claim of general denial-of-service immunity.

## CVE-2021-45960 — large attribute-count class

- Source class: NVD entry `https://nvd.nist.gov/vuln/detail/CVE-2021-45960`.
- No PoC is imported.
- Disposition: an original distinct-attribute generator within the raw-input and
  callback-payload bounds; the callback's ordered pairs are checked exactly.
  Cost is measured; attribute count has no separate public budget.

## CVE-2024-8176 — long linear internal-entity chain

- Source: libexpat issue `https://github.com/libexpat/libexpat/issues/893`.
- The linked user attachment has no verified individual license or author.
- Disposition: **feature absent**. A small local `DOCTYPE`/entity input is
  refused as `XML_ERROR_UNSUPPORTED_DTD` before declaration content. A short
  bounded reference case is compared with the pinned oracle; no
  stack-exhaustion-sized attachment is shipped or run.

## CVE-2022-43680 — external-entity parser creation under OOM

- Source: libexpat issue `https://github.com/libexpat/libexpat/issues/649`.
- The linked attachment has no verified individual license or author.
- Disposition: **feature absent**. `XML_ExternalEntityParserCreate` returns
  `NULL` and no external entity, file or network is resolved. This is not an OOM
  guarantee for the Lean runtime; the existing unsupported-family verification
  asserts the refusal.

## CVE-2021-46143 — DTD content-model group overflow

- Source: libexpat issue `https://github.com/libexpat/libexpat/issues/532`.
- The report describes a craft input of about 2 GiB.
- Disposition: **feature absent**. A short local `DOCTYPE` form is refused as
  `XML_ERROR_UNSUPPORTED_DTD`. The reported input is outside both the absent-DTD
  path and the 8 MiB raw-input budget, so it is neither shipped nor run, and
  lexpat does not claim to have fixed Expat's arithmetic bug.

## CVE-2024-50602 — resume of an unstarted parser

- Source class: NVD entry `https://nvd.nist.gov/vuln/detail/CVE-2024-50602`.
- Disposition: **feature absent**. The existing `XML_ResumeParser` refusal
  verification asserts `XML_STATUS_ERROR` and
  `XML_ERROR_UNSUPPORTED_FEATURE` (50); no new public route is added.

## CVE-2022-25235 — invalid UTF-8 validation class

- Source class: NVD entry `https://nvd.nist.gov/vuln/detail/CVE-2022-25235`.
- Disposition: **existing mitigation/bound**. The reference is the existing 18
  `encoding-attack` corpus rows with their exact expected results. They are not
  imported PoCs and are not claimed to cover every encoding flaw.

## Reproduction

```sh
nix develop -c python3 tests/security-cve.py
```

The checker validates the provenance fields above, rejects an unknown generator
or case reference, requires an exact expected result for each side, and asserts
the candidate before the optional pinned-reference comparison.
