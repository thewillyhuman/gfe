# Testing

What a change to GFE has to prove before it lands, and how. Three
questions, each with one place that answers it:

| Question | Answered by | Fails when |
|---|---|---|
| Does the node still do what the README promises? | the test suite, mapped to the features by [`requirements.md`](requirements.md) | a test fails, a named test is gone, a feature has no requirement |
| Is the node no slower? | `hack/loadtest.sh --against <ref>` and `cargo bench`, run by the `perf` workflow on every pull request | a scenario's CPU per request is above the base's by more than the tolerance; a bench by more than a quarter |
| Is the build sound? | the `CI` workflow | a warning, a lint, a broken doc link, an advisory, a license |

## The suite

`cargo test --workspace` runs everything: about 1,100 tests, 40 s on a
laptop once built. There are three kinds, and a reader finds each
where the README says:

- **Unit tests** sit next to the code: `foo.rs` has its tests in
  `foo_test.rs`, and nothing else is in that file. They test one function
  or type, with no sockets.
- **Functional tests** are in each crate's `tests/`, one file per feature
  (`gfe/proxy/tests/retries.rs` is the retries). Those of `gfe-proxy` run
  a whole proxy in-process, with real TLS termination, in front of mock
  backends (`tests/common/`); those of the libraries run the library
  against a peer on hyper or rustls.
- **Tests of the binary** are in `gfe/node/tests/`: they start `gfe-node`
  as an operator would and cover what only the process can show (its
  flags, its log, the ops endpoints, signals, draining, upgrading in
  place). `smoke.rs` walks through the product end to end.

Tests are named after the behaviour they protect, so that a failure reads
as a sentence (`does_not_retry_once_the_response_has_started`). A new
behaviour gets its test first, in the file of its feature; a new feature
gets a file.

CI runs the suite with [cargo-nextest](https://nexte.st), which reports
the workspace as one result, and the doctests with `cargo test --doc`,
which nextest does not run:

```bash
cargo nextest run --workspace --no-fail-fast --failure-output immediate-final
cargo test --workspace --doc
```

The kernel view needs Linux and `CAP_BPF`. Its tests skip themselves where
they cannot run and say so (`skipped:` in their output); CI runs them as
root and fails if they skipped. On a development machine that is not
Linux, run the suite in a container as well, as the product runs on
Linux:

```bash
docker run --rm -v "$PWD":/gfe:ro -w /gfe -e CARGO_TARGET_DIR=/tmp/target \
    --cap-add BPF --cap-add NET_ADMIN rust:1 bash -c \
    'apt-get update -qq && apt-get install -y -qq clang >/dev/null && cargo test --workspace'
```

The tests that wait on timers (`drain.rs`, the reload tests, the upgrade
tests) fail under heavy machine load: do not build something else next
to the suite.

## Requirements

[`requirements.md`](requirements.md) is the README's feature list written
as requirements, one section per feature in the README's order, each
naming the tests that fail when it breaks, and saying what no test proves
yet. It is the map from "what GFE promises" to "what checks it", and it is
kept true by `gfe/node/tests/requirements.rs`:

- every test a requirement names must exist, so a renamed or deleted
  test is renamed or replaced there too;
- every requirement must name what proves it;
- the requirements must follow the README's features one for one, so a
  feature added to the README without a requirement fails the suite.

So a change that adds a feature touches three places: the README's list,
`requirements.md` with the tests that prove it, and the tests themselves.
A change that fixes a behaviour adds the test that would have caught it,
and names it under its requirement when it proves something the listed
tests did not.

## Performance

The question is never "how fast is the node" but "did this change make it
slower": the node's cost depends on the machine, so the only comparison
that means something is between two builds on the same machine in the
same run. Two instruments, from the outside in.

### The load test: the whole node, against a base commit

`hack/loadtest.sh` runs the real `gfe-node` binary on loopback, set up as
in production (access log to a file, an ECDSA P-256 certificate), in
front of a mock backend, and drives a matrix of scenarios at it. Each row
ends with **the node's own CPU per request**, which is the number to
read: req/s and latencies are bounded by the load client and the backend
sharing the cores, the node's CPU is not.

| Row | What it isolates |
|---|---|
| `http · fixed` | GFE's own work per request: routing, a response it writes itself, its log line |
| `http · proxy` | plus the hop to a backend: a pooled upstream connection, both HTTP legs |
| `http · upload 400KiB` | the cost per byte, on the request size of a telemetry collector behind the node |
| `https · proxy (warm TLS)` | TLS on an established connection |
| `https · proxy + 2000 idle conns` | what thousands of kept connections that seldom send cost the requests of the others |
| `https · proxy (resumed TLS/req)` | a new connection per request: accept, a resumed handshake, the close |
| `https · proxy (full TLS/req)` | the same with a full handshake, as from a client without a session |

To decide about a change, run it against the commit the change is based
on:

```bash
./hack/loadtest.sh --against main          # 64 connections, 6 s per scenario
./hack/loadtest.sh --against main 32 4     # quicker
```

The script builds the node of that commit next to this tree's, runs the
matrix against each in turn, two rounds each (`--rounds`), so that
whatever else the host does weighs on both, and ends with a table of the
best round of each side and a verdict:

```
scenario                                 base µs/req   head µs/req    change
http  · fixed (GFE overhead)                    33.3          33.1     -0.8%
http  · proxy (+upstream)                       70.8          70.7     -0.3%
...
passed: no scenario beyond the tolerance of 10% on the node's cpu per request
```

It exits non-zero when a scenario is slower by more than the tolerance
(`--tolerance`, 10% by default), or could not be compared: a scenario
with errors on either side is not a measurement, and the row says so.
The best round is compared rather than the mean because noise on a
shared machine only adds.

What to expect: the same code on both sides compares within 1%; a quiet
laptop resolves a change of 3 to 5% on the kept-connection rows. Before
a run, let loopback clear (`netstat -an | grep -c TIME_WAIT` under a few
hundred), stop other builds, and know that the demo's containers add
background load when they are up.

The pieces are usable on their own. `--out <file>` keeps the rows of a
run as JSON lines; `gfe-loadtest compare --base a.jsonl --head b.jsonl`
compares any two such files; `gfe-loadtest run` is the load client, with
`--upload-bytes`, `--idle-connections` and `--cpu-of <pid>` for a
scenario of one's own.

### The micro-benchmarks: where in the node

`cargo bench` runs criterion over what sits on the path of every request
or every connection, in a thread, with no I/O: route matching and table
compilation (`gfe-proxy`), backend selection per policy
(`netkit-load-balancing`), a full TLS 1.3 handshake and the SNI lookup
(`netkit-tls`). They do not say whether the node got slower, the load
test does; they say where, and they catch a change in the complexity of
one of these (a match that grew with the number of routes would show as
`route_match_hit/1000` leaving `route_match_hit/10`).

Compare a change against a saved baseline of the base commit:

```bash
git stash   # or check out the base
cargo bench -p gfe-proxy --bench routing -- --save-baseline base
git stash pop
cargo bench -p gfe-proxy --bench routing -- --baseline base
```

criterion prints the change of each bench against the baseline and a
verdict. The other targets are `-p netkit-load-balancing --bench
selection` and `-p netkit-tls --bench handshake`.

### In CI

The `perf` workflow (`.github/workflows/perf.yml`) runs both on every
pull request against the commit it is based on, on one runner: the
benchmarks of the base, then of the head against them, failing on a bench
slower by more than a quarter (the runners are shared); and
`hack/loadtest.sh --against <base>` with a tolerance of 15%. The numbers
in the log are those of a four-core runner that the node shares with the
load client and the backend: read the changes, not the values.

## Before a commit

What CI checks, in the order it is quickest to learn from:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo deny check
./hack/loadtest.sh --against main      # when the change touches the path of a request
```
