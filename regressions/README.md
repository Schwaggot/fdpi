# Regression Tests

Regression tests decode every PCAP in `tracefiles/` through the full fdpi pipeline and compare the serialized output
against committed text baselines. If a code change alters decoding behavior, the affected test fails with a diff.

## How It Works

1. Each PCAP file (≤ 1 MB) has a corresponding `.txt` baseline in `regressions/baselines/`.
2. The baseline is a deterministic, line-oriented dump of every decoded packet (`key=value` format covering all protocol
   layers).
3. A parameterized Google Test re-decodes the PCAP at test time and compares the output against the baseline. Any
   difference is a regression.

Defragmentation and TCP reassembly are disabled so that each packet's output is independent of cross-packet state.

## Generating Baselines

After building, generate (or regenerate) all baselines:

```bash
./build/regressions/fdpi_regression --create --all
```

Generate a baseline for a single PCAP:

```bash
./build/regressions/fdpi_regression --create --pcap tracefiles/protocol-pcap/dns.pcap
```

Optional overrides:

```bash
./build/regressions/fdpi_regression --create --all \
    --tracefiles-dir /path/to/tracefiles \
    --baselines-dir /path/to/baselines
```

Commit the resulting `regressions/baselines/` files so that CI and other developers can run the tests without
regenerating.

## Running Tests

Directly:

```bash
./build/regressions/fdpi_regression
```

Via CTest:

```bash
ctest --test-dir build -R "Regression" --output-on-failure
```

Or as part of the full test suite:

```bash
ctest --test-dir build --output-on-failure
```

## Building

The regression target is controlled by the `FDPI_BUILD_REGRESSION` CMake option (ON by default in standalone builds):

```bash
cmake -B build -DFDPI_BUILD_REGRESSION=ON
cmake --build build --target fdpi_regression
```

## Updating Baselines After Intentional Changes

If a code change intentionally alters decoding output:

1. Run `./build/regressions/fdpi_regression` to see which tests fail.
2. Regenerate baselines: `./build/regressions/fdpi_regression --create --all`
3. Review the diffs in `regressions/baselines/` to confirm they match the intended change.
4. Commit the updated baselines.
