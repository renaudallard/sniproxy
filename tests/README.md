# Test Build Instructions

To build the standalone test binaries without running the full project build, first generate the Autotools files and configure the build tree:

```sh
./autogen.sh
./configure
```

The configure step will check for and report any missing development dependencies (such as `libev-dev` and `libpcre3-dev`). After configuration succeeds, individual tests can be built from the `tests` directory. For example, to rebuild the buffer unit tests:

```sh
make -C tests buffer_test
```

You can then run the binary directly:

```sh
./tests/buffer_test
```

These steps were used to rerun the buffer tests in this change.
