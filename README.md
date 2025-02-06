# zage: zig implementation of age

The format specification is at [age-encryption.org/v1](https://age-encryption.org/v1). age was designed by [@Benjojo](https://benjojo.co.uk/) and [@FiloSottile](https://bsky.app/profile/did:plc:x2nsupeeo52oznrmplwapppl).

# Installation

TODO

## Features

TODO

## Usage

TODO

## Zig library

The library is for `zig v0.13.0` for now.

To install as a zig library you can run the `zig fetch` command:

```
zig fetch --save https://github.com/KhoaNguyen55/zage/releases/download/v0.1.0-age-test/release.tar.gz
```

Then add the following to `build.zig`:

```
const age = b.dependency("age", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("age", age.module("age"));
```

See `TODO` for api documentations
