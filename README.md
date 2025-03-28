# zage: zig implementation of age

The format specification is at [age-encryption.org/v1](https://age-encryption.org/v1). age was designed by [@Benjojo](https://benjojo.co.uk/) and [@FiloSottile](https://bsky.app/profile/did:plc:x2nsupeeo52oznrmplwapppl).

# Installation

Download executable from [here](https://github.com/KhoaNguyen55/zage/releases).

## Build from source

Clone the repo: `git clone https://github.com/KhoaNguyen55/zage.git`

Use zig build system: `zig build -Dbuild-cli --release=safe`

# Usage

For complete usage run `zage --help`

## Encrypt

With passphrase: `zage -p -o <output_file> <input_file>`

With recipient: `zage -r age1ylsp6apgw0e9526s5tgaqj70qerc0286hl95quzg2jq5r30ewqxquaxhpp -o <output_file> <input_file>`

## Decrypt 

With passphrase: `zage -d <input_file>`

With recipient: `zage -d -i private_key <input_file>`

# Zig library

[Documentation](https://khoanguyen55.github.io/zage/)

The library is for `zig v0.14.0` for now.

To install as a zig library you can run the `zig fetch` command:

```
zig fetch --save https://github.com/KhoaNguyen55/zage/archive/refs/tags/<tag>.tar.gz
```

Then add the following to `build.zig`:

```
const age = b.dependency("age", .{
    .target = target,
    .optimize = optimize,
});
exe_mod.addImport("age", age.module("age"));
// exe_mod.addImport("age_plugin", age.module("age_plugin")); // uncomment if you're developing a plugin
```

# Contributes

Report bugs at https://github.com/KhoaNguyen55/zage/issues

Contributing: TODO
