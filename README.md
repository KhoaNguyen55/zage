# zage: zig implementation of age

The format specification is at [age-encryption.org/v1](https://age-encryption.org/v1). age was designed by [@Benjojo](https://benjojo.co.uk/) and [@FiloSottile](https://bsky.app/profile/did:plc:x2nsupeeo52oznrmplwapppl).

# Installation

Download executable from [here](https://github.com/KhoaNguyen55/zage/releases).

## Build from source

Clone the repo: `git clone https://github.com/KhoaNguyen55/zage.git`

Use zig build system: `zig build -Dbuild-cli --release=fast`

# Usage

There is 3 command: `keygen`, `encrypt`, and `decrypt`

For complete usage run `zage <command> --help`

## Generate key

### Example:
- `zage keygen`
- `zage keygen my_key`
- `zage keygen > my_key`

## Encrypt

With passphrase: `zage encrypt -p -o <output_file> <input_file>`

With recipient: `zage -r <public_key> -o <output_file> <input_file>`

### Example:
- with public key: `zage encrypt -r age1fmm3lmxh7rtzf7g6829tlr6a9mljq9xt4hd3yw7ffx9vgaywfeaqhg7dd3 text.txt`
- with identity file: `zage encrypt -i my_key -o msg.age text.txt`
- with stdin: `echo 'hello world!' | zage encrypt -i my_key -o msg.age --stdin`

## Decrypt 

With passphrase: `zage decrypt <input_file>`

With recipient: `zage decrypt -i <private_key_file> <input_file>`

### Example:
- text file: `zage decrypt -i my_key msg.age`
- with stdin: `cat msg.age | zage decrypt -i my_key --stdin`

# Zig library

[Documentation](https://khoanguyen55.github.io/zage/)

The library is for `zig v0.14.1` for now.

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

# Contribute

Report bugs at https://github.com/KhoaNguyen55/zage/issues

Contributing: TODO
