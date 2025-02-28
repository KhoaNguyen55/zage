const std = @import("std");
const builtin = @import("builtin");

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const clap = @import("clap");
const age = @import("age");

const fatal = std.zig.fatal;
const assert = std.debug.assert;

fn printUsage() void {
    std.debug.print(
        \\Usage: zage [-h] [-e | -d] [-i <file>...] [-r <string>...] [-R <file>...] [-p] [-o <file>] <file>
        \\
    , .{});
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        const leak = gpa.deinit();
        std.debug.assert(leak == .ok);
    }

    const allocator = gpa.allocator();

    const params = comptime clap.parseParamsComptime(
        \\-h, --help                        Display this help and exit.
        \\-e, --encrypt                     Encrypt input to output, default.
        \\-d, --decrypt                     Decrypt input to output.
        \\    --force                       Override output file when decrypting.
        \\-i, --identity-file <file>...     Encrypt/Decrypt using identity at file, can be repeated.
        \\-r, --recipient <string>...       Encrypt to recipient, can be repeated.
        \\-R, --recipient-file <file>...    Encrypt to recipients at file, can be repeated.
        \\-p, --passphrase                  Encrypt using passphrase.
        \\-o, --output <file>               Path to output file, default to stdout.
        \\<file>                            Path to file to encrypt or decrypt.
        \\
    );

    const parsers = comptime .{
        .file = clap.parsers.string,
        .string = clap.parsers.string,
    };

    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, parsers, .{
        .allocator = allocator,
        .diagnostic = &diag,
    }) catch |err| {
        diag.report(std.io.getStdErr().writer(), err) catch {};
        return err;
    };
    defer res.deinit();

    const args = res.args;

    if (args.help != 0) {
        printUsage();
        std.debug.print("Options:\n", .{});
        return clap.help(std.io.getStdErr().writer(), clap.Help, &params, .{});
    }

    const input = blk: {
        if (res.positionals.len == 0) {
            fatal("Missing input file.", .{});
        }
        const path = res.positionals[0];
        break :blk std.fs.cwd().openFile(path, .{}) catch |err| {
            fatal("Can't open file '{s}': {s}", .{ path, @errorName(err) });
        };
    };
    defer input.close();

    const output_file = blk: {
        if (args.output) |path| {
            var opt: std.fs.File.CreateFlags = .{};
            if (args.decrypt != 0 and args.force == 0) {
                opt.exclusive = true;
            }

            break :blk std.fs.cwd().createFile(path, opt) catch |err| switch (err) {
                error.PathAlreadyExists => fatal("Decrypting won't override existing file, use --force to override", .{}),
                else => fatal("Can't open file '{s}': {s}", .{ path, @errorName(err) }),
            };
        } else {
            break :blk null;
        }
    };
    defer {
        if (output_file) |file| {
            file.close();
        }
    }

    const output = blk: {
        if (output_file) |file| {
            break :blk file.writer().any();
        } else if (args.decrypt != 0) {
            break :blk std.io.getStdOut().writer().any();
        } else {
            fatal("Won't output binary to stdout, use -o <file>", .{});
        }
    };

    if (args.encrypt != 0 and args.decrypt != 0) {
        fatal("Can't encrypt and decrypt at the same time.", .{});
    }

    if (args.passphrase != 0 and (args.recipient.len != 0 or
        args.@"recipient-file".len != 0 or
        args.@"identity-file".len != 0))
    {
        fatal("Passphrase can not be use in conjuction with recipient or identity.", .{});
    }

    if (args.passphrase == 0 and
        args.recipient.len == 0 and
        args.@"recipient-file".len == 0 and
        args.@"identity-file".len == 0)
    {
        fatal("Missing identity, recipient or passphrase.", .{});
    }

    if (args.decrypt != 0) {
        try handleDecryption(allocator, args, input, output);
    } else {
        try handleEncryption(allocator, args, input, output);
    }
}

fn changeInputEcho(enable: bool) !void {
    if (builtin.os.tag == .windows) {
        const handle = std.io.getStdIn().handle;

        var flags: u32 = undefined;
        if (std.os.windows.kernel32.GetConsoleMode(handle, &flags) == 0) {
            fatal("Not inside a terminal", .{});
        }

        const echo_enable: u32 = 0x0004;
        if (enable) {
            flags &= ~echo_enable;
        } else {
            flags &= echo_enable;
        }

        assert(std.os.windows.kernel32.SetConsoleMode(handle, flags) != 0);
    } else {
        var termios = try std.posix.tcgetattr(std.posix.STDIN_FILENO);
        if (enable) {
            termios.lflag.ECHO = true;
        } else {
            termios.lflag.ECHO = false;
        }
        try std.posix.tcsetattr(std.posix.STDIN_FILENO, .NOW, termios);
    }
}

fn getPassphrase(allocator: Allocator) ![]const u8 {
    const stdin = std.io.getStdIn();

    var passphrase = std.ArrayList(u8).init(allocator);

    try stdin.writeAll("Passphrase: ");

    try changeInputEcho(false);
    try stdin.reader().streamUntilDelimiter(passphrase.writer(), '\n', null);
    try changeInputEcho(true);

    return passphrase.toOwnedSlice();
}

fn handleDecryption(allocator: Allocator, args: anytype, input: std.fs.File, output: std.io.AnyWriter) !void {
    var decryptor = try age.AgeDecryptor.decryptInit(allocator, input.reader().any());

    if (args.@"identity-file".len != 0) {
        try addIdentityFromFiles(allocator, .{ .decryptor = &decryptor }, args.@"identity-file");
    }

    //TODO: detect passphrase

    try decryptor.finalizeIdentities();

    while (try decryptor.next()) |data| {
        try output.writeAll(data);
    }
}

fn handleEncryption(allocator: Allocator, args: anytype, input: std.fs.File, output: std.io.AnyWriter) !void {
    var encryptor = age.AgeEncryptor.encryptInit(allocator);

    if (args.@"identity-file".len != 0) {
        try addIdentityFromFiles(allocator, .{ .encryptor = &encryptor }, args.@"identity-file");
    }

    if (args.@"recipient-file".len != 0) {
        try addRecipientFromFiles(allocator, &encryptor, args.@"recipient-file");
    }

    if (args.recipient.len != 0) {
        for (args.recipient) |str| {
            try addRecipientFromString(allocator, &encryptor, str);
        }
    }

    if (args.passphrase != 0) {
        const passphrase = try getPassphrase(allocator);
        defer allocator.free(passphrase);

        std.debug.print("\nEncrypting using passphrase, this might take a while...\n", .{});

        // since passphrase lives in the same scope
        // create Recipient directly instead of using Create(),
        // prevent a heap allocation, using it directly does feel dirty
        // might change the API, or make a seperate one that don't allocate anything instead
        const identity = age.scrypt.ScryptRecipient{
            .allocator = allocator,
            .passphrase = passphrase,
            .work_factor = 18,
        };

        try encryptor.addRecipient(identity);
    }

    const buffer = try input.readToEndAlloc(allocator, std.math.maxInt(usize));
    defer allocator.free(buffer);

    try encryptor.finalizeRecipients(output);
    try encryptor.update(buffer);
    try encryptor.finish();
}

const AgeProcessor = union(enum) {
    encryptor: *age.AgeEncryptor,
    decryptor: *age.AgeDecryptor,
};

fn addIdentityFromString(allocator: Allocator, processor: AgeProcessor, identity: []const u8) !void {
    if (std.mem.startsWith(u8, identity, "AGE-SECRET-KEY-")) {
        const x25519_identity = try age.x25519.X25519Identity.parse(allocator, identity);
        switch (processor) {
            .encryptor => |encryptor| {
                try encryptor.*.addRecipient(x25519_identity.recipient());
            },
            .decryptor => |decryptor| {
                try decryptor.*.addIdentity(x25519_identity);
            },
        }
    } else if (std.mem.startsWith(u8, identity, "AGE-PLUGIN-")) {
        const index = std.mem.indexOfScalarPos(u8, identity, 11, '-');
        if (index) |idx| {
            const plugin_name = identity[11..idx];
            _ = plugin_name;
            fatal("Support for plugins is not implemented", .{});
        } else {
            return error.UnrecognizedIdentity;
        }
    } else {
        return error.UnrecognizedIdentity;
    }
}

fn addIdentityFromFiles(allocator: Allocator, processor: AgeProcessor, paths: []const []const u8) !void {
    var identity_string = ArrayList(u8).init(allocator);
    defer identity_string.deinit();

    for (paths) |path| {
        const file = std.fs.cwd().openFile(path, .{}) catch |err| {
            fatal("Can't open identity files at '{s}': {s}", .{ path, @errorName(err) });
        };
        defer file.close();

        std.log.debug("Reading identity file at {s}", .{path});

        var line_num: usize = 1;
        while (true) : ({
            line_num += 1;
            identity_string.clearRetainingCapacity();
        }) {
            file.reader().streamUntilDelimiter(identity_string.writer(), '\n', null) catch |err| {
                switch (err) {
                    error.EndOfStream => break,
                    else => return err,
                }
            };

            if (identity_string.items.len == 0) {
                std.log.debug("Skipping empty string at line: {}", .{line_num});
                continue;
            }
            if (std.mem.startsWith(u8, identity_string.items, "#")) {
                std.log.debug("Skipping comment at line: {}", .{line_num});
                continue;
            }

            std.log.debug("Processing identity string at line: {}", .{line_num});

            const trimmed = std.mem.trimRight(u8, identity_string.items, "\r");
            addIdentityFromString(allocator, processor, trimmed) catch |err| switch (err) {
                error.UnrecognizedIdentity => fatal("Unrecognized identity in file: '{s}' at line: '{}'", .{ path, line_num }),
                else => return err,
            };
        }
    }
}

fn addRecipientFromString(allocator: Allocator, encryptor: *age.AgeEncryptor, recipient: []const u8) !void {
    if (std.mem.startsWith(u8, recipient, "age1")) {
        const index = std.mem.indexOfScalarPos(u8, recipient, 4, '1');
        if (index) |idx| {
            const plugin_name = recipient[4..idx];
            _ = plugin_name;
            fatal("Support for plugins is not implemented", .{});
        } else {
            const x25519_recipient = try age.x25519.X25519Recipient.parse(allocator, recipient);
            try encryptor.*.addRecipient(x25519_recipient);
        }
    } else {
        fatal("Unrecognized recipient: {s}", .{recipient});
    }
}

fn addRecipientFromFiles(allocator: Allocator, encryptor: *age.AgeEncryptor, paths: []const []const u8) !void {
    var recipient_string = ArrayList(u8).init(allocator);
    defer recipient_string.deinit();

    for (paths) |path| {
        const file = std.fs.cwd().openFile(path, .{}) catch |err| {
            fatal("Can't open recipient files at '{s}': {s}", .{ path, @errorName(err) });
        };
        defer file.close();

        while (true) {
            file.reader().streamUntilDelimiter(recipient_string.writer(), '\n', null) catch |err| {
                switch (err) {
                    error.EndOfStream => break,
                    else => return err,
                }
            };

            if (recipient_string.items.len == 0) continue;
            if (std.mem.startsWith(u8, recipient_string.items, "#")) continue;

            const trimmed = std.mem.trimRight(u8, recipient_string.items, "\r");
            try addRecipientFromString(allocator, encryptor, trimmed);
            recipient_string.clearRetainingCapacity();
        }
    }
}
