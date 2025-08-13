const std = @import("std");

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayListUnmanaged;
const builtin = @import("builtin");

const clap = @import("clap");
const age = @import("age");
const age_plugin = @import("age_plugin");
const client = @import("client.zig");
const getInput = client.getInput;

const fatal = std.process.fatal;
const assert = std.debug.assert;

const SubCommand = enum {
    help,
    encrypt,
    decrypt,
    keygen,
};

fn parseCommand(str: []const u8) !SubCommand {
    const cmd = std.meta.stringToEnum(SubCommand, str);
    return cmd orelse SubCommand.help;
}

fn printUsageHelp(comptime usage: []const u8, comptime params: anytype) !void {
    std.debug.print(usage, .{});
    return clap.help(std.io.getStdErr().writer(), clap.Help, params, .{});
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;

    const allocator, const is_debug = gpa: {
        break :gpa switch (builtin.mode) {
            .Debug, .ReleaseSafe => .{ gpa.allocator(), true },
            .ReleaseFast, .ReleaseSmall => .{ std.heap.smp_allocator, false },
        };
    };
    defer if (is_debug) {
        _ = gpa.deinit();
    };

    var iter = try std.process.ArgIterator.initWithAllocator(allocator);
    defer iter.deinit();

    _ = iter.next();

    const main_params = comptime clap.parseParamsComptime(
        \\-h, --help    Display this help and exit.
        \\<command>
        \\
    );

    const usage =
        \\ Usage: zage (encrypt | decrypt | keygen) [options]
        \\
    ;

    const main_parsers = .{ .command = parseCommand };

    var diag = clap.Diagnostic{};
    var res = clap.parseEx(clap.Help, &main_params, main_parsers, &iter, .{
        .diagnostic = &diag,
        .allocator = allocator,
        .terminating_positional = 0,
    }) catch |err| {
        try diag.report(std.io.getStdErr().writer(), err);
        return printUsageHelp(usage, &main_params);
    };
    defer res.deinit();

    if (res.args.help != 0 or res.positionals[0] == null) {
        return printUsageHelp(usage, &main_params);
    }

    const command = res.positionals[0].?;
    switch (command) {
        .keygen => try keygenSubCmd(allocator, &iter),
        .decrypt => try decryptSubCmd(allocator, &iter),
        .encrypt => try encryptSubCmd(allocator, &iter),
        else => return printUsageHelp(usage, &main_params),
    }
}

fn keygenSubCmd(allocator: std.mem.Allocator, iter: *std.process.ArgIterator) !void {
    const usage =
        \\ Usage: zage keygen <file>
        \\
    ;
    const params = comptime clap.parseParamsComptime(
        \\-h, --help                        Display this help and exit.
        \\<file>                            Path to file to write key into.
        \\
    );

    const parsers = comptime .{
        .file = clap.parsers.string,
    };

    var diag = clap.Diagnostic{};
    var res = clap.parseEx(clap.Help, &params, parsers, iter, .{
        .allocator = allocator,
        .diagnostic = &diag,
    }) catch |err| {
        diag.report(std.io.getStdErr().writer(), err) catch {};
        return printUsageHelp(usage, &params);
    };
    defer res.deinit();

    const args = res.args;

    if (args.help != 0) {
        return printUsageHelp(usage, &params);
    }

    const new_key = age.x25519.X25519Identity.generate();
    const output = blk: {
        if (res.positionals[0]) |path| {
            break :blk std.fs.cwd().createFile(path, .{}) catch |err| {
                fatal("Can't open file '{s}': {s}", .{ path, @errorName(err) });
            };
        } else {
            break :blk std.io.getStdOut();
        }
    };
    defer output.close();

    const output_fmt =
        \\# Created: TODO
        \\# Public key: {public}
        \\{secret}
        \\
    ;
    try output.writer().print(output_fmt, .{ new_key, new_key });
    if (!output.isTty()) {
        std.debug.print("public key: {public}\n", .{new_key});
    }
}

fn decryptSubCmd(allocator: std.mem.Allocator, iter: *std.process.ArgIterator) !void {
    const usage =
        \\ Usage: zage decrypt [--force] [-i <file>] [-o <file>] <file>
        \\
    ;
    const params = comptime clap.parseParamsComptime(
        \\-h, --help                        Display this help and exit.
        \\    --force                       Override output file when decrypting.
        \\-i, --identity-file <file>...     Decrypt using identity at file, can be repeated.
        \\                                  If the file is encrypted using a passphrase it will be detect automatically.
        \\-o, --output <file>               Path to output file, default to stdout.
        \\    --stdin                       Use stdin instead of a file path to decrypt.
        \\<file>                            Path to file to decrypt.
        \\
    );

    const parsers = comptime .{
        .file = clap.parsers.string,
    };

    var diag = clap.Diagnostic{};
    var res = clap.parseEx(clap.Help, &params, parsers, iter, .{
        .allocator = allocator,
        .diagnostic = &diag,
    }) catch |err| {
        diag.report(std.io.getStdErr().writer(), err) catch {};
        return printUsageHelp(usage, &params);
    };
    defer res.deinit();

    const args = res.args;

    if (args.help != 0) {
        return printUsageHelp(usage, &params);
    }

    const input = blk: {
        if (args.stdin != 0) {
            break :blk std.io.getStdIn();
        } else {
            const path = res.positionals[0] orelse fatal("Missing input file.", .{});
            break :blk std.fs.cwd().openFile(path, .{}) catch |err| {
                fatal("Can't open file '{s}': {s}", .{ path, @errorName(err) });
            };
        }
    };
    defer input.close();

    const output = blk: {
        if (args.output) |path| {
            var opt: std.fs.File.CreateFlags = .{ .truncate = false };
            if (args.force == 0) {
                opt.exclusive = true;
            }

            break :blk std.fs.cwd().createFile(path, opt) catch |err| switch (err) {
                error.PathAlreadyExists => fatal("Decrypting won't override existing file, use --force to override", .{}),
                else => fatal("Can't open file '{s}': {s}", .{ path, @errorName(err) }),
            };
        } else {
            break :blk std.io.getStdOut();
        }
    };
    defer output.close();

    handleDecryption(allocator, args, input, output) catch |err| {
        fatal("Can't decrypt file: {s}", .{@errorName(err)});
    };
}

fn encryptSubCmd(allocator: std.mem.Allocator, iter: *std.process.ArgIterator) !void {
    const usage =
        \\ Usage: zage encrypt (-i <file>... -r <string>... -R <file>... | -p) (-o <file> | --stdout) (<file> | --stdin)
        \\
    ;
    const params = comptime clap.parseParamsComptime(
        \\-h, --help                        Display this help and exit.
        \\-i, --identity-file <file>...     Encrypt using identity at file, can be repeated.
        \\-r, --recipient <string>...       Encrypt to recipient, can be repeated.
        \\-R, --recipient-file <file>...    Encrypt to recipients at file, can be repeated.
        \\-p, --passphrase                  Encrypt using passphrase.
        \\-o, --output <file>               Path to output file.
        \\    --stdout                      Output encryted file to stdout.
        \\    --stdin                       Use stdin instead of a file path to encrypt.
        \\<file>                            Path to file to encrypt
        \\
    );

    const parsers = comptime .{
        .file = clap.parsers.string,
        .string = clap.parsers.string,
    };

    var diag = clap.Diagnostic{};
    var res = clap.parseEx(clap.Help, &params, parsers, iter, .{
        .allocator = allocator,
        .diagnostic = &diag,
    }) catch |err| {
        diag.report(std.io.getStdErr().writer(), err) catch {};
        return printUsageHelp(usage, &params);
    };
    defer res.deinit();

    const args = res.args;

    if (args.help != 0) {
        return printUsageHelp(usage, &params);
    }

    const input = blk: {
        if (args.stdin != 0) {
            break :blk std.io.getStdIn();
        } else {
            const path = res.positionals[0] orelse fatal("Missing input file.", .{});
            break :blk std.fs.cwd().openFile(path, .{}) catch |err| {
                fatal("Can't open file '{s}': {s}", .{ path, @errorName(err) });
            };
        }
    };
    defer input.close();

    const output = blk: {
        if (args.output) |path| {
            break :blk std.fs.cwd().createFile(path, .{ .truncate = false }) catch |err| switch (err) {
                else => fatal("Can't open file '{s}': {s}", .{ path, @errorName(err) }),
            };
        } else if (args.stdout != 0) {
            break :blk std.io.getStdOut();
        } else {
            fatal("Use -o <file>, or force output binary to stdout with --stdout.", .{});
        }
    };
    defer output.close();

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

    if (args.stdin != 0 and args.passphrase != 0) {
        fatal("Encryption using passphrase and stdin is not supported.", .{});
    }

    handleEncryption(allocator, args, input, output) catch |err| {
        fatal("Can't encrypt file: {s}", .{@errorName(err)});
    };
}

fn handleDecryption(allocator: Allocator, args: anytype, input: std.fs.File, output: std.fs.File) !void {
    var decryptor = try age.AgeDecryptor.decryptInit(allocator, input.reader().any());

    const expect_passphrase = blk: {
        if (decryptor.header.recipients.items.len != 1) break :blk false;
        break :blk std.mem.eql(u8, decryptor.header.recipients.items[0].type, "scrypt");
    };

    if (args.stdin != 0 and expect_passphrase) {
        fatal("Decryption using passphrase and stdin is not supported.", .{});
    }

    if (expect_passphrase) {
        const passphrase = try getInput(allocator, "Passphrase: ", true);
        defer allocator.free(passphrase);

        std.debug.print("\nDecrypting using passphrase, this might take a while...\n", .{});

        // since passphrase lives in the same scope
        // create Identity directly instead of using Create(),
        // prevent a heap allocation
        const identity = age.scrypt.ScryptIdentity{
            .passphrase = passphrase,
        };

        try decryptor.addIdentity(identity);
    } else if (args.@"identity-file".len != 0) {
        try addIdentityFromFiles(allocator, .{ .decryptor = &decryptor }, args.@"identity-file");
    } else {
        fatal("Missing identity file.", .{});
    }

    decryptor.finalizeIdentities() catch |err| switch (err) {
        age.HeaderError.NoValidIdentities => {
            if (expect_passphrase) return error.WrongPassphrase else return err;
        },
        else => return err,
    };

    if (!output.isTty()) try output.setEndPos(0);

    while (try decryptor.next()) |data| {
        try output.writeAll(data);
    }
}

fn handleEncryption(allocator: Allocator, args: anytype, input: std.fs.File, output: std.fs.File) !void {
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
        const passphrase = try getInput(allocator, "Passphrase: ", true);
        defer allocator.free(passphrase);

        std.debug.print("\nEncrypting using passphrase, this might take a while...\n", .{});

        // since passphrase lives in the same scope
        // create Recipient directly instead of using Create(),
        // prevent a heap allocation
        const identity = age.scrypt.ScryptRecipient{
            .passphrase = passphrase,
            .work_factor = 18,
        };

        try encryptor.addRecipient(identity);
    }

    const buffer = try input.readToEndAlloc(allocator, std.math.maxInt(usize));
    defer allocator.free(buffer);

    if (!output.isTty()) try output.setEndPos(0);

    try encryptor.finalizeRecipients(output.writer().any());
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
        var client_identity = try client.ClientUI.create(allocator, identity, true);
        defer client_identity.destroy();

        switch (processor) {
            .encryptor => |encryptor| {
                try encryptor.*.addRecipient(&client_identity);
            },
            .decryptor => |decryptor| {
                try decryptor.*.addIdentity(&client_identity);
            },
        }
    } else {
        return error.UnrecognizedIdentity;
    }
}

fn addIdentityFromFiles(allocator: Allocator, processor: AgeProcessor, paths: []const []const u8) !void {
    var identity_string: ArrayList(u8) = .empty;
    defer identity_string.deinit(allocator);

    for (paths) |path| {
        const file = std.fs.cwd().openFile(path, .{}) catch |err| {
            fatal("Can't open identity files at '{s}': {s}", .{ path, @errorName(err) });
        };
        defer file.close();

        var line_num: usize = 1;
        while (true) : ({
            line_num += 1;
            identity_string.clearRetainingCapacity();
        }) {
            file.reader().streamUntilDelimiter(identity_string.writer(allocator), '\n', null) catch |err| {
                switch (err) {
                    error.EndOfStream => {
                        if (identity_string.items.len == 0) break;
                    },
                    else => return err,
                }
            };

            if (identity_string.items.len == 0) {
                std.log.debug("Skipping empty string at line: {}, in file: {s}", .{ line_num, path });
                continue;
            }
            if (std.mem.startsWith(u8, identity_string.items, "#")) {
                std.log.debug("Skipping comment at line: {}, in file: {s}", .{ line_num, path });
                continue;
            }

            std.log.debug("Processing identity string at line: {}", .{line_num});

            const trimmed = std.mem.trimRight(u8, identity_string.items, "\r");
            addIdentityFromString(allocator, processor, trimmed) catch |err| switch (err) {
                error.UnrecognizedIdentity, error.UnableToStartPlugin => std.log.info("Skipping unrecognized identity in file: '{s}' at line: '{}'", .{ path, line_num }),
                else => return err,
            };
        }
    }
}

fn addRecipientFromString(allocator: Allocator, encryptor: *age.AgeEncryptor, recipient: []const u8) !void {
    if (std.mem.startsWith(u8, recipient, "age1")) {
        const index = std.mem.indexOfScalarPos(u8, recipient, 4, '1');
        if (index) |_| {
            var client_recipient = client.ClientUI.create(allocator, recipient, false) catch |err| switch (err) {
                error.UnableToStartPlugin => return std.log.info("Unable to start plugin for recipient: {s}", .{recipient}),
                else => return err,
            };
            defer client_recipient.destroy();

            try encryptor.*.addRecipient(&client_recipient);
        } else {
            const x25519_recipient = try age.x25519.X25519Recipient.parse(allocator, recipient);
            try encryptor.*.addRecipient(x25519_recipient);
        }
    } else {
        std.log.info("Unrecognized recipient: {s}", .{recipient});
    }
}

fn addRecipientFromFiles(allocator: Allocator, encryptor: *age.AgeEncryptor, paths: []const []const u8) !void {
    var recipient_string: ArrayList(u8) = .empty;
    defer recipient_string.deinit(allocator);

    for (paths) |path| {
        const file = std.fs.cwd().openFile(path, .{}) catch |err| {
            fatal("Can't open recipient files at '{s}': {s}", .{ path, @errorName(err) });
        };
        defer file.close();

        var line_num: usize = 1;
        while (true) : ({
            line_num += 1;
            recipient_string.clearRetainingCapacity();
        }) {
            file.reader().streamUntilDelimiter(recipient_string.writer(allocator), '\n', null) catch |err| {
                switch (err) {
                    error.EndOfStream => {
                        if (recipient_string.items.len == 0) break;
                    },
                    else => return err,
                }
            };

            if (recipient_string.items.len == 0) {
                std.log.debug("Skipping empty string at line: {}, in file: {s}", .{ line_num, path });
                continue;
            }
            if (std.mem.startsWith(u8, recipient_string.items, "#")) {
                std.log.debug("Skipping comment at line: {}, in file: {s}", .{ line_num, path });
                continue;
            }

            const trimmed = std.mem.trimRight(u8, recipient_string.items, "\r");
            try addRecipientFromString(allocator, encryptor, trimmed);
            recipient_string.clearRetainingCapacity();
        }
    }
}
