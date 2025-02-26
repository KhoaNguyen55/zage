const std = @import("std");
const builtin = @import("builtin");

const Allocator = std.mem.Allocator;

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
        \\-i, --identity-file <file>...      Encrypt/Decrypt using identity at file, can be repeated.
        \\-r, --recipient <string>...       Encrypt to recipient, can be repeated.
        \\-R, --recipient-file <file>...     Encrypt to recipients at file, can be repeated.
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
            break :blk std.fs.cwd().openFile(path, .{ .mode = .write_only }) catch |err| {
                fatal("Can't open file '{s}': {s}", .{ path, @errorName(err) });
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
        } else {
            break :blk std.io.getStdOut().writer().any();
        }
    };

    if (args.encrypt != 0 and args.decrypt != 0) {
        std.debug.print("Can't encrypt and decrypt at the same time.", .{});
        return;
    }

    if (args.passphrase != 0 and (args.recipient.len != 0 or
        args.@"recipient-file".len != 0 or
        args.@"recipient-file".len != 0))
    {
        std.debug.print("Passphrase can not be use in conjuction with recipient or identity.", .{});
        return;
    }

    if (args.decrypt != 0) {
        fatal("Not implemented.", .{});
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

    std.debug.print("Passphrase: ", .{});

    try changeInputEcho(false);
    try stdin.reader().streamUntilDelimiter(passphrase.writer(), '\n', null);
    try changeInputEcho(true);

    return passphrase.toOwnedSlice();
}

fn handleEncryption(allocator: Allocator, args: anytype, input: std.fs.File, output: std.io.AnyWriter) !void {
    var encryptor = age.AgeEncryptor.encryptInit(allocator);

    if (args.@"recipient-file".len != 0) {
        fatal("Not implemented.", .{});
    }

    if (args.recipient.len != 0) {
        for (args.recipient) |str| {
            const identity = age.x25519.X25519Recipient.parse(allocator, str) catch |err| {
                fatal("Failed to create recipient '{s}': {s}", .{ str, @errorName(err) });
            };

            try encryptor.addRecipient(identity);
        }
    } else if (args.passphrase != 0) {
        const passphrase = try getPassphrase(allocator);
        defer allocator.free(passphrase);

        std.debug.print("\nEncrypting using passphrase, this might take a while...\n", .{});

        const identity = age.scrypt.ScryptRecipient.create(allocator, passphrase, null) catch |err| {
            fatal("Failed to create scrypt recipient: {s}", .{@errorName(err)});
        };
        defer identity.destroy();

        try encryptor.addRecipient(identity);
    } else {
        fatal("Missing identity, recipient or passphrase.", .{});
    }

    const buffer = try input.readToEndAlloc(allocator, std.math.maxInt(usize));
    defer allocator.free(buffer);

    try encryptor.finalizeRecipients(output);
    try encryptor.update(buffer);
    try encryptor.finish();
}
