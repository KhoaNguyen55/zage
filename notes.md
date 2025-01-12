# Notes:
- stanzas is the encrypted `file key` addressed to the recipients i.e, `-> X25519 XEl0dJ6y3C7KZkgmgWUicg63EyXJiwBJW8PdYJ/cYBE`

# Age File format:
- MUST BE TREATED AS BINARY
- MAY use .age
- Header wraps file key for one or more recipients
    - Can only be upwrap by one of the corresponding identities
- Binary payload of the encrypted data

## file key:
- each file is encrypted with a 128-bit symmetric `file key`
- `file key` is a randomly generated 16 bytes of [CSPRNG](https://ziglang.org/documentation/master/std/#std.crypto.tlcsprng.interface) output
    - MUST NOT be reused across multiple files

## Header:
- Version line
- One or more recipients stanzas
- MAC
```
age-encryption.org/v1
-> X25519 XEl0dJ6y3C7KZkgmgWUicg63EyXJiwBJW8PdYJ/cYBE
qRS0AMjdjPvZ/WT08U2KL4G+PIooA3hy38SvLpvaC1E
--- HK2NmOBN9Dpq0Gw6xMCuhFcQlQLvZ/wQUi/2scLG75s
```

### Sections:
- Can be parse by looking at the first 3 characters
    - version: `age`
    - recipients: `-> `
    - MAC: `---`
- Ends at the next newline for version and MAC lines
- Ends at the first line shorter than 64 columns for stanzas
- Always ends with a line feed `0x0A`

### Version line:
- Always start with `age-encryption.org/` follows by any version string

### Recipient stanza
- Start with `-> `
- After the space followed by one or more space-seperated arguments and a base64-encoded body wrapped at 64 columns
- The body MUST end with a line shorter than 64 characters, which MAY be empty
- Each stanza wrap the `file key` independently
- It is RECOMMENDED that non-native recipient implementations use fully-qualified names as the first stanza argument, such as example.com/enigma, to avoid ambiguity and conflicts.
    - use the full name of the encryption algorithm as the first argument of the stanza

### Header MAC
- Start with `---`
- After a space followed by the base64-encoded MAC of the header
- MAC key is computed with [HKDF](https://ziglang.org/documentation/master/std/#std.crypto.hkdf.HkdfSha256), HMAC is computed with [HMAC-SHA-256](https://ziglang.org/documentation/master/std/#std.crypto.hmac.sha2.HmacSha256) over the whole header up to and including the `---` (excluding the space following it).

for example:
```
[]u8 key = HKDF-SHA-256(ikm = file key, salt = empty)
```

### Payload
- Start immediately after the header
- Begins with a 16-bytes nonce (one of number) generated from a CSPRNG, nonce MUST be generated for each file

Payload key:
```
[]u8 key = HKDF-SHA-256(ikm = file key, salt = nonce)
```

- Splits into chunks of 64 KiB
    - Each chunk encrypted with [ChaCha20-Poly1305](https://ziglang.org/documentation/master/std/#std.crypto.chacha20.ChaCha20Poly1305) using the payload key and 12-bytes nonce.
    - 12-bytes nonce
        - first 11 bytes are big endian chunk counter starting at zero incrementing by one for each subsequent chunk
        - the last byte is 0x01 for the final chunk and 0x00 for all preceding ones
    - The final chunk MAY be shorter than 64 KiB but MUST NOT be empty unless the whole payload is empty

# Implementation notes:
- Use [interfaces](https://www.openmymind.net/Zig-Interfaces/) to allow extension

## Encoder
- MUST generate canonical base64 according to RFC 4648
## Decoder
- MUST reject non-canonical encodings and encodings ending with = padding characters
- Streaming decryption MUST signal an error if the end of file is reached without seccessfully decypting the final chunk
- Payload can be seek by jumping a head in the chunk increment
    - seek relatively from the end MUST first decrypt the last chunk and verify it is valid
## Identity
- Provided with full set of stanzas
- Recognized the stanzas addressed to them from their arguments
    - The identity should know the the stanzas are for them from the arguments (the text between the first space after `->` and the last space before the b64 text that ends with a new line)
- MUST ignored unrecognized stanzas
## Recipient
- MAY choose to include an identifier of the specific recipient i.e, a short hash of the public key
    - anonymity and unlinkability is sacrifices in this case
### Native Types

