# LOX Vault Android

A small offline Android file-encryption app using the same `.enc` format as the Python implementation.

## Cryptography

- Argon2id password KDF
- 256-bit derived key
- AES-256-GCM authenticated encryption
- Fresh 16-byte random salt per file
- Fresh 12-byte random nonce per file
- Versioned header: `LOXENC01`
- Header is authenticated as AES-GCM associated data
- No password is stored
- Base64 is only an outer transport encoding

The mobile defaults are Argon2id time=3, memory=65536 KiB, parallelism=2. These parameters are stored in each file, so the decryptor reads them from the authenticated header.

## Interoperability

The binary/header layout matches the production Python implementation created in this conversation:

`MAGIC(8) | VERSION(1) | KDF(1) | CIPHER(1) | TIME(4) | MEMORY_KIB(4) | PARALLELISM(4) | SALT(16) | NONCE(12) | CIPHERTEXT+TAG`

The complete binary is then Base64 encoded.

## Build

Open the project in Android Studio, or use Gradle 9.5 with Android SDK API 37 / Build Tools 36.0.0.

```bash
gradle assembleRelease
```

A GitHub Actions workflow is included under `.github/workflows/build.yml` and produces an unsigned release APK artifact.

## Important production note

The app currently reads the selected file into memory before encrypting/decrypting. That is appropriate for small/medium files but should be replaced with a carefully designed chunked AEAD format before accepting very large files in a production deployment.

The release APK must also be signed with the team's real Android signing key before distribution.
