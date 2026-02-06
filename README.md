# plocker

A zero-dependency CLI tool for encrypting and decrypting files using a master password.

## Install

```bash
npm install -g @prethora/plocker
```

## Usage

```bash
plocker [-y|--yes] <file>
```

### Encrypt a file

```bash
plocker secrets.txt
```

You'll be prompted for a password and confirmation. This creates `secrets.txt.plocker` in the same directory.

### Decrypt a file

```bash
plocker secrets.txt.plocker
```

You'll be prompted for the password. This restores the original `secrets.txt`.

### Force overwrite

By default, if the output file already exists, you'll be asked to confirm. Use `-y` to skip the prompt:

```bash
plocker -y secrets.txt
plocker --yes secrets.txt.plocker
```

## How it works

- **Encryption**: AES-256-GCM with a key derived via PBKDF2 (600,000 iterations, SHA-512)
- **File format**: Binary with a magic header, random salt, IV, GCM auth tag, password verification hash, and ciphertext
- **Password verification**: A hash of the derived key is stored in the encrypted file to provide a clear "incorrect password" error on decryption
