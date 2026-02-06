#!/usr/bin/env node

import { createCipheriv, createDecipheriv, createHash, pbkdf2Sync, randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import { createInterface, Interface as ReadlineInterface } from "node:readline";

const EXTENSION = ".plocker";
const MAGIC = Buffer.from("PLOCKER");
const SALT_LENGTH = 32;
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const VERIFICATION_HASH_LENGTH = 32;
const PBKDF2_ITERATIONS = 600_000;
const KEY_LENGTH = 32;

const HEADER_LENGTH =
  MAGIC.length + SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH + VERIFICATION_HASH_LENGTH;

function deriveKey(password: string, salt: Buffer): Buffer {
  return pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, KEY_LENGTH, "sha512");
}

function verificationHash(key: Buffer): Buffer {
  return createHash("sha256").update(key).digest();
}

// Line queue for non-TTY mode: buffers lines so multiple prompts work with piped input
class LineQueue {
  private rl: ReadlineInterface;
  private lines: string[] = [];
  private waiters: ((line: string) => void)[] = [];

  constructor() {
    this.rl = createInterface({ input: process.stdin, output: process.stderr });
    this.rl.on("line", (line) => {
      const waiter = this.waiters.shift();
      if (waiter) {
        waiter(line);
      } else {
        this.lines.push(line);
      }
    });
  }

  nextLine(): Promise<string> {
    const buffered = this.lines.shift();
    if (buffered !== undefined) {
      return Promise.resolve(buffered);
    }
    return new Promise((resolve) => {
      this.waiters.push(resolve);
    });
  }

  close(): void {
    this.rl.close();
  }
}

let lineQueue: LineQueue | null = null;

function getLineQueue(): LineQueue {
  if (!lineQueue) {
    lineQueue = new LineQueue();
  }
  return lineQueue;
}

function promptHidden(prompt: string): Promise<string> {
  return new Promise((resolve) => {
    const stdin = process.stdin;

    if (!stdin.isTTY) {
      process.stderr.write(prompt);
      getLineQueue().nextLine().then(resolve);
      return;
    }

    // TTY: use raw mode for hidden input
    process.stderr.write(prompt);

    const wasRaw = stdin.isRaw ?? false;
    stdin.setRawMode(true);
    stdin.resume();

    let input = "";

    const onData = (data: Buffer) => {
      const char = data.toString("utf8");

      for (const c of char) {
        const code = c.charCodeAt(0);

        if (code === 3) {
          // Ctrl+C
          cleanup();
          process.stderr.write("\n");
          process.exit(1);
        } else if (code === 13 || code === 10) {
          // Enter
          cleanup();
          process.stderr.write("\n");
          resolve(input);
          return;
        } else if (code === 127 || code === 8) {
          // Backspace
          input = input.slice(0, -1);
        } else if (code >= 32) {
          input += c;
        }
      }
    };

    const cleanup = () => {
      stdin.removeListener("data", onData);
      stdin.setRawMode(wasRaw);
      stdin.pause();
    };

    stdin.on("data", onData);
  });
}

function promptConfirm(prompt: string): Promise<boolean> {
  return new Promise((resolve) => {
    const stdin = process.stdin;

    if (!stdin.isTTY) {
      process.stderr.write(prompt);
      getLineQueue().nextLine().then((line) => {
        resolve(line.toLowerCase() === "y");
      });
      return;
    }

    const rl = createInterface({ input: stdin, output: process.stderr });
    rl.question(prompt, (answer) => {
      rl.close();
      resolve(answer.toLowerCase() === "y");
    });
  });
}

function encrypt(data: Buffer, password: string): Buffer {
  const salt = randomBytes(SALT_LENGTH);
  const iv = randomBytes(IV_LENGTH);
  const key = deriveKey(password, salt);
  const vHash = verificationHash(key);

  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return Buffer.concat([MAGIC, salt, iv, authTag, vHash, encrypted]);
}

function decrypt(data: Buffer, password: string): Buffer {
  if (data.length < HEADER_LENGTH) {
    process.stderr.write("Error: file is too small to be a valid .plocker file.\n");
    process.exit(1);
  }

  const magic = data.subarray(0, MAGIC.length);
  if (!magic.equals(MAGIC)) {
    process.stderr.write("Error: file is not a valid .plocker file.\n");
    process.exit(1);
  }

  let offset = MAGIC.length;
  const salt = data.subarray(offset, offset + SALT_LENGTH);
  offset += SALT_LENGTH;
  const iv = data.subarray(offset, offset + IV_LENGTH);
  offset += IV_LENGTH;
  const authTag = data.subarray(offset, offset + AUTH_TAG_LENGTH);
  offset += AUTH_TAG_LENGTH;
  const storedHash = data.subarray(offset, offset + VERIFICATION_HASH_LENGTH);
  offset += VERIFICATION_HASH_LENGTH;
  const ciphertext = data.subarray(offset);

  const key = deriveKey(password, salt);
  const vHash = verificationHash(key);

  if (!vHash.equals(storedHash)) {
    process.stderr.write("Error: incorrect password.\n");
    process.exit(1);
  }

  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);

  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    process.stderr.write("Error: decryption failed.\n");
    process.exit(1);
  }
}

function usage(): never {
  process.stderr.write("Usage: plocker [-y|--yes] <file>\n");
  process.exit(1);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  let forceOverwrite = false;
  let filePath: string | undefined;

  for (const arg of args) {
    if (arg === "-y" || arg === "--yes") {
      forceOverwrite = true;
    } else if (arg.startsWith("-")) {
      process.stderr.write(`Unknown option: ${arg}\n`);
      usage();
    } else if (filePath === undefined) {
      filePath = arg;
    } else {
      process.stderr.write("Error: only one file argument is supported.\n");
      usage();
    }
  }

  if (filePath === undefined) {
    usage();
  }

  const inputPath = resolve(filePath);

  if (!existsSync(inputPath)) {
    process.stderr.write(`Error: file not found: ${filePath}\n`);
    process.exit(1);
  }

  const isDecrypt = inputPath.endsWith(EXTENSION);

  if (isDecrypt) {
    // Decrypt mode
    const password = await promptHidden("Password: ");

    if (password.length === 0) {
      process.stderr.write("Error: password cannot be empty.\n");
      process.exit(1);
    }

    const data = readFileSync(inputPath);
    const decrypted = decrypt(data, password);

    const outputPath = inputPath.slice(0, -EXTENSION.length);

    if (existsSync(outputPath) && !forceOverwrite) {
      const overwrite = await promptConfirm(
        `File already exists: ${basename(outputPath)}. Overwrite? [y/N] `
      );
      if (!overwrite) {
        process.stderr.write("Aborted.\n");
        process.exit(1);
      }
    }

    writeFileSync(outputPath, decrypted);
    process.stderr.write(`Decrypted: ${basename(outputPath)}\n`);
  } else {
    // Encrypt mode
    const password = await promptHidden("New password: ");

    if (password.length === 0) {
      process.stderr.write("Error: password cannot be empty.\n");
      process.exit(1);
    }

    const confirm = await promptHidden("Confirm password: ");

    if (password !== confirm) {
      process.stderr.write("Error: passwords do not match.\n");
      process.exit(1);
    }

    const data = readFileSync(inputPath);
    const encrypted = encrypt(data, password);

    const outputPath = inputPath + EXTENSION;

    if (existsSync(outputPath) && !forceOverwrite) {
      const overwrite = await promptConfirm(
        `File already exists: ${basename(outputPath)}. Overwrite? [y/N] `
      );
      if (!overwrite) {
        process.stderr.write("Aborted.\n");
        process.exit(1);
      }
    }

    writeFileSync(outputPath, encrypted);
    process.stderr.write(`Encrypted: ${basename(outputPath)}\n`);
  }
}

main()
  .catch((err) => {
    process.stderr.write(`Error: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  })
  .finally(() => {
    lineQueue?.close();
  });
