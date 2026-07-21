// cryptographer_js.js — криптограф (шифрование файлов) на JavaScript (Node.js)

const crypto = require('crypto');
const fs = require('fs');
const { promisify } = require('util');
const readFile = promisify(fs.readFile);
const writeFile = promisify(fs.writeFile);

const SALT_LEN = 16;
const NONCE_LEN = 12;
const TAG_LEN = 16;
const ITERATIONS = 100000;
const KEY_LEN = 32;

function deriveKey(password, salt) {
    return crypto.pbkdf2Sync(password, salt, ITERATIONS, KEY_LEN, 'sha256');
}

async function encryptFile(input, output, password) {
    const plaintext = await readFile(input);
    const salt = crypto.randomBytes(SALT_LEN);
    const nonce = crypto.randomBytes(NONCE_LEN);
    const key = deriveKey(password, salt);

    const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    const result = Buffer.concat([salt, nonce, encrypted, tag]);
    await writeFile(output, result);
    console.log(`Файл зашифрован: ${output}`);
}

async function decryptFile(input, output, password) {
    const data = await readFile(input);
    if (data.length < SALT_LEN + NONCE_LEN + TAG_LEN) {
        throw new Error('Некорректный зашифрованный файл');
    }
    const salt = data.slice(0, SALT_LEN);
    const nonce = data.slice(SALT_LEN, SALT_LEN + NONCE_LEN);
    const encrypted = data.slice(SALT_LEN + NONCE_LEN, -TAG_LEN);
    const tag = data.slice(-TAG_LEN);
    const key = deriveKey(password, salt);

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    await writeFile(output, plaintext);
    console.log(`Файл расшифрован: ${output}`);
}

async function main() {
    const args = process.argv.slice(2);
    if (args.length !== 4) {
        console.log('Использование: node cryptographer_js.js <encrypt|decrypt> <input> <output> <password>');
        process.exit(1);
    }
    const mode = args[0];
    const input = args[1];
    const output = args[2];
    const password = args[3];

    try {
        if (mode === 'encrypt') {
            await encryptFile(input, output, password);
        } else if (mode === 'decrypt') {
            await decryptFile(input, output, password);
        } else {
            console.log('Режим должен быть encrypt или decrypt');
            process.exit(1);
        }
    } catch (err) {
        console.error('Ошибка:', err.message);
        process.exit(1);
    }
}

main();
