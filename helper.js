const crypto = require('crypto');

const SHARED_SECRET_PASSWORD = "kunci_gila_rahasia_kita_bersama_123!@#";

const key = crypto.scryptSync(SHARED_SECRET_PASSWORD, 'salt-statis-rahasia', 32);

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;

function encrypt(text) {
    try {
        const iv = crypto.randomBytes(IV_LENGTH);
        const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
        
        const encrypted = Buffer.concat([
            cipher.update(text, 'utf8'),
            cipher.final()
        ]);
        
        const authTag = cipher.getAuthTag();

        return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;

    } catch (error) {
        console.error("ENCRYPT FAILED:", error);
        return null;
    }
}

function decrypt(encryptedText) {
    try {
        const parts = encryptedText.split(':');
        if (parts.length !== 3) {
            throw new Error("Format teks terenkripsi salah.");
        }

        const iv = Buffer.from(parts[0], 'hex');
        const authTag = Buffer.from(parts[1], 'hex');
        const content = Buffer.from(parts[2], 'hex');

        const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
        
        decipher.setAuthTag(authTag);

        const decrypted = Buffer.concat([
            decipher.update(content),
            decipher.final()
        ]);

        return decrypted.toString('utf8');

    } catch (error) {
        console.error(chalk.red("DECRYPT FAILED (Kemungkinan Tampering):"), error.message);
        throw new Error("Gagal mendekripsi data.");
    }
}

module.exports = { encrypt, decrypt };
