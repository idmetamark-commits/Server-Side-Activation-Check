const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const chalk = require('chalk');

const app = express();
const PORT = 3000;

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// --- PENGATURAN DATABASE & MASTER KEY ---
const DB_BASENAME = 'token-db';
const MASTER_KEY_FILE = 'master-key.json';

let TOKEN_DB_FILE;
let dbPath;
let MASTER_KEY_SERVER;

const buatHashSha256 = (teks) => {
    return crypto.createHash('sha256').update(teks).digest('hex');
};

function inisialisasiServer() {
    try {
        const masterKeyPath = path.join(__dirname, MASTER_KEY_FILE);
        
        if (fs.existsSync(masterKeyPath)) {
            const keyData = fs.readFileSync(masterKeyPath, 'utf8');
            MASTER_KEY_SERVER = JSON.parse(keyData).masterKey;
            console.log(chalk.green(`Master Key berhasil dimuat dari '${MASTER_KEY_FILE}'.`));
        } else {
            console.log(chalk.yellow(`'${MASTER_KEY_FILE}' tidak ditemukan. Membuat Master Key baru...`));
            MASTER_KEY_SERVER = crypto.randomBytes(32).toString('hex');
            const keyData = { masterKey: MASTER_KEY_SERVER };
            fs.writeFileSync(masterKeyPath, JSON.stringify(keyData, null, 2), 'utf8');
            
            console.log(chalk.red.bold("\n==================== PERHATIAN ===================="));
            console.log(chalk.white(`Master Key Anda adalah: ${MASTER_KEY_SERVER}`));
            console.log(chalk.yellow(`CATAT!!! Gunakan Master Key untuk menambah token baru.`));
            console.log(chalk.red.bold("===================================================\n"));
        }

        const dirFiles = fs.readdirSync(__dirname);
        const existingDbFile = dirFiles.find(file => 
            file.startsWith(DB_BASENAME) && file.endsWith('.json')
        );

        if (existingDbFile) {
            TOKEN_DB_FILE = existingDbFile;
            dbPath = path.join(__dirname, TOKEN_DB_FILE);
            console.log(chalk.green(`Database '${TOKEN_DB_FILE}' berhasil ditemukan.`));
        } else {
            const timestamp = Date.now();
            TOKEN_DB_FILE = `${DB_BASENAME}-${timestamp}.json`;
            dbPath = path.join(__dirname, TOKEN_DB_FILE);
            
            console.log(chalk.yellow(`Database token tidak ditemukan. Membuat: '${TOKEN_DB_FILE}'`));
            fs.writeFileSync(dbPath, JSON.stringify({}, null, 2), 'utf8');
        }
        
    } catch (error) {
        console.error(chalk.red("FATAL: Gagal menginisialisasi server!"), error);
        process.exit(1);
    }
}

function readDatabase() {
    try {
        const data = fs.readFileSync(dbPath, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        console.error(chalk.red(`Error membaca database '${dbPath}':`), error);
        return {};
    }
}

function writeDatabase(data) {
    try {
        const dataString = JSON.stringify(data, null, 2);
        fs.writeFileSync(dbPath, dataString, 'utf8');
    } catch (error) {
        console.error(chalk.red(`Error menulis ke database '${dbPath}':`), error);
    }
}

// --- MIDDLEWARE ---
app.use(express.json());

app.get('/panel-admin', (req, res) => {
    res.render('admin');
});

app.post('/validasi-token', (req, res) => {
    const hashTokenDariBot = req.body.tokenHash;
    console.log(`Menerima permintaan validasi...`);

    if (!hashTokenDariBot) {
        console.log("-> Permintaan ditolak: Hash token tidak ada.");
        return res.status(400).json({ status: 'error', pesan: 'Hash token diperlukan.' });
    }

    const db = readDatabase();

    if (db.hasOwnProperty(hashTokenDariBot)) {
        console.log(chalk.green(`-> Validasi BERHASIL untuk hash: ${hashTokenDariBot.substring(0, 8)}...`));
        
        const sessionSecret = crypto.randomBytes(16).toString('hex');
        db[hashTokenDariBot].terakhirDilihat = new Date().toISOString(); 
        writeDatabase(db);
        
        res.json({ 
            status: 'ok',
            session_secret: sessionSecret
        });

    } else {
        console.log(chalk.red(`-> Validasi GAGAL untuk hash: ${hashTokenDariBot.substring(0, 8)}...`));
        res.json({ status: 'ditolak' });
    }
});

app.post('/addtoken', (req, res) => {
    const { tokenAsli, masterKey } = req.body;

    if (masterKey !== MASTER_KEY_SERVER) {
        console.warn(chalk.red("PERINGATAN: Upaya menambah token GAGAL (Master key salah)."));
        return res.status(401).json({ status: 'error', pesan: 'Akses ditolak.' });
    }
    
    if (!tokenAsli) {
        return res.status(400).json({ status: 'error', pesan: 'tokenHash diperlukan.' });
    }
    const hashToken = buatHashSha256(tokenAsli);
  
    const db = readDatabase();

    if (db.hasOwnProperty(hashToken)) {
        console.log(chalk.yellow(`Token ${hashToken.substring(0, 8)}... sudah ada di database.`));
        return res.status(409).json({ status: 'error', pesan: 'Token hash ini sudah ada.' });
    }

    db[hashToken] = {
        ditambahkan: new Date().toISOString(),
        terakhirDilihat: null
    };

    writeDatabase(db);

    console.log(chalk.green(`BERHASIL: Token ${hashToken.substring(0, 8)}... telah ditambahkan.`));
    res.json({ 
        status: 'ok', 
        pesan: `Token hash ${hashToken.substring(0, 8)}... berhasil ditambahkan.` 
    });
});

app.listen(PORT, () => {
    inisialisasiServer(); 
    console.log(chalk.blue(`🚀 Server aktivasi berjalan di port ${PORT}`));
    console.log(chalk.blue(`Menggunakan database: ${TOKEN_DB_FILE}`));
});
