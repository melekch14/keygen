const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const fs = require('fs');
const zlib = require('zlib');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const path = require('path'); 

const app = express();
app.use(bodyParser.json());

app.use(express.static(path.join(__dirname, 'public')));

// File paths for keys
const PRIVATE_KEY_PATH = 'private_key.pem';
const PUBLIC_KEY_PATH = 'public_key.pem';

app.use(cors({
    origin: 'http://localhost:4200',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
  }));

// Initialize SQLite database
const db = new sqlite3.Database('./licenses.db', (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        // Create licenses table if it doesn't exist
        db.run(`
            CREATE TABLE IF NOT EXISTS licenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license TEXT NOT NULL UNIQUE,
                isActive INTEGER DEFAULT 0,
                nbUsed INTEGER DEFAULT 0,
                maxnbUsed INTEGER DEFAULT 1,
                userId INTEGER,
                expiryDate TEXT
            )
        `);
    }
});

// Generate RSA keys and save them to files
function generateKeys() {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem',
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem',
        },
    });

    fs.writeFileSync(PRIVATE_KEY_PATH, privateKey);
    fs.writeFileSync(PUBLIC_KEY_PATH, publicKey);

    console.log('Keys generated and saved:', PRIVATE_KEY_PATH, PUBLIC_KEY_PATH);
}

// Load private key
function loadPrivateKey() {
    if (!fs.existsSync(PRIVATE_KEY_PATH)) {
        throw new Error('Private key not found. Generate keys first.');
    }
    return fs.readFileSync(PRIVATE_KEY_PATH, 'utf8');
}

// Load public key
function loadPublicKey() {
    if (!fs.existsSync(PUBLIC_KEY_PATH)) {
        throw new Error('Public key not found. Generate keys first.');
    }
    return fs.readFileSync(PUBLIC_KEY_PATH, 'utf8');
}

// Compress data using zlib
function compressData(data) {
    return zlib.deflateSync(data).toString('base64');
}

// Decompress data using zlib
function decompressData(compressedData) {
    return zlib.inflateSync(Buffer.from(compressedData, 'base64')).toString('utf8');
}

// Encode data to a URL-friendly string
function encodeData(data) {
    return Buffer.from(data).toString('base64')
        .replace(/\+/g, '-') // Replace '+' with '-'
        .replace(/\//g, '_') // Replace '/' with '_'
        .replace(/=+$/, ''); // Remove padding '='
}

// Decode data from a URL-friendly string
function decodeData(encodedData) {
    // Add padding back if necessary
    while (encodedData.length % 4 !== 0) {
        encodedData += '=';
    }
    return Buffer.from(
        encodedData
            .replace(/-/g, '+') // Replace '-' with '+'
            .replace(/_/g, '/'), // Replace '_' with '/'
        'base64'
    ).toString();
}

// Generate a license
function generateLicense(data) {
    const privateKey = loadPrivateKey();
    const publicKey = loadPublicKey();

    // Encrypt the data
    const encryptedData = crypto.publicEncrypt(publicKey, Buffer.from(data, 'utf8')).toString('base64');

    // Compress the encrypted data
    const compressedData = compressData(encryptedData);

    // Encode the compressed data
    const encodedData = encodeData(compressedData);

    // Sign the encoded data
    const sign = crypto.createSign('SHA256');
    sign.update(encodedData);
    sign.end();
    const signature = sign.sign(privateKey, 'base64');

    // Compress the signature
    const compressedSignature = compressData(signature);

    // Encode the compressed signature
    const encodedSignature = encodeData(compressedSignature);

    // Return the license (encoded data + encoded signature)
    return `${encodedData}.${encodedSignature}`;
}

// Validate a license
function validateLicense(license) {
    const [encodedData, encodedSignature] = license.split('.');

    // Decode the signature
    const compressedSignature = decodeData(encodedSignature);

    // Decompress the signature
    const signature = decompressData(compressedSignature);

    // Verify the signature
    const publicKey = loadPublicKey();
    const verify = crypto.createVerify('SHA256');
    verify.update(encodedData);
    verify.end();
    const isValid = verify.verify(publicKey, signature, 'base64');

    if (!isValid) {
        throw new Error('Invalid license');
    }

    // Decode the data
    const compressedData = decodeData(encodedData);

    // Decompress the data
    const encryptedData = decompressData(compressedData);

    // Decrypt the data
    const privateKey = loadPrivateKey();
    const decryptedData = crypto.privateDecrypt(privateKey, Buffer.from(encryptedData, 'base64')).toString('utf8');

    return JSON.parse(decryptedData);
}

// API Endpoints

// Generate keys
app.post('/generate-keys', (req, res) => {
    generateKeys();
    res.json({ message: 'Keys generated successfully.' });
});

// Generate a license
app.post('/generate-license', (req, res) => {
    const { userId, expiryDate, maxnbUsed } = req.body;
    if (!userId || !expiryDate || !maxnbUsed) {
        return res.status(400).json({ error: 'userId, expiryDate, and maxnbUsed are required.' });
    }

    const data = JSON.stringify({ userId, expiryDate });
    const license = generateLicense(data);

    // Store the license in the database (inactive by default)
    db.run(
        'INSERT INTO licenses (license, maxnbUsed, userId, expiryDate) VALUES (?, ?, ?, ?)',
        [license, maxnbUsed, userId, expiryDate],
        function (err) {
            if (err) {
                return res.status(500).json({ error: 'Failed to store license in the database.' });
            }
            res.json({ license });
        }
    );
});

// Activate/Deactivate a license
app.post('/toggle-license', (req, res) => {
    const { license, isActive } = req.body;
    if (!license || isActive === undefined) {
        return res.status(400).json({ error: 'license and isActive are required.' });
    }

    db.run(
        'UPDATE licenses SET isActive = ? WHERE license = ?',
        [isActive ? 1 : 0, license],
        function (err) {
            if (err) {
                return res.status(500).json({ error: 'Failed to update license status.' });
            }
            res.json({ message: 'License status updated successfully.' });
        }
    );
});

// Fetch all licenses
app.get('/licenses', (req, res) => {
    db.all('SELECT * FROM licenses', (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch licenses.' });
        }
        res.json({ licenses: rows });
    });
});

// Validate a license (client endpoint)
app.post('/validate-license', (req, res) => {
    const { license } = req.body;
    if (!license) {
        return res.status(400).json({ error: 'License is required.' });
    }

    // Fetch the license from the database
    db.get('SELECT * FROM licenses WHERE license = ?', [license], (err, row) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to validate license.' });
        }

        if (!row) {
            return res.status(400).json({ error: 'License not found.' });
        }

        // Check if the license is active
        if (!row.isActive) {
            return res.status(400).json({ error: 'License is not active.' });
        }

        // Check if nbUsed < maxnbUsed
        if (row.nbUsed >= row.maxnbUsed) {
            return res.status(400).json({ error: 'License usage limit exceeded.' });
        }

        // Check if the license has expired
        const currentDate = new Date();
        const expiryDate = new Date(row.expiryDate);
        if (currentDate > expiryDate) {
            return res.status(400).json({ error: 'License has expired.' });
        }

        // Validate the license before incrementing nbUsed
        try {
            const licenseData = validateLicense(license);
            res.json({ valid: true, data: licenseData });
        } catch (error) {
            // If validation fails, return the error
            res.status(400).json({ valid: false, error: error.message });
        }
    });
});

// Validate a license (client endpoint)
app.post('/submit-license', (req, res) => {
    const { license } = req.body;
    if (!license) {
        return res.status(400).json({ error: 'License is required.' });
    }

    // Fetch the license from the database
    db.get('SELECT * FROM licenses WHERE license = ?', [license], (err, row) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to validate license.' });
        }

        if (!row) {
            return res.status(400).json({ error: 'License not found.' });
        }

        // Check if the license is active
        if (!row.isActive) {
            return res.status(400).json({ error: 'License is not active.' });
        }

        // Check if nbUsed < maxnbUsed
        if (row.nbUsed >= row.maxnbUsed) {
            return res.status(400).json({ error: 'License usage limit exceeded.' });
        }

        // Check if the license has expired
        const currentDate = new Date();
        const expiryDate = new Date(row.expiryDate);
        if (currentDate > expiryDate) {
            return res.status(400).json({ error: 'License has expired.' });
        }

        // Validate the license before incrementing nbUsed
        try {
            const licenseData = validateLicense(license);

            // Increment nbUsed only if validation succeeds
            db.run(
                'UPDATE licenses SET nbUsed = nbUsed + 1 WHERE license = ?',
                [license],
                function (err) {
                    if (err) {
                        return res.status(500).json({ error: 'Failed to update license usage.' });
                    }

                    // Return success response
                    res.json({ valid: true, data: licenseData });
                }
            );
        } catch (error) {
            // If validation fails, return the error
            res.status(400).json({ valid: false, error: error.message });
        }
    });
});

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start the server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});