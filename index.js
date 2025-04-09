const express = require('express');
const { MongoClient } = require('mongodb');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

// MongoDB Connection
let db;
(async () => {
    try {
        const client = new MongoClient(process.env.MONGO_URI);
        await client.connect();
        db = client.db('pasterbin');
        console.log('Connected to MongoDB');
    } catch (error) {
        console.error('Failed to connect to MongoDB:', error);
        process.exit(1);
    }
})();

// Email Transporter (using Brevo SMTP)
const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

// Middleware
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Generate a 6-character random ID for pastes
function generateRandomId() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    let id = '';
    for (let i = 0; i < 6; i++) {
        id += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return id;
}

// Middleware to verify JWT
function authenticateToken(req, res, next) {
    const token = req.query.token || req.body.token;
    if (!token) return res.redirect('/login');
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.redirect('/login');
        req.user = user;
        next();
    });
}

// Home route - Serve index.html
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public/index.html');
});

// API to get total number of pastes
app.get('/api/total-pastes', async (req, res) => {
    try {
        const totalPastes = await db.collection('pastes').countDocuments();
        res.json({ totalPastes });
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Signup page
app.get('/signup', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Signup - JSON Pastebin</title>
            <script src="https://cdn.tailwindcss.com"></script>
        </head>
        <body class="bg-gray-100 min-h-screen flex flex-col">
            <nav class="bg-blue-600 text-white p-4 shadow-md">
                <div class="container mx-auto flex justify-between items-center">
                    <a href="/" class="text-2xl font-bold">JSON Pastebin</a>
                    <div>
                        <a href="/" class="hover:underline">Home</a>
                        <a href="/signup" class="ml-4 hover:underline">Signup</a>
                        <a href="/login" class="ml-4 hover:underline">Login</a>
                    </div>
                </div>
            </nav>
            <main class="flex-grow container mx-auto p-6">
                <div class="bg-white rounded-lg shadow-lg p-6 max-w-md mx-auto">
                    <h1 class="text-3xl font-semibold text-gray-800 mb-4">Signup</h1>
                    <form action="/signup" method="POST">
                        <input type="text" name="username" placeholder="Username" class="w-full p-3 border rounded-lg mb-3" required>
                        <input type="email" name="email" placeholder="Email" class="w-full p-3 border rounded-lg mb-3" required>
                        <input type="password" name="password" placeholder="Password" class="w-full p-3 border rounded-lg mb-3" required>
                        <button type="submit" class="w-full bg-blue-600 text-white py-2 rounded-lg hover:bg-blue-700">Signup</button>
                    </form>
                </div>
            </main>
            <footer class="bg-gray-800 text-white p-4 text-center">
                <p>© 2025 JSON Pastebin. All rights reserved.</p>
            </footer>
        </body>
        </html>
    `);
});

// Handle signup
app.post('/signup', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const existingUser = await db.collection('users').findOne({ $or: [{ username }, { email }] });
        if (existingUser) {
            return res.send('Username or email already exists. <a href="/signup">Try again</a>');
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const verificationToken = Math.random().toString(36).substring(2);
        const user = {
            username,
            email,
            password: hashedPassword,
            verified: false,
            verificationToken,
            pastes: [],
        };
        await db.collection('users').insertOne(user);

        // Send verification email
        const verificationLink = `${req.protocol}://${req.get('host')}/verify?token=${verificationToken}`;
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Verify Your Email - JSON Pastebin',
            html: `Please click this link to verify your email: <a href="${verificationLink}">${verificationLink}</a>`,
        });

        res.send('Signup successful! Please check your email to verify your account. <a href="/login">Login</a>');
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).send('Internal Server Error');
    }
});

// Verify email
app.get('/verify', async (req, res) => {
    try {
        const { token } = req.query;
        const user = await db.collection('users').findOne({ verificationToken: token });
        if (!user) {
            return res.send('Invalid or expired verification token. <a href="/signup">Signup again</a>');
        }
        await db.collection('users').updateOne(
            { verificationToken: token },
            { $set: { verified: true }, $unset: { verificationToken: "" } }
        );
        res.send('Email verified successfully! <a href="/login">Login</a>');
    } catch (error) {
        res.status(500).send('Internal Server Error');
    }
});

// Login page
app.get('/login', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Login - JSON Pastebin</title>
            <script src="https://cdn.tailwindcss.com"></script>
        </head>
        <body class="bg-gray-100 min-h-screen flex flex-col">
            <nav class="bg-blue-600 text-white p-4 shadow-md">
                <div class="container mx-auto flex justify-between items-center">
                    <a href="/" class="text-2xl font-bold">JSON Pastebin</a>
                    <div>
                        <a href="/" class="hover:underline">Home</a>
                        <a href="/signup" class="ml-4 hover:underline">Signup</a>
                        <a href="/login" class="ml-4 hover:underline">Login</a>
                    </div>
                </div>
            </nav>
            <main class="flex-grow container mx-auto p-6">
                <div class="bg-white rounded-lg shadow-lg p-6 max-w-md mx-auto">
                    <h1 class="text-3xl font-semibold text-gray-800 mb-4">Login</h1>
                    <form action="/login" method="POST">
                        <input type="text" name="identifier" placeholder="Username or Email" class="w-full p-3 border rounded-lg mb-3" required>
                        <input type="password" name="password" placeholder="Password" class="w-full p-3 border rounded-lg mb-3" required>
                        <button type="submit" class="w-full bg-blue-600 text-white py-2 rounded-lg hover:bg-blue-700">Login</button>
                    </form>
                </div>
            </main>
            <footer class="bg-gray-800 text-white p-4 text-center">
                <p>© 2025 JSON Pastebin. All rights reserved.</p>
            </footer>
        </body>
        </html>
    `);
});

// Handle login
app.post('/login', async (req, res) => {
    try {
        const { identifier, password } = req.body;
        const user = await db.collection('users').findOne({
            $or: [{ username: identifier }, { email: identifier }],
        });
        if (!user) {
            return res.send('User not found. <a href="/login">Try again</a>');
        }
        if (!user.verified) {
            return res.send('Please verify your email before logging in. <a href="/login">Back</a>');
        }
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.send('Invalid password. <a href="/login">Try again</a>');
        }
        const token = jwt.sign({ username: user.username }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN });
        console.log('Generated JWT:', token); // Log the token for debugging
        res.redirect(`/account?token=${token}`);
    } catch (error) {
        res.status(500).send('Internal Server Error');
    }
});

// Create a new JSON paste
app.post('/paste', async (req, res) => {
    try {
        const { title, content, username } = req.body;
        let newId;
        do {
            newId = generateRandomId();
        } while (await db.collection('pastes').findOne({ id: newId }));

        const paste = {
            id: newId,
            title: title || 'Untitled Paste',
            content: content.replace(/\r\n/g, '\n'),
            createdAt: new Date().toISOString(),
            username: username || 'Anonymous',
            views: 0,
        };
        await db.collection('pastes').insertOne(paste);

        if (username) {
            await db.collection('users').updateOne(
                { username },
                { $push: { pastes: newId } },
                { upsert: true }
            );
        }

        res.redirect(`/paste/${newId}`);
    } catch (error) {
        res.status(500).send('Internal Server Error');
    }
});

// View a JSON paste
app.get('/paste/:id', async (req, res) => {
    try {
        const paste = await db.collection('pastes').findOne({ id: req.params.id });
        if (paste) {
            await db.collection('pastes').updateOne(
                { id: req.params.id },
                { $inc: { views: 1 } }
            );
            paste.views += 1;
            res.send(`
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>${paste.title} - JSON Pastebin</title>
                    <script src="https://cdn.tailwindcss.com"></script>
                    <link rel="stylesheet" href="/style.css">
                </head>
                <body class="bg-gray-100 min-h-screen flex flex-col">
                    <nav class="bg-blue-600 text-white p-4 shadow-md">
                        <div class="container mx-auto flex justify-between items-center">
                            <a href="/" class="text-2xl font-bold">JSON Pastebin</a>
                            <div>
                                <a href="/" class="hover:underline">Home</a>
                                <a href="/paste/1" class="ml-4 hover:underline">Sample Paste</a>
                                <a href="/account" class="ml-4 hover:underline">Account</a>
                                <a href="/signup" class="ml-4 hover:underline">Signup</a>
                                <a href="/login" class="ml-4 hover:underline">Login</a>
                            </div>
                        </div>
                    </nav>
                    <main class="flex-grow container mx-auto p-6">
                        <div class="bg-white rounded-lg shadow-lg p-6 max-w-2xl mx-auto">
                            <h1 class="text-3xl font-semibold text-gray-800 mb-2">${paste.title}</h1>
                            <p class="text-sm text-gray-500 mb-4">Paste ID: ${paste.id} | Created by: ${paste.username} | Views: ${paste.views}</p>
                            <pre class="text-gray-700">${paste.content}</pre>
                            <p class="mt-4 text-gray-600">Raw JSON: <a href="/raw/${paste.id}" class="text-blue-500 hover:underline">/raw/${paste.id}</a></p>
                            <div class="mt-4 flex space-x-3">
                                <a href="/edit/${paste.id}" class="flex-1 bg-blue-600 text-white py-2 rounded-lg text-center hover:bg-blue-700 transition duration-200 shadow-md">Edit this Paste</a>
                                <a href="/" class="flex-1 bg-gray-300 text-gray-800 py-2 rounded-lg text-center hover:bg-gray-400 transition duration-200 shadow-md">Create Another</a>
                            </div>
                        </div>
                    </main>
                    <footer class="bg-gray-800 text-white p-4 text-center">
                        <p>© 2025 JSON Pastebin. All rights reserved.</p>
                    </footer>
                </body>
                </html>
            `);
        } else {
            res.status(404).send('Paste not found');
        }
    } catch (error) {
        res.status(500).send('Internal Server Error');
    }
});

// Raw JSON endpoint
app.get('/raw/:id', async (req, res) => {
    try {
        const paste = await db.collection('pastes').findOne({ id: req.params.id });
        if (paste) {
            res.setHeader('Content-Type', 'text/plain');
            res.send(paste.content);
        } else {
            res.status(404).send('Paste not found');
        }
    } catch (error) {
        res.status(500).send('Internal Server Error');
    }
});

// API to get paste data (for edit page)
app.get('/api/paste/:id', async (req, res) => {
    try {
        const paste = await db.collection('pastes').findOne({ id: req.params.id });
        if (paste) {
            res.json(paste);
        } else {
            res.status(404).json({ error: 'Paste not found' });
        }
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Edit page
app.get('/edit/:id', async (req, res) => {
    try {
        const paste = await db.collection('pastes').findOne({ id: req.params.id });
        if (paste) {
            res.sendFile(__dirname + '/public/edit.html');
        } else {
            res.status(404).send('Paste not found');
        }
    } catch (error) {
        res.status(500).send('Internal Server Error');
    }
});

// Update a paste
app.post('/edit/:id', async (req, res) => {
    try {
        const { content } = req.body;
        await db.collection('pastes').updateOne(
            { id: req.params.id },
            { $set: { content: content.replace(/\r\n/g, '\n'), updatedAt: new Date().toISOString() } }
        );
        res.redirect(`/paste/${req.params.id}`);
    } catch (error) {
        res.status(500).send('Internal Server Error');
    }
});

// Account page with "Your Pastes"
app.get('/account', authenticateToken, async (req, res) => {
    try {
        const username = req.user.username;
        const user = await db.collection('users').findOne({ username });
        if (!user) {
            return res.redirect('/login');
        }
        const pastes = await db.collection('pastes').find({ id: { $in: user.pastes || [] } }).toArray();
        res.send(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Account - JSON Pastebin</title>
                <script src="https://cdn.tailwindcss.com"></script>
                <link rel="stylesheet" href="/style.css">
            </head>
            <body class="bg-gray-100 min-h-screen flex flex-col">
                <nav class="bg-blue-600 text-white p-4 shadow-md">
                    <div class="container mx-auto flex justify-between items-center">
                        <a href="/" class="text-2xl font-bold">JSON Pastebin</a>
                        <div>
                            <a href="/" class="hover:underline">Home</a>
                            <a href="/paste/1" class="ml-4 hover:underline">Sample Paste</a>
                            <a href="/account?token=${req.query.token}" class="ml-4 hover:underline">Account</a>
                            <a href="/signup" class="ml-4 hover:underline">Signup</a>
                            <a href="/login" class="ml-4 hover:underline">Login</a>
                        </div>
                    </div>
                </nav>
                <main class="flex-grow container mx-auto p-6">
                    <div class="bg-white rounded-lg shadow-lg p-6 max-w-2xl mx-auto">
                        <h1 class="text-3xl font-semibold text-gray-800 mb-4">Account</h1>
                        <div>
                            <h2 class="text-xl font-medium text-gray-700 mb-2">Your Pastes</h2>
                            <div id="pastesList" class="space-y-3">
                                ${
                                    pastes.length === 0
                                        ? '<p class="text-gray-600">No pastes found.</p>'
                                        : pastes.map(paste => `
                                            <div class="p-3 bg-gray-50 rounded-lg">
                                                <a href="/paste/${paste.id}" class="text-blue-500 hover:underline">${paste.title}</a>
                                                <p class="text-sm text-gray-500">ID: ${paste.id} | Views: ${paste.views}</p>
                                            </div>
                                        `).join('')
                                }
                            </div>
                        </div>
                    </div>
                </main>
                <footer class="bg-gray-800 text-white p-4 text-center">
                    <p>© 2025 JSON Pastebin. All rights reserved.</p>
                </footer>
            </body>
            </html>
        `);
    } catch (error) {
        res.status(500).send('Internal Server Error');
    }
});

// Start the server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});