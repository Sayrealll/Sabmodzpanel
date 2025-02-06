const express = require("express");
const moment = require("moment");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

const PORT = 3000;
const SECRET_KEY = process.env.SECRET_KEY || "SabModz";

const USER_IP_FILE = path.join(__dirname, "UserIp.json");
const LOGIN_USER_FILE = path.join(__dirname, "LoginUser.json");
const USERPANEL_DIR = path.join(__dirname, "USERPANEL");

if (!fs.existsSync(USERPANEL_DIR)) {
    fs.mkdirSync(USERPANEL_DIR);
}

let keysCache = {};

// Function to load keys from file
function loadKeys(username) {
    const keyFilePath = path.join(USERPANEL_DIR, `${username}.json`);
    if (fs.existsSync(keyFilePath)) {
        try {
            keysCache = JSON.parse(fs.readFileSync(keyFilePath, "utf8"));
        } catch (error) {
            console.error("Error loading keys:", error.message);
            keysCache = {};
        }
    } else {
        keysCache = {};
        saveKeys(username);
    }
}

// Function to save keys to file
function saveKeys(username) {
    const keyFilePath = path.join(USERPANEL_DIR, `${username}.json`);
    fs.writeFileSync(keyFilePath, JSON.stringify(keysCache, null, 2), "utf8");
}

// Function to validate API key
function isValidKey(apiKey) {
    return keysCache[apiKey] && moment().isBefore(moment(keysCache[apiKey], "YYYY-MM-DD"));
}

// Function to clean up expired keys
function cleanupExpiredKeys(username) {
    const now = moment();
    Object.keys(keysCache).forEach((key) => {
        if (moment(keysCache[key], "YYYY-MM-DD").isBefore(now)) {
            delete keysCache[key];
        }
    });
    saveKeys(username);
}

// Middleware for JWT authentication
function authenticateToken(req, res, next) {
    const token = req.headers["authorization"];
    if (!token) return res.status(401).json({ error: "Access Denied. No token provided." });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid Token" });
        req.user = user;
        loadKeys(user.username); // Load keys specific to user
        next();
    });
}

// Route: Get API Key File (Protected)
app.get("/key", authenticateToken, (req, res) => {
    const keyFilePath = path.join(USERPANEL_DIR, `${req.user.username}.json`);
    if (!fs.existsSync(keyFilePath)) {
        return res.status(404).json({ error: "No API keys found for this user" });
    }
    res.sendFile(keyFilePath);
});

// Route: Home
app.get("/", async (req, res) => {
    res.sendFile(path.join(__dirname, "genapikey.html"));
});

// Route: Signup
app.post("/signup", async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Username and password are required" });

    let users = {};
    if (fs.existsSync(LOGIN_USER_FILE)) {
        users = JSON.parse(fs.readFileSync(LOGIN_USER_FILE, "utf8"));
    }

    if (users[username]) return res.status(400).json({ error: "Username already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    users[username] = hashedPassword;

    fs.writeFileSync(LOGIN_USER_FILE, JSON.stringify(users, null, 2), "utf8");
    res.json({ message: "User registered successfully" });
});

// Route: Login
app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Username and password are required" });

    if (!fs.existsSync(LOGIN_USER_FILE)) return res.status(400).json({ error: "User not found" });

    const users = JSON.parse(fs.readFileSync(LOGIN_USER_FILE, "utf8"));

    if (!users[username]) return res.status(400).json({ error: "Invalid username or password" });

    const isMatch = await bcrypt.compare(password, users[username]);
    if (!isMatch) return res.status(400).json({ error: "Invalid username or password" });

    const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: "1h" });

    loadKeys(username); // Load user's keys after login

    res.json({ message: "Login successful", token });
});

// Route: Add API Key (Protected)
app.post("/add-key", authenticateToken, (req, res) => {
    const { apiKey, expirationDate } = req.body;
    if (!apiKey || !moment(expirationDate, "YYYY-MM-DD", true).isValid()) {
        return res.status(400).json({ error: "Invalid API key or expiration date format" });
    }

    keysCache[apiKey] = expirationDate;
    saveKeys(req.user.username);
    res.json({ message: "API key added successfully", apiKey, expirationDate });
});

// Route: Remove API Key (Protected)
app.post("/removekey", authenticateToken, (req, res) => {
    const { apiKey } = req.body;
    if (!keysCache[apiKey]) {
        return res.status(404).json({ message: "API Key not found!" });
    }

    delete keysCache[apiKey];
    saveKeys(req.user.username);
    res.json({ message: "API Key removed successfully!" });
});

// Route: Validate API Key
app.get("/execute", (req, res) => {
    const { username, apiKey } = req.query;

    if (!username || !apiKey) return res.status(400).json({ error: "API key and username are required" });



    loadKeys(username); // Ensure the correct user's keys are loaded

    if (!keysCache[apiKey]) return res.status(404).json({ error: "The key is not found in JSON" });

    if (!isValidKey(apiKey)) {
        return res.status(403).json({ error: "The script has expired. Contact the owner for a new key." });
    }

    res.json({ message: `Your key will expires on: ${keysCache[apiKey]}` });
});

// Start Server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
