const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'halal-semi-auto-secret-key';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '01234567890123456789012345678901';

// ==================== ISLAMIC COMPLIANCE SETTINGS ====================
// Minimum holding period (user commits to ownership)
const MIN_HOLDING_DAYS = 7;  // User agrees to hold for at least 7 days

// ==================== DATA DIRECTORIES ====================
const dataDir = path.join(__dirname, 'data');
const tradesDir = path.join(dataDir, 'trades');
const pendingDir = path.join(dataDir, 'pending');
const holdingsDir = path.join(dataDir, 'holdings');
const signalsDir = path.join(dataDir, 'signals');

if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);
if (!fs.existsSync(tradesDir)) fs.mkdirSync(tradesDir);
if (!fs.existsSync(pendingDir)) fs.mkdirSync(pendingDir);
if (!fs.existsSync(holdingsDir)) fs.mkdirSync(holdingsDir);
if (!fs.existsSync(signalsDir)) fs.mkdirSync(signalsDir);

const usersFile = path.join(dataDir, 'users.json');
const pendingFile = path.join(pendingDir, 'pending_users.json');

// Default owner account
if (!fs.existsSync(usersFile)) {
    const defaultUsers = {
        "mujtabahatif@gmail.com": {
            email: "mujtabahatif@gmail.com",
            password: bcrypt.hashSync("Mujtabah@2598", 10),
            isOwner: true,
            isApproved: true,
            isBlocked: false,
            apiKey: "",
            secretKey: "",
            createdAt: new Date().toISOString()
        }
    };
    fs.writeFileSync(usersFile, JSON.stringify(defaultUsers, null, 2));
}
if (!fs.existsSync(pendingFile)) fs.writeFileSync(pendingFile, JSON.stringify({}));

function readUsers() { return JSON.parse(fs.readFileSync(usersFile)); }
function writeUsers(users) { fs.writeFileSync(usersFile, JSON.stringify(users, null, 2)); }
function readPending() { return JSON.parse(fs.readFileSync(pendingFile)); }
function writePending(pending) { fs.writeFileSync(pendingFile, JSON.stringify(pending, null, 2)); }

function encrypt(text) {
    if (!text) return "";
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}
function decrypt(text) {
    if (!text) return "";
    const parts = text.split(':');
    const iv = Buffer.from(parts.shift(), 'hex');
    const encryptedText = Buffer.from(parts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

// ==================== MIDDLEWARE ====================
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: '🕋 100% Halal Semi-Auto Trading Bot' });
});

// ==================== AUTHENTICATION ====================
app.post('/api/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password required' });
    const users = readUsers();
    if (users[email]) return res.status(400).json({ success: false, message: 'User already exists' });
    const pending = readPending();
    if (pending[email]) return res.status(400).json({ success: false, message: 'Request already pending' });
    const hashedPassword = bcrypt.hashSync(password, 10);
    pending[email] = { email, password: hashedPassword, requestedAt: new Date().toISOString(), status: 'pending' };
    writePending(pending);
    res.json({ success: true, message: 'Registration request sent to owner.' });
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    const users = readUsers();
    const user = users[email];
    if (!user) {
        const pending = readPending();
        if (pending[email]) return res.status(401).json({ success: false, message: 'Pending approval' });
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ success: false, message: 'Invalid credentials' });
    if (!user.isApproved && !user.isOwner) return res.status(401).json({ success: false, message: 'Account not approved' });
    if (user.isBlocked) return res.status(401).json({ success: false, message: 'Your account has been blocked.' });
    const token = jwt.sign({ email, isOwner: user.isOwner || false }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, isOwner: user.isOwner || false });
});

function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ success: false, message: 'No token' });
    const token = authHeader.split(' ')[1];
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) {
        res.status(401).json({ success: false, message: 'Invalid token' });
    }
}

// ==================== ADMIN ROUTES ====================
app.get('/api/admin/pending-users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const pending = readPending();
    const list = Object.keys(pending).map(email => ({ email, requestedAt: pending[email].requestedAt }));
    res.json({ success: true, pending: list });
});

app.post('/api/admin/approve-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const pending = readPending();
    if (!pending[email]) return res.status(404).json({ success: false });
    const users = readUsers();
    users[email] = {
        email, password: pending[email].password,
        isOwner: false, isApproved: true, isBlocked: false,
        apiKey: "", secretKey: "",
        approvedAt: new Date().toISOString(),
        createdAt: pending[email].requestedAt
    };
    writeUsers(users);
    delete pending[email];
    writePending(pending);
    res.json({ success: true, message: `User ${email} approved.` });
});

app.post('/api/admin/reject-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const pending = readPending();
    if (!pending[email]) return res.status(404).json({ success: false });
    delete pending[email];
    writePending(pending);
    res.json({ success: true, message: `User ${email} rejected.` });
});

app.post('/api/admin/toggle-block', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const users = readUsers();
    if (!users[email]) return res.status(404).json({ success: false });
    users[email].isBlocked = !users[email].isBlocked;
    writeUsers(users);
    res.json({ success: true, message: `User ${email} is now ${users[email].isBlocked ? 'blocked' : 'unblocked'}.` });
});

// ==================== BINANCE API ====================
function cleanKey(key) {
    if (!key) return "";
    return key.replace(/[\s\n\r\t]+/g, '').trim();
}

async function getServerTime(useDemo = false) {
    const baseUrl = useDemo ? 'https://demo-api.binance.com' : 'https://api.binance.com';
    try {
        const response = await axios.get(`${baseUrl}/api/v3/time`, { timeout: 5000 });
        return response.data.serverTime;
    } catch (error) {
        return Date.now();
    }
}

function generateSignature(queryString, secret) {
    return crypto.createHmac('sha256', secret).update(queryString).digest('hex');
}

async function binanceRequest(apiKey, secretKey, endpoint, params = {}, method = 'GET', useDemo = false) {
    const timestamp = await getServerTime(useDemo);
    const allParams = { ...params, timestamp, recvWindow: 5000 };
    const sortedKeys = Object.keys(allParams).sort();
    const queryString = sortedKeys.map(k => `${k}=${allParams[k]}`).join('&');
    const signature = generateSignature(queryString, secretKey);
    const baseUrl = useDemo ? 'https://demo-api.binance.com' : 'https://api.binance.com';
    const url = `${baseUrl}${endpoint}?${queryString}&signature=${signature}`;
    const response = await axios({ method, url, headers: { 'X-MBX-APIKEY': apiKey }, timeout: 10000 });
    return response.data;
}

async function getSpotBalance(apiKey, secretKey, useDemo = false) {
    try {
        const accountData = await binanceRequest(apiKey, secretKey, '/api/v3/account', {}, 'GET', useDemo);
        const usdtBalance = accountData.balances.find(b => b.asset === 'USDT');
        return parseFloat(usdtBalance?.free || 0);
    } catch (error) {
        return 0;
    }
}

async function getCurrentPrice(symbol, useDemo = false) {
    const baseUrl = useDemo ? 'https://demo-api.binance.com' : 'https://api.binance.com';
    const response = await axios.get(`${baseUrl}/api/v3/ticker/price?symbol=${symbol}`);
    return parseFloat(response.data.price);
}

async function get24hrStats(symbol, useDemo = false) {
    const baseUrl = useDemo ? 'https://demo-api.binance.com' : 'https://api.binance.com';
    const response = await axios.get(`${baseUrl}/api/v3/ticker/24hr?symbol=${symbol}`);
    return {
        priceChangePercent: parseFloat(response.data.priceChangePercent),
        volume: parseFloat(response.data.volume),
        quoteVolume: parseFloat(response.data.quoteVolume),
        high: parseFloat(response.data.highPrice),
        low: parseFloat(response.data.lowPrice),
        lastPrice: parseFloat(response.data.lastPrice)
    };
}

async function executeBuyOrder(apiKey, secretKey, symbol, usdtAmount, useDemo = false) {
    if (usdtAmount < 10) throw new Error('Minimum order size is $10');
    return await binanceRequest(apiKey, secretKey, '/api/v3/order', {
        symbol, side: 'BUY', type: 'MARKET', quoteOrderQty: usdtAmount.toFixed(2)
    }, 'POST', useDemo);
}

async function executeSellOrder(apiKey, secretKey, symbol, quantity, useDemo = false) {
    return await binanceRequest(apiKey, secretKey, '/api/v3/order', {
        symbol, side: 'SELL', type: 'MARKET', quantity: quantity.toFixed(6)
    }, 'POST', useDemo);
}

// ==================== PORTFOLIO MANAGEMENT ====================
function loadHoldings(email) {
    const file = path.join(holdingsDir, email.replace(/[^a-z0-9]/gi, '_') + '.json');
    if (!fs.existsSync(file)) return [];
    return JSON.parse(fs.readFileSync(file));
}

function saveHoldings(email, holdings) {
    const file = path.join(holdingsDir, email.replace(/[^a-z0-9]/gi, '_') + '.json');
    fs.writeFileSync(file, JSON.stringify(holdings, null, 2));
}

function saveSignal(email, signal) {
    const signals = loadSignals(email);
    signals.unshift({ ...signal, id: Date.now(), status: 'pending' });
    const file = path.join(signalsDir, email.replace(/[^a-z0-9]/gi, '_') + '.json');
    fs.writeFileSync(file, JSON.stringify(signals, null, 2));
}

function loadSignals(email) {
    const file = path.join(signalsDir, email.replace(/[^a-z0-9]/gi, '_') + '.json');
    if (!fs.existsSync(file)) return [];
    return JSON.parse(fs.readFileSync(file));
}

function updateSignalStatus(email, signalId, status, orderDetails = null) {
    const signals = loadSignals(email);
    const index = signals.findIndex(s => s.id === signalId);
    if (index !== -1) {
        signals[index].status = status;
        if (orderDetails) signals[index].orderDetails = orderDetails;
        fs.writeFileSync(path.join(signalsDir, email.replace(/[^a-z0-9]/gi, '_') + '.json'), JSON.stringify(signals, null, 2));
    }
}

// ==================== API KEY MANAGEMENT ====================
app.post('/api/set-api-keys', authenticate, async (req, res) => {
    let { apiKey, secretKey, accountType } = req.body;
    if (!apiKey || !secretKey) return res.status(400).json({ success: false, message: 'Both keys required' });
    const cleanApi = cleanKey(apiKey);
    const cleanSecret = cleanKey(secretKey);
    const useDemo = (accountType === 'testnet');
    
    try {
        const spotBalance = await getSpotBalance(cleanApi, cleanSecret, useDemo);
        const users = readUsers();
        users[req.user.email].apiKey = encrypt(cleanApi);
        users[req.user.email].secretKey = encrypt(cleanSecret);
        writeUsers(users);
        res.json({ success: true, message: `API keys saved! Balance: ${spotBalance} USDT`, spotBalance: spotBalance });
    } catch (error) {
        res.status(401).json({ success: false, message: 'Invalid API keys. Enable Spot & Margin Trading.' });
    }
});

app.post('/api/connect-binance', authenticate, async (req, res) => {
    const { accountType } = req.body;
    const users = readUsers();
    const user = users[req.user.email];
    if (!user || !user.apiKey) return res.status(400).json({ success: false, message: 'No API keys saved.' });
    
    const apiKey = decrypt(user.apiKey);
    const secretKey = decrypt(user.secretKey);
    const useDemo = (accountType === 'testnet');
    
    try {
        const spotBalance = await getSpotBalance(apiKey, secretKey, useDemo);
        res.json({ success: true, spotBalance: spotBalance, message: `Connected! Balance: ${spotBalance} USDT` });
    } catch (error) {
        res.status(401).json({ success: false, message: 'Connection failed.' });
    }
});

app.get('/api/get-keys', authenticate, (req, res) => {
    const users = readUsers();
    const user = users[req.user.email];
    if (!user || !user.apiKey) return res.json({ success: false, message: 'No keys set' });
    res.json({ success: true, apiKey: decrypt(user.apiKey), secretKey: decrypt(user.secretKey) });
});

// ==================== MARKET ANALYSIS (Bot Analyzes - User Decides) ====================
app.post('/api/analyze-market', authenticate, async (req, res) => {
    const { symbols, accountType, minHoldingDays } = req.body;
    const useDemo = (accountType === 'testnet');
    
    const analysisResults = [];
    
    for (const symbol of symbols) {
        try {
            // Get real market data
            const stats = await get24hrStats(symbol, useDemo);
            const currentPrice = await getCurrentPrice(symbol, useDemo);
            
            // Get month trend (for fundamental context)
            const baseUrl = useDemo ? 'https://demo-api.binance.com' : 'https://api.binance.com';
            const monthlyKlines = await axios.get(`${baseUrl}/api/v3/klines`, {
                params: { symbol, interval: '1d', limit: 30 }
            });
            const monthStartPrice = parseFloat(monthlyKlines.data[0][4]);
            const monthTrend = ((currentPrice - monthStartPrice) / monthStartPrice) * 100;
            
            // Calculate average volume
            const avgVolume = monthlyKlines.data.slice(-7).reduce((sum, k) => sum + parseFloat(k[5]), 0) / 7;
            const volumeRatio = stats.volume / avgVolume;
            
            analysisResults.push({
                symbol: symbol,
                currentPrice: currentPrice,
                priceChange24h: stats.priceChangePercent,
                volume24h: stats.volume,
                volumeRatio: volumeRatio.toFixed(2),
                monthTrend: monthTrend.toFixed(2),
                high24h: stats.high,
                low24h: stats.low,
                signal: volumeRatio > 1.5 && monthTrend > -10 ? 'OBSERVE' : 'NEUTRAL',
                // Islamic note
                halalNote: `Minimum recommended holding period: ${minHoldingDays || MIN_HOLDING_DAYS} days for genuine ownership`,
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            analysisResults.push({ symbol: symbol, error: error.message });
        }
    }
    
    res.json({ success: true, analysis: analysisResults, minHoldingDays: MIN_HOLDING_DAYS });
});

// ==================== PENDING SIGNALS (User Must Approve) ====================
app.post('/api/create-signal', authenticate, async (req, res) => {
    const { symbol, usdtAmount, accountType, commitmentToHoldDays } = req.body;
    
    if (!symbol || !usdtAmount) {
        return res.status(400).json({ success: false, message: 'Symbol and amount required' });
    }
    
    if (usdtAmount < 10) {
        return res.status(400).json({ success: false, message: 'Minimum investment is $10' });
    }
    
    if (commitmentToHoldDays < MIN_HOLDING_DAYS) {
        return res.status(400).json({ success: false, message: `You must commit to hold for at least ${MIN_HOLDING_DAYS} days (Islamic ownership requirement)` });
    }
    
    const users = readUsers();
    const user = users[req.user.email];
    if (!user.apiKey) {
        return res.status(400).json({ success: false, message: 'Please add API keys first' });
    }
    
    // Get current price for reference
    const useDemo = (accountType === 'testnet');
    const currentPrice = await getCurrentPrice(symbol, useDemo);
    const stats = await get24hrStats(symbol, useDemo);
    
    // Create pending signal (NOT executed yet)
    const signal = {
        symbol: symbol,
        usdtAmount: usdtAmount,
        currentPrice: currentPrice,
        priceChange24h: stats.priceChangePercent,
        volume24h: stats.volume,
        commitmentToHoldDays: commitmentToHoldDays,
        accountType: accountType,
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(), // Expires in 1 hour
        status: 'pending'
    };
    
    saveSignal(req.user.email, signal);
    
    res.json({ 
        success: true, 
        message: `Signal created for ${symbol}. You have 1 hour to approve or reject.`,
        signal: signal
    });
});

// Get pending signals (user needs to approve)
app.get('/api/pending-signals', authenticate, (req, res) => {
    const signals = loadSignals(req.user.email);
    const pendingSignals = signals.filter(s => s.status === 'pending' && new Date(s.expiresAt) > new Date());
    res.json({ success: true, signals: pendingSignals });
});

// Approve a signal (USER MUST CLICK APPROVE)
app.post('/api/approve-signal', authenticate, async (req, res) => {
    const { signalId } = req.body;
    
    const signals = loadSignals(req.user.email);
    const signal = signals.find(s => s.id === signalId);
    
    if (!signal) {
        return res.status(404).json({ success: false, message: 'Signal not found' });
    }
    
    if (signal.status !== 'pending') {
        return res.status(400).json({ success: false, message: `Signal already ${signal.status}` });
    }
    
    if (new Date(signal.expiresAt) < new Date()) {
        updateSignalStatus(req.user.email, signalId, 'expired');
        return res.status(400).json({ success: false, message: 'Signal has expired' });
    }
    
    const users = readUsers();
    const user = users[req.user.email];
    const apiKey = decrypt(user.apiKey);
    const secretKey = decrypt(user.secretKey);
    const useDemo = (signal.accountType === 'testnet');
    
    try {
        // Check balance
        const balance = await getSpotBalance(apiKey, secretKey, useDemo);
        if (balance < signal.usdtAmount) {
            updateSignalStatus(req.user.email, signalId, 'failed');
            return res.status(400).json({ success: false, message: `Insufficient balance: ${balance} USDT < ${signal.usdtAmount}` });
        }
        
        // Execute the buy order (USER APPROVED)
        const order = await executeBuyOrder(apiKey, secretKey, signal.symbol, signal.usdtAmount, useDemo);
        const fillPrice = parseFloat(order.fills?.[0]?.price || signal.currentPrice);
        const quantity = parseFloat(order.executedQty);
        
        // Save to holdings
        const holdings = loadHoldings(req.user.email);
        holdings.push({
            symbol: signal.symbol,
            quantity: quantity,
            entryPrice: fillPrice,
            usdtAmount: signal.usdtAmount,
            entryDate: new Date().toISOString(),
            entryTimestamp: Date.now(),
            commitmentToHoldDays: signal.commitmentToHoldDays,
            signalId: signalId
        });
        saveHoldings(req.user.email, holdings);
        
        // Save to trade history
        const userTradeFile = path.join(tradesDir, req.user.email.replace(/[^a-z0-9]/gi, '_') + '.json');
        let allTrades = [];
        if (fs.existsSync(userTradeFile)) allTrades = JSON.parse(fs.readFileSync(userTradeFile));
        allTrades.unshift({
            type: 'BUY',
            symbol: signal.symbol,
            quantity: quantity,
            price: fillPrice,
            usdtAmount: signal.usdtAmount,
            commitmentToHoldDays: signal.commitmentToHoldDays,
            timestamp: new Date().toISOString()
        });
        fs.writeFileSync(userTradeFile, JSON.stringify(allTrades, null, 2));
        
        // Update signal status
        updateSignalStatus(req.user.email, signalId, 'executed', { fillPrice, quantity });
        
        res.json({ 
            success: true, 
            message: `✅ Trade executed! Bought ${quantity.toFixed(6)} ${signal.symbol} at $${fillPrice}. You committed to hold for ${signal.commitmentToHoldDays} days.`,
            order: order
        });
        
    } catch (error) {
        updateSignalStatus(req.user.email, signalId, 'failed');
        res.status(500).json({ success: false, message: 'Trade failed: ' + error.message });
    }
});

// Reject a signal
app.post('/api/reject-signal', authenticate, async (req, res) => {
    const { signalId } = req.body;
    updateSignalStatus(req.user.email, signalId, 'rejected');
    res.json({ success: true, message: 'Signal rejected' });
});

// ==================== SELL ORDERS (Manual - User decides when to sell) ====================
app.post('/api/manual-sell', authenticate, async (req, res) => {
    const { symbol, quantity, accountType } = req.body;
    
    const holdings = loadHoldings(req.user.email);
    const holding = holdings.find(h => h.symbol === symbol);
    
    if (!holding) {
        return res.status(404).json({ success: false, message: 'Position not found' });
    }
    
    if (quantity > holding.quantity) {
        return res.status(400).json({ success: false, message: `Insufficient quantity. You have ${holding.quantity}` });
    }
    
    // Check if minimum holding period has been met
    const daysHeld = (Date.now() - holding.entryTimestamp) / (1000 * 60 * 60 * 24);
    if (daysHeld < holding.commitmentToHoldDays) {
        return res.status(400).json({ 
            success: false, 
            message: `Cannot sell yet. You committed to hold for ${holding.commitmentToHoldDays} days. Only ${daysHeld.toFixed(1)} days passed. Islamic ownership requirement.` 
        });
    }
    
    const users = readUsers();
    const user = users[req.user.email];
    const apiKey = decrypt(user.apiKey);
    const secretKey = decrypt(user.secretKey);
    const useDemo = (accountType === 'testnet');
    
    try {
        const currentPrice = await getCurrentPrice(holding.symbol, useDemo);
        const order = await executeSellOrder(apiKey, secretKey, holding.symbol, quantity, useDemo);
        const exitPrice = parseFloat(order.fills?.[0]?.price || currentPrice);
        const profit = (exitPrice - holding.entryPrice) * quantity;
        
        // Update holdings
        if (quantity === holding.quantity) {
            const updatedHoldings = holdings.filter(h => h.symbol !== symbol);
            saveHoldings(req.user.email, updatedHoldings);
        } else {
            holding.quantity -= quantity;
            saveHoldings(req.user.email, holdings);
        }
        
        // Save to trade history
        const userTradeFile = path.join(tradesDir, req.user.email.replace(/[^a-z0-9]/gi, '_') + '.json');
        let allTrades = [];
        if (fs.existsSync(userTradeFile)) allTrades = JSON.parse(fs.readFileSync(userTradeFile));
        allTrades.unshift({
            type: 'SELL',
            symbol: holding.symbol,
            quantity: quantity,
            entryPrice: holding.entryPrice,
            exitPrice: exitPrice,
            profit: profit,
            profitPercent: ((profit / (holding.entryPrice * quantity)) * 100).toFixed(2),
            daysHeld: daysHeld.toFixed(1),
            timestamp: new Date().toISOString()
        });
        fs.writeFileSync(userTradeFile, JSON.stringify(allTrades, null, 2));
        
        res.json({ success: true, message: `Sold ${quantity} ${holding.symbol} at $${exitPrice}. Profit: $${profit.toFixed(2)}`, profit: profit });
        
    } catch (error) {
        res.status(500).json({ success: false, message: 'Sell failed: ' + error.message });
    }
});

// ==================== VIEW HOLDINGS ====================
app.post('/api/holdings', authenticate, async (req, res) => {
    const { accountType } = req.body;
    const holdings = loadHoldings(req.user.email);
    const useDemo = (accountType === 'testnet');
    
    const holdingsWithData = [];
    for (const holding of holdings) {
        try {
            const currentPrice = await getCurrentPrice(holding.symbol, useDemo);
            const currentValue = currentPrice * holding.quantity;
            const entryValue = holding.entryPrice * holding.quantity;
            const unrealizedPnL = currentValue - entryValue;
            const unrealizedPercent = (unrealizedPnL / entryValue) * 100;
            const daysHeld = (Date.now() - holding.entryTimestamp) / (1000 * 60 * 60 * 24);
            const canSell = daysHeld >= holding.commitmentToHoldDays;
            
            holdingsWithData.push({
                ...holding,
                currentPrice: currentPrice,
                currentValue: currentValue,
                unrealizedPnL: unrealizedPnL,
                unrealizedPercent: unrealizedPercent.toFixed(2),
                daysHeld: daysHeld.toFixed(1),
                canSell: canSell,
                remainingDays: Math.max(0, holding.commitmentToHoldDays - daysHeld).toFixed(1)
            });
        } catch (e) {
            holdingsWithData.push({ ...holding, error: true });
        }
    }
    
    res.json({ success: true, holdings: holdingsWithData, minHoldingDays: MIN_HOLDING_DAYS });
});

// ==================== TRADE HISTORY ====================
app.get('/api/trade-history', authenticate, (req, res) => {
    const userTradeFile = path.join(tradesDir, req.user.email.replace(/[^a-z0-9]/gi, '_') + '.json');
    if (!fs.existsSync(userTradeFile)) {
        return res.json({ success: true, trades: [] });
    }
    const trades = JSON.parse(fs.readFileSync(userTradeFile));
    res.json({ success: true, trades: trades });
});

// ==================== BALANCE ====================
app.post('/api/get-balance', authenticate, async (req, res) => {
    const { accountType } = req.body;
    const users = readUsers();
    const user = users[req.user.email];
    if (!user || !user.apiKey) return res.json({ success: false, balance: 0 });
    try {
        const apiKey = decrypt(user.apiKey);
        const secretKey = decrypt(user.secretKey);
        const useDemo = (accountType === 'testnet');
        const spotBalance = await getSpotBalance(apiKey, secretKey, useDemo);
        res.json({ success: true, spotBalance: spotBalance });
    } catch (error) {
        res.json({ success: false, balance: 0 });
    }
});

// ==================== AVAILABLE COINS ====================
app.get('/api/available-coins', authenticate, (req, res) => {
    const coins = [
        { symbol: 'BTCUSDT', name: 'Bitcoin' },
        { symbol: 'ETHUSDT', name: 'Ethereum' },
        { symbol: 'BNBUSDT', name: 'Binance Coin' },
        { symbol: 'SOLUSDT', name: 'Solana' },
        { symbol: 'ADAUSDT', name: 'Cardano' },
        { symbol: 'XRPUSDT', name: 'Ripple' }
    ];
    res.json({ success: true, coins: coins, minHoldingDays: MIN_HOLDING_DAYS });
});

// ==================== OWNER ROUTES ====================
app.get('/api/admin/users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const users = readUsers();
    const list = Object.keys(users).map(email => ({
        email, hasApiKeys: !!users[email].apiKey, isOwner: users[email].isOwner, isApproved: users[email].isApproved, isBlocked: users[email].isBlocked
    }));
    res.json({ success: true, users: list });
});

app.get('/api/admin/all-trades', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const allTrades = {};
    const files = fs.readdirSync(tradesDir);
    for (const file of files) {
        if (file === '.gitkeep') continue;
        allTrades[file.replace('.json', '')] = JSON.parse(fs.readFileSync(path.join(tradesDir, file)));
    }
    res.json({ success: true, trades: allTrades });
});

app.post('/api/change-password', authenticate, async (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { currentPassword, newPassword } = req.body;
    const users = readUsers();
    const owner = users[req.user.email];
    if (!bcrypt.compareSync(currentPassword, owner.password)) return res.status(401).json({ success: false, message: 'Current password incorrect' });
    owner.password = bcrypt.hashSync(newPassword, 10);
    writeUsers(users);
    res.json({ success: true, message: 'Password changed!' });
});

// ==================== CATCH‑ALL ROUTE ====================
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n╔════════════════════════════════════════════════════════════════════╗`);
    console.log(`║         🕋 100% HALAL SEMI-AUTO TRADING BOT v10.0              ║`);
    console.log(`╠════════════════════════════════════════════════════════════════════╣`);
    console.log(`║  OWNER: mujtabahatif@gmail.com                                    ║`);
    console.log(`║  PASSWORD: Mujtabah@2598                                          ║`);
    console.log(`╠════════════════════════════════════════════════════════════════════╣`);
    console.log(`║  ISLAMIC COMPLIANCE:                                              ║`);
    console.log(`║  ✅ Bot ANALYZES - User DECIDES (No auto-execution)               ║`);
    console.log(`║  ✅ User must APPROVE every trade manually                        ║`);
    console.log(`║  ✅ Minimum ${MIN_HOLDING_DAYS} day holding period (Ownership)            ║`);
    console.log(`║  ✅ NO take-profit targets (No gambling)                          ║`);
    console.log(`║  ✅ NO stop-loss (No gambling)                                    ║`);
    console.log(`║  ✅ Spot trading only, Long only, Your capital                    ║`);
    console.log(`║  ✅ No interest (Riba)                                            ║`);
    console.log(`║  ✅ No speculation (Gharar) - User researches fundamentals        ║`);
    console.log(`╠════════════════════════════════════════════════════════════════════╣`);
    console.log(`║  Server running on port: ${PORT}                                      ║`);
    console.log(`╚════════════════════════════════════════════════════════════════════╝`);
});
