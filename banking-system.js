const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

dotenv.config();
const app = express();
app.use(express.json());

// Connect to MongoDB
mongoose.connect(process.env.DB_URI2, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    balance: { type: Number, default: 0 },
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// Transaction Log Schema
const transactionLogSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    type: { type: String, required: true }, // "withdrawal" or "transfer"
    amount: { type: Number, required: true },
    timestamp: { type: Date, default: Date.now }
});

const TransactionLog = mongoose.model('TransactionLog', transactionLogSchema);

// Helper functions to generate tokens
const generateAccessToken = (user) => {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
};

// Middleware to authenticate tokens
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// User registration
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });

    try {
        await newUser.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// User login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    const accessToken = generateAccessToken({ id: user._id });
    res.json({ accessToken });
});

// GET Balance API
app.get('/balance', authenticateToken, async (req, res) => {
    const user = await User.findById(req.user.id).select('balance');
    res.json({ balance: user.balance });
});

// Withdrawal API
app.post('/withdraw', authenticateToken, async (req, res) => {
    const { amount } = req.body;
    const user = await User.findById(req.user.id);

    if (user.balance < amount) {
        return res.status(400).json({ message: 'Insufficient balance' });
    }

    user.balance -= amount;
    await user.save();

    // Log transaction
    const transactionLog = new TransactionLog({ userId: user._id, type: 'withdrawal', amount });
    await transactionLog.save();

    res.json({ message: 'Withdrawal successful', balance: user.balance });
});

// Money Transfer API
app.post('/transfer', authenticateToken, async (req, res) => {
    const { amount, toUser } = req.body;
    const fromUser = await User.findById(req.user.id);
    const toUserAccount = await User.findOne({ username: toUser });

    if (!toUserAccount) {
        return res.status(400).json({ message: 'Recipient not found' });
    }

    if (fromUser.balance < amount) {
        return res.status(400).json({ message: 'Insufficient balance' });
    }

    fromUser.balance -= amount;
    toUserAccount.balance += amount;

    await fromUser.save();
    await toUserAccount.save();

    // Log transaction
    const transactionLog = new TransactionLog({ userId: fromUser._id, type: 'transfer', amount });
    await transactionLog.save();

    res.json({ message: 'Transfer successful', balance: fromUser.balance });
});

// Transaction History API
app.get('/transactions', authenticateToken, async (req, res) => {
    const logs = await TransactionLog.find({ userId: req.user.id }).populate('userId');
    res.json(logs);
});

// Start the server
app.listen(3000, () => {
    console.log('Server running on port 3000');
});
