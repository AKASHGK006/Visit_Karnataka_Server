const express = require("express");
const mongoose = require('mongoose');
const cors = require("cors");
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const xss = require('xss');
const jwt = require('jsonwebtoken');
const SignupModel = require('./models/Signup');
const Place = require('./models/PlaceModel');
const Feedback = require('./models/Feedback');
const Booking = require('./models/Booking');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT;

app.use(cors({
    origin: ["https://visit-karnataka-frontend.vercel.app"],
    methods: ["GET", "PUT", "POST", "DELETE"],
    credentials: true,
}));

app.use(helmet()); // Add security headers
app.use(express.json({ limit: '100mb' }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 })); // Limit repeated requests

const secretKey = process.env.JWT_SECRET_KEY;
const refreshSecretKey = process.env.JWT_REFRESH_SECRET_KEY;

mongoose.connect(process.env.MONGO_URL, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("Connected to MongoDB!"))
    .catch((err) => console.error("Error connecting to MongoDB:", err));

// Reusable error handling function
const handleError = (res, statusCode, message) => {
    console.error(message);
    res.status(statusCode).json({ error: message });
};

// Middleware to check for JWT token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401);

    jwt.verify(token, secretKey, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Sanitize input data
const sanitizeInput = (input) => {
    return xss(input);
};

// Route to check if phone number exists
app.get('/checkUserExist', async (req, res) => {
    try {
        const { phone } = req.query;
        const sanitizedPhone = sanitizeInput(phone);
        const user = await SignupModel.findOne({ phone: sanitizedPhone });

        if (user) {
            return res.json({ exists: true });
        } else {
            return res.json({ exists: false });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

// Endpoint for user login
app.post('/Login', async (req, res) => {
    try {
        const { phone, password } = req.body;
        const sanitizedPhone = sanitizeInput(phone);
        const sanitizedPassword = sanitizeInput(password);
        const user = await SignupModel.findOne({ phone: sanitizedPhone });

        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        const passwordMatch = await bcrypt.compare(sanitizedPassword, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ error: "Incorrect Password" });
        }

        const token = jwt.sign({ userId: user._id, role: user.role }, secretKey, { expiresIn: '15m' });
        const refreshToken = jwt.sign({ userId: user._id, role: user.role }, refreshSecretKey);

        res.json({
            Status: "Success",
            role: user.role,
            name: user.name,
            phone: user.phone,
            token,
            refreshToken
        });
    } catch (err) {
        console.error("Login error:", err);
        handleError(res, 500, 'Internal server error');
    }
});

// Endpoint for refreshing JWT token
app.post('/RefreshToken', async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) {
        return res.status(401).json({ error: 'Refresh token missing' });
    }

    try {
        jwt.verify(refreshToken, refreshSecretKey, (err, decoded) => {
            if (err) {
                return res.status(403).json({ error: 'Invalid refresh token' });
            }

            const newToken = jwt.sign({ userId: decoded.userId, role: decoded.role }, secretKey, { expiresIn: '15m' });
            res.json({ token: newToken });
        });
    } catch (err) {
        handleError(res, 500, 'Internal server error');
    }
});

// Endpoint for user signup
app.post('/Signup', async (req, res) => {
    try {
        const { name, phone, password } = req.body;
        const sanitizedName = sanitizeInput(name);
        const sanitizedPhone = sanitizeInput(phone);
        const sanitizedPassword = sanitizeInput(password);
        const hash = await bcrypt.hash(sanitizedPassword, 10);
        await SignupModel.create({ name: sanitizedName, phone: sanitizedPhone, password: hash });
        res.json({ status: "OK" });
    } catch (err) {
        handleError(res, 500, 'Internal server error');
    }
});

// Endpoint for creating places (authenticated route)
app.post('/Createplaces', authenticateToken, async (req, res) => {
    try {
        const sanitizedData = sanitizeInput(req.body);
        const place = await Place.create(sanitizedData);
        res.json({ status: "OK", place });
    } catch (err) {
        handleError(res, 500, err.message);
    }
});

// Endpoint for retrieving all places
app.get('/places', async (req, res) => {
    try {
        const places = await Place.find({});
        res.json(places);
    } catch (err) {
        handleError(res, 500, 'Internal server error');
    }
});

// Endpoint for retrieving a specific place by ID
app.get('/places/:id', async (req, res) => {
    try {
        const sanitizedId = sanitizeInput(req.params.id);
        const place = await Place.findById(sanitizedId);
        if (!place) return res.status(404).json({ error: 'Place not found' });
        res.json(place);
    } catch (err) {
        handleError(res, 500, 'Internal server error');
    }
});

// Endpoint for deleting a place by ID (authenticated route)
app.delete('/places/:id', authenticateToken, async (req, res) => {
    try {
        const sanitizedId = sanitizeInput(req.params.id);
        const deletedPlace = await Place.findByIdAndDelete(sanitizedId);
        if (!deletedPlace) return res.status(404).json({ error: 'Place not found' });
        res.json({ message: 'Place deleted successfully', deletedPlace });
    } catch (err) {
        handleError(res, 500, 'Internal server error');
    }
});

// Endpoint for updating a place by ID (authenticated route)
app.put('/places/:placeId', authenticateToken, async (req, res) => {
    try {
        const sanitizedId = sanitizeInput(req.params.placeId);
        const sanitizedData = sanitizeInput(req.body);
        const updatedPlace = await Place.findByIdAndUpdate(sanitizedId, sanitizedData, { new: true });
        res.json({ status: 'OK', updatedPlace });
    } catch (err) {
        handleError(res, 500, 'Failed to update place. Please try again.');
    }
});

// Endpoint for creating Feedback (authenticated route)
app.post('/Feedback', async (req, res) => {
    try {
        const sanitizedData = sanitizeInput(req.body);
        const feedback = await Feedback.create(sanitizedData);
        res.json({ status: "OK", feedback });
    } catch (err) {
        handleError(res, 500, err.message);
    }
});

// Endpoint for fetching feedback data (authenticated route)
app.get('/Feedback', authenticateToken, async (req, res) => {
    try {
        const feedbackData = await Feedback.find();
        res.json(feedbackData);
    } catch (err) {
        handleError(res, 500, err.message);
    }
});

// Endpoint for deleting a feedback entry by ID (authenticated route)
app.delete('/Feedback/:id', authenticateToken, async (req, res) => {
    try {
        const sanitizedId = sanitizeInput(req.params.id);
        const deletedFeedback = await Feedback.findByIdAndDelete(sanitizedId);

        if (!deletedFeedback) {
            return res.status(404).json({ error: "Feedback entry not found" });
        }

        res.json({ message: "Feedback entry deleted successfully", deletedFeedback });
    } catch (err) {
        handleError(res, 500, err.message);
    }
});

// Endpoint for creating bookings (authenticated route)
app.post('/bookings', async (req, res) => {
    try {
        const { name, mobileNumber, place, participants, date, time, language, totalPrice } = req.body;

        const sanitizedBookingData = {
            name: sanitizeInput(name),
            mobileNumber: sanitizeInput(mobileNumber),
            place: sanitizeInput(place),
            participants: sanitizeInput(participants),
            date: sanitizeInput(date),
            time: sanitizeInput(time),
            language: sanitizeInput(language),
            totalPrice: sanitizeInput(totalPrice)
        };

        const newBooking = new Booking(sanitizedBookingData);

        const savedBooking = await newBooking.save();
        res.status(201).json(savedBooking);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Endpoint for retrieving bookings (authenticated route)
app.get('/bookings', authenticateToken, async (req, res) => {
    try {
        const bookings = await Booking.find();
        res.status(200).json(bookings);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Endpoint for deleting a booking by ID (authenticated route)
app.delete('/bookings/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;

    try {
        const sanitizedId = sanitizeInput(id);
        const deletedBooking = await Booking.findByIdAndDelete(sanitizedId);

        if (!deletedBooking) {
            return res.status(404).json({ error: 'Booking not found' });
        }

        res.json({ message: 'Booking deleted successfully' });
    } catch (error) {
        console.error('Error deleting booking:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Enforce HTTPS
app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] !== 'https') {
        return res.redirect(`https://${req.headers.host}${req.url}`);
    }
    next();
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
