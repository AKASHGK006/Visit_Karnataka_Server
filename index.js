const express = require("express");
const mongoose = require('mongoose');
const cors = require("cors");
const bcrypt = require('bcrypt');
const SignupModel = require('./models/Signup');
const Place = require('./models/PlaceModel');
const Feedback = require('./models/Feedback');
const app = express();
const jwt = require('jsonwebtoken');
const path = require('path');
const Booking = require('./models/Booking');
require('dotenv').config();

const PORT = process.env.PORT;

app.use(cors({
    origin: ["https://visit-karnataka-frontend.vercel.app"],
    methods: ["GET", "PUT", "POST", "DELETE"],
    credentials: true, // Allow credentials
}));

app.use(express.json({ limit: '100mb' }));

const secretKey = process.env.key;
const refreshSecretKey = process.env.rkey; // Add a separate secret key for refresh tokens

mongoose.connect(process.env.MONGO_URL)
    .then(() => {
        console.log("Connected to MongoDB!");
    })
    .catch((err) => {
        console.error("Error connecting to MongoDB:", err);
    });

// Reusable error handling function
const handleError = (res, statusCode, message) => {
    console.error(message);
    res.status(statusCode).json({ error: message });
};

// Middleware to verify admin role
const verifyAdmin = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ error: 'Authorization header missing' });
    }

    const token = authHeader.split(' ')[1];
    jwt.verify(token, secretKey, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Forbidden' });
        }

        if (user.role !== 'admin') {
            return res.status(403).json({ error: 'Admin role required' });
        }

        req.user = user;
        next();
    });
};

// Route to check if phone number exists
app.get('/checkUserExist', async (req, res) => {
    try {
        const { phone } = req.query;

        // Check if the phone number exists in the database
        const user = await SignupModel.findOne({ phone });

        // If user exists, return status true
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
        // Find user by phone number
        const user = await SignupModel.findOne({ phone });
        if (!user) {
            console.log("User not found for phone:", phone); // Added logging
            return res.status(404).json({ error: "User not found" });
        }

        // Compare passwords
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            console.log("Incorrect password for phone:", phone); // Added logging
            return res.status(401).json({ error: "Incorrect Password" });
        }

        // Generate JWT token and refresh token
        const token = jwt.sign({ userId: user._id, role: user.role }, secretKey, { expiresIn: '10s' });
        const refreshToken = jwt.sign({ userId: user._id, role: user.role }, refreshSecretKey);

        res.json({
            Status: "Success",
            role: user.role,
            name: user.name,
            phone: user.phone,
            token,
            refreshToken // Send the refresh token to the client
        });
    } catch (err) {
        console.error("Login error:", err); // Added logging
        handleError(res, 500, 'Internal server error');
    }
});

// Endpoint for refreshing JWT token
app.post('/RefreshToken', async (req, res) => {
    const { token, refreshToken } = req.body;
    if (!token || !refreshToken) {
        return res.status(401).json({ error: 'Token or refresh token missing' });
    }

    try {
        // Verify the refresh token
        jwt.verify(refreshToken, refreshSecretKey, (err, decoded) => {
            if (err) {
                return res.status(403).json({ error: 'Invalid refresh token' });
            }

            // If refresh token is valid, generate a new JWT token
            const newToken = jwt.sign({ userId: decoded.userId, role: decoded.role }, secretKey, { expiresIn: '10s' });
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
        const hash = await bcrypt.hash(password, 10);
        await SignupModel.create({ name, phone, password: hash });
        res.json({ status: "OK" });
    } catch (err) {
        handleError(res, 500, 'Internal server error');
    }
});

// Endpoint for creating places
app.post('/Createplaces', verifyAdmin, async (req, res) => {
    try {
        const place = await Place.create(req.body);
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
        const place = await Place.findById(req.params.id);
        if (!place) return res.status(404).json({ error: 'Place not found' });
        res.json(place);
    } catch (err) {
        handleError(res, 500, 'Internal server error');
    }
});

// Endpoint for deleting a place by ID
app.delete('/places/:id', verifyAdmin, async (req, res) => {
    try {
        const deletedPlace = await Place.findByIdAndDelete(req.params.id);
        if (!deletedPlace) return res.status(404).json({ error: 'Place not found' });
        res.json({ message: 'Place deleted successfully', deletedPlace });
    } catch (err) {
        handleError(res, 500, 'Internal server error');
    }
});

// Endpoint for updating a place by ID
app.put('/places/:placeId', verifyAdmin, async (req, res) => {
    try {
        const updatedPlace = await Place.findByIdAndUpdate(req.params.placeId, req.body, { new: true });
        res.json({ status: 'OK', updatedPlace });
    } catch (err) {
        handleError(res, 500, 'Failed to update place. Please try again.');
    }
});

// Endpoint for creating Feedback (not restricted, as per your instruction)
app.post('/Feedback', async (req, res) => {
    try {
        const feedback = await Feedback.create(req.body);
        res.json({ status: "OK", feedback });
    } catch (err) {
        handleError(res, 500, err.message);
    }
});

// Endpoint for fetching feedback data
app.get('/Feedback', async (req, res) => {
    try {
        const feedbackData = await Feedback.find();
        res.json(feedbackData);
    } catch (err) {
        handleError(res, 500, err.message);
    }
});

// Endpoint for deleting a feedback entry by ID
app.delete('/Feedback/:id', verifyAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const deletedFeedback = await Feedback.findByIdAndDelete(id);

        if (!deletedFeedback) {
            return res.status(404).json({ error: "Feedback entry not found" });
        }

        res.json({ message: "Feedback entry deleted successfully", deletedFeedback });
    } catch (err) {
        handleError(res, 500, err.message);
    }
});

// Endpoint for creating bookings (not restricted, as per your instruction)
app.post('/bookings', async (req, res) => {
    console.log(req.body); // Log incoming data

    const { name, mobileNumber, place, participants, date, time, language, totalPrice } = req.body;

    const newBooking = new Booking({
        name,
        mobileNumber,
        place,
        participants,
        date,
        time,
        language,
        totalPrice
    });

    try {
        const savedBooking = await newBooking.save();
        res.status(201).json(savedBooking);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Endpoint for retrieving all bookings
app.get('/bookings', async (req, res) => {
    try {
        const bookings = await Booking.find(); // Retrieve all bookings
        res.status(200).json(bookings); // Send bookings as JSON response
    } catch (error) {
        res.status(500).json({ error: error.message }); // Handle server error
    }
});

// Endpoint for deleting a booking entry by ID
app.delete('/bookings/:id', verifyAdmin, async (req, res) => {
    const { id } = req.params;

    try {
        const deletedBooking = await Booking.findByIdAndDelete(id);

        if (!deletedBooking) {
            return res.status(404).json({ error: 'Booking not found' });
        }

        res.json({ message: 'Booking deleted successfully' });
    } catch (error) {
        console.error('Error deleting booking:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
