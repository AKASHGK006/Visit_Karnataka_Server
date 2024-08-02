const express = require("express");
const mongoose = require('mongoose');
const cors = require("cors");
const bcrypt = require('bcrypt');
const SignupModel = require('./models/Signup');
const Place = require('./models/PlaceModel');
const Feedback = require('./models/Feedback');
const Booking = require('./models/Booking');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

const allowedOrigins = ['https://visit-karnataka-frontend.vercel.app'];

app.use(cors({
    origin: allowedOrigins,
    methods: ["GET", "PUT", "POST", "DELETE"],
    credentials: true,
}));

app.use(express.json({ limit: '100kb' }));

mongoose.connect(process.env.MONGO_URL)
    .then(() => {
        console.log("Connected to MongoDB!");
    })
    .catch((err) => {
        console.error("Error connecting to MongoDB:", err);
    });

// Middleware to check Referer header
const checkReferer = (req, res, next) => {
    const referer = req.get('Referer');
    if (!referer || !allowedOrigins.some(origin => referer.startsWith(origin))) {
        return res.status(403).json({ Message: 'Unauthorized' });
    }
    next();
};

// Reusable error handling function
const handleError = (res, statusCode, message) => {
    console.error(message);
    res.status(statusCode).json({ error: message });
};


// Endpoint to check if phone number exists
app.get('/checkUserExist', checkReferer, async (req, res) => {
    try {
        const { phone } = req.query;
        const user = await SignupModel.findOne({ phone });
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
app.post('/Login', checkReferer, async (req, res) => {
    try {
        const { phone, password } = req.body;
        const user = await SignupModel.findOne({ phone });
        if (!user) {
            console.log("User not found for phone:", phone);
            return res.status(404).json({ error: "User not found" });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            console.log("Incorrect password for phone:", phone);
            return res.status(401).json({ error: "Incorrect Password" });
        }

        res.json({
            Status: "Success",
            role: user.role,
            name: user.name,
            phone: user.phone
        });
    } catch (err) {
        console.error("Login error:", err);
        handleError(res, 500, 'Internal server error');
    }
});

// Endpoint for user signup
app.post('/Signup', checkReferer, async (req, res) => {
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
app.post('/Createplaces', checkReferer, async (req, res) => {
    try {
        const place = await Place.create(req.body);
        res.json({ status: "OK", place });
    } catch (err) {
        handleError(res, 500, err.message);
    }
});

// Endpoint for retrieving all places
app.get('/places', checkReferer, async (req, res) => {
    try {
        const places = await Place.find({});
        res.json(places);
    } catch (err) {
        handleError(res, 500, 'Internal server error');
    }
});

// Endpoint for retrieving a specific place by ID
app.get('/places/:id', checkReferer, async (req, res) => {
    try {
        const place = await Place.findById(req.params.id);
        if (!place) return res.status(404).json({ error: 'Place not found' });
        res.json(place);
    } catch (err) {
        handleError(res, 500, 'Internal server error');
    }
});

// Endpoint for deleting a place by ID
app.delete('/places/:id', checkReferer, async (req, res) => {
    try {
        const deletedPlace = await Place.findByIdAndDelete(req.params.id);
        if (!deletedPlace) return res.status(404).json({ error: 'Place not found' });
        res.json({ message: 'Place deleted successfully', deletedPlace });
    } catch (err) {
        handleError(res, 500, 'Internal server error');
    }
});

// Endpoint for updating a place by ID
app.put('/places/:placeId', checkReferer, async (req, res) => {
    try {
        const updatedPlace = await Place.findByIdAndUpdate(req.params.placeId, req.body, { new: true });
        res.json({ status: 'OK', updatedPlace });
    } catch (err) {
        handleError(res, 500, 'Failed to update place. Please try again.');
    }
});

// Endpoint for creating Feedback
app.post('/Feedback', checkReferer, async (req, res) => {
    try {
        const feedback = await Feedback.create(req.body);
        res.json({ status: "OK", feedback });
    } catch (err) {
        handleError(res, 500, err.message);
    }
});

// Endpoint for fetching feedback data
app.get('/Feedback', checkReferer, async (req, res) => {
    try {
        const feedbackData = await Feedback.find();
        res.json(feedbackData);
    } catch (err) {
        handleError(res, 500, err.message);
    }
});

// Endpoint for deleting a feedback entry by ID
app.delete('/Feedback/:id', checkReferer, async (req, res) => {
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

// Endpoint for creating bookings
app.post('/bookings', checkReferer, async (req, res) => {
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
app.get('/bookings', checkReferer, async (req, res) => {
    try {
        const bookings = await Booking.find(); // Retrieve all bookings
        res.status(200).json(bookings); // Send bookings as JSON response
    } catch (error) {
        res.status(500).json({ error: error.message }); // Handle server error
    }
});

// Endpoint for deleting a booking by ID
app.delete('/bookings/:id', checkReferer, async (req, res) => {
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
