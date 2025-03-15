const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
require('dotenv').config();

// Import models
const SignupModel = require('./models/Signup');
const Place = require('./models/PlaceModel');
const Feedback = require('./models/Feedback');
const Booking = require('./models/Booking');

const app = express();
const PORT = process.env.PORT || 5000;

const allowedOrigins = ['https://visit-karnataka-frontend.vercel.app'];

app.use(helmet());
app.use(cors({
    origin: allowedOrigins,
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
}));

app.use(express.json({ limit: '100kb' }));

mongoose.connect(process.env.MONGO_URL)
    .then(() => console.log("Connected to MongoDB!"))
    .catch(err => console.error("Error connecting to MongoDB:", err));

// Middleware to check Referer header
const checkReferer = (req, res, next) => {
    const referer = req.get('Referer');
    if (!referer || !allowedOrigins.some(origin => referer.startsWith(origin))) {
        return res.status(403).json({ message: 'Unauthorized' });
    }
    next();
};

// Error handling function
const handleError = (res, statusCode, message) => {
    console.error(message);
    res.status(statusCode).json({ error: message });
};

// Routes
app.get('/checkUserExist', checkReferer, async (req, res) => {
    try {
        const { phone } = req.query;
        const user = await SignupModel.findOne({ phone });
        res.json({ exists: !!user });
    } catch (error) {
        handleError(res, 500, 'Internal Server Error');
    }
});

app.post('/Login', checkReferer, async (req, res) => {
    console.log("Login API Hit:", req.body); // Debugging
    try {
        const { phone, password } = req.body;
        const user = await SignupModel.findOne({ phone });
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ error: "Incorrect Password" });
        }

        res.json({ status: "Success", role: user.role, name: user.name, phone: user.phone });
    } catch (err) {
        handleError(res, 500, 'Internal server error');
    }
});


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

app.post('/Createplaces', checkReferer, async (req, res) => {
    try {
        const place = await Place.create(req.body);
        res.json({ status: "OK", place });
    } catch (err) {
        handleError(res, 500, 'Failed to create place');
    }
});

app.get('/places', checkReferer, async (req, res) => {
    try {
        const places = await Place.find({});
        res.json(places);
    } catch (err) {
        handleError(res, 500, 'Failed to retrieve places');
    }
});

app.get('/places/:id', checkReferer, async (req, res) => {
    try {
        const place = await Place.findById(req.params.id);
        if (!place) return res.status(404).json({ error: 'Place not found' });
        res.json(place);
    } catch (err) {
        handleError(res, 500, 'Failed to retrieve place');
    }
});

app.delete('/places/:id', checkReferer, async (req, res) => {
    try {
        const deletedPlace = await Place.findByIdAndDelete(req.params.id);
        if (!deletedPlace) return res.status(404).json({ error: 'Place not found' });
        res.json({ message: 'Place deleted successfully', deletedPlace });
    } catch (err) {
        handleError(res, 500, 'Failed to delete place');
    }
});

app.put('/places/:placeId', checkReferer, async (req, res) => {
    try {
        const updatedPlace = await Place.findByIdAndUpdate(req.params.placeId, req.body, { new: true });
        res.json({ status: 'OK', updatedPlace });
    } catch (err) {
        handleError(res, 500, 'Failed to update place');
    }
});

app.post('/Feedback', checkReferer, async (req, res) => {
    try {
        const feedback = await Feedback.create(req.body);
        res.json({ status: "OK", feedback });
    } catch (err) {
        handleError(res, 500, 'Failed to create feedback');
    }
});

app.get('/Feedback', checkReferer, async (req, res) => {
    try {
        const feedbackData = await Feedback.find();
        res.json(feedbackData);
    } catch (err) {
        handleError(res, 500, 'Failed to retrieve feedback');
    }
});

app.delete('/Feedback/:id', checkReferer, async (req, res) => {
    try {
        const { id } = req.params;
        const deletedFeedback = await Feedback.findByIdAndDelete(id);
        if (!deletedFeedback) return res.status(404).json({ error: "Feedback entry not found" });
        res.json({ message: "Feedback entry deleted successfully", deletedFeedback });
    } catch (err) {
        handleError(res, 500, 'Failed to delete feedback');
    }
});

app.post('/bookings', checkReferer, async (req, res) => {
    try {
        const booking = new Booking(req.body);
        const savedBooking = await booking.save();
        res.status(201).json(savedBooking);
    } catch (error) {
        handleError(res, 400, error.message);
    }
});

app.get('/bookings', checkReferer, async (req, res) => {
    try {
        const bookings = await Booking.find();
        res.json(bookings);
    } catch (error) {
        handleError(res, 500, 'Failed to retrieve bookings');
    }
});

app.delete('/bookings/:id', checkReferer, async (req, res) => {
    try {
        const deletedBooking = await Booking.findByIdAndDelete(req.params.id);
        if (!deletedBooking) return res.status(404).json({ error: 'Booking not found' });
        res.json({ message: 'Booking deleted successfully' });
    } catch (error) {
        handleError(res, 500, 'Failed to delete booking');
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
