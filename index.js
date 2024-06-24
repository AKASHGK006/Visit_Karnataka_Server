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
app.post('/Createplaces', async (req, res) => {
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
app.delete('/places/:id' ,async (req, res) => {
    try {
        const deletedPlace = await Place.findByIdAndDelete(req.params.id);
        if (!deletedPlace) return res.status(404).json({ error: 'Place not found' });
        res.json({ message: 'Place deleted successfully', deletedPlace });
    } catch (err) {
        handleError(res, 500, 'Internal server error');
    }
});

// Endpoint for updating a place by ID
app.put('/places/:placeId', async (req, res) => {
    try {
        const updatedPlace = await Place.findByIdAndUpdate(req.params.placeId, req.body, { new: true });
        res.json({ status: 'OK', updatedPlace });
    } catch (err) {
        handleError(res, 500, 'Failed to update place. Please try again.');
    }
});


// Endpoint for creating Feedback
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
app.delete('/Feedback/:id', async (req, res) => {
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


app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
