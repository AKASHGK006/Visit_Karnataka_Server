const express = require("express");
const mongoose = require('mongoose');
const cors = require("cors");
const bcrypt = require('bcrypt');
const SignupModel = require('./models/Signup');
const Place = require('./models/PlaceModel');
const Feedback = require('./models/Feedback');
const app = express();
const jwt = require('jsonwebtoken');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });
const path = require('path');
require('dotenv').config();
const PORT = process.env.PORT;

app.use(cors({
  origin: ["https://visit-karnataka-frontend.vercel.app"],
  methods: ["GET", "PUT", "POST", "DELETE"],
  credentials: true, // Allow credentials
}));

app.use(express.json());

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const secretKey = process.env.key;
const refreshSecretKey = process.env.rkey;

mongoose.connect(process.env.MONGO_URL)
  .then(() => {
    console.log("Connected to MongoDB!");
  })
  .catch((err) => {
    console.error("Error connecting to MongoDB:", err);
  });

  
  app.post('/Createplaces', upload.single('file'), async (req, res) => {
    try {
      const { placetitle, placelocation, guidename, guidemobile, guidelanguage, residentialdetails, policestation, firestation, maplink, description } = req.body;
  
      // Upload image to Cloudinary
      const result = await cloudinary.uploader.upload(req.file.path);
  
      // Create a new place record in MongoDB with Cloudinary image URL
      const place = await Place.create({
        placetitle,
        placelocation,
        guidename,
        guidemobile,
        guidelanguage,
        residentialdetails,
        policestation,
        firestation,
        maplink,
        description,
        image: result.secure_url // Store Cloudinary URL in database
      });
  
      res.json({ status: "OK", place });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Failed to create place. Please try again.' });
    }
  });
  

// Serve uploaded images statically (if needed, though Cloudinary serves images directly)
// app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

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
    res.status(500).json({ error: 'Internal server error' });
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
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
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
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint for retrieving all places
app.get('/places', async (req, res) => {
  try {
    const places = await Place.find({});
    res.json(places);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint for retrieving a specific place by ID
app.get('/places/:id', async (req, res) => {
  try {
    const place = await Place.findById(req.params.id);
    if (!place) return res.status(404).json({ error: 'Place not found' });
    res.json(place);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint for deleting a place by ID
app.delete('/places/:id', async (req, res) => {
  try {
    const deletedPlace = await Place.findByIdAndDelete(req.params.id);
    if (!deletedPlace) return res.status(404).json({ error: 'Place not found' });
    res.json({ message: 'Place deleted successfully', deletedPlace });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update endpoint with file upload
app.put('/places/:placeId', async (req, res) => {
  try {
    const { placeId } = req.params;
    const updateData = { ...req.body };

    // If there's an uploaded image, upload it to Cloudinary
    if (req.file) {
      const result = await cloudinary.uploader.upload(req.file.path);
      updateData.image = result.secure_url;
    }

    const updatedPlace = await Place.findByIdAndUpdate(placeId, updateData, { new: true });
    if (!updatedPlace) {
      return res.status(404).json({ error: 'Place not found' });
    }

    res.json({ status: 'OK', updatedPlace });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update place. Please try again.' });
  }
});

// Endpoint for creating Feedback
app.post('/Feedback', async (req, res) => {
  try {
    const feedback = await Feedback.create(req.body);
    res.json({ status: "OK", feedback });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint for fetching feedback data
app.get('/Feedback', async (req, res) => {
  try {
    const feedbackData = await Feedback.find();
    res.json(feedbackData);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
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
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
