const express = require("express");
const mongoose = require('mongoose');
const cors = require("cors");
const bcrypt = require('bcrypt');
const SignupModel = require('./models/Signup');
const Place = require('./models/PlaceModel');
const Feedback = require('./models/Feedback');
const app = express();
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
require('dotenv').config();
const PORT = process.env.PORT;

app.use(cors({
  origin: ["https://visit-karnataka-frontend.onrender.com"],
  methods: ["GET", "PUT", "POST", "DELETE"],
  credentials: true, // Allow credentials
}));

app.use(express.json());

const secretKey = process.env.key;
const refreshSecretKey = process.env.rkey;

mongoose.connect(process.env.MONGO_URL)
.then(() => {
console.log("Connected to MongoDB!");
})
.catch((err) => {
console.error("Error connecting to MongoDB:", err);
});

// Multer storage configuration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/'); // Save files to uploads directory
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname); // Add timestamp to file name to avoid duplicates
  }
});

// Multer file filter to accept only images
const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith('image/')) {
    cb(null, true);
  } else {
    cb(new Error('Only images are allowed.'), false);
  }
};

const upload = multer({ storage, fileFilter });

// Reusable error handling function
const handleError = (res, statusCode, message) => {
  console.error(message);
  res.status(statusCode).json({ error: message });
};

// Endpoint for creating places with image upload
app.post('/Createplaces', upload.single('image'), async (req, res) => {
  try {
    // Destructure fields from req.body and req.file
    const { placetitle, placelocation, guidename, guidemobile, guidelanguage, residentialdetails, policestation, firestation, maplink, description } = req.body;
    const { filename: image } = req.file; // Multer adds the 'file' object to the request
    
    // Create a new place record in MongoDB
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
      image: 'uploads/' + image, // Save relative path to image in database
    });

    res.json({ status: "OK", place });
  } catch (err) {
    handleError(res, 500, err.message);
  }
});

// Serve uploaded images statically
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

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

// Update endpoint with file upload
app.put('/places/:placeId', upload.single('image'), async (req, res) => {
    try {
      const updateData = { ...req.body };
      if (req.file) {
        updateData.image = 'uploads/' + req.file.filename; // Save relative path to image in database
      }
  
      const updatedPlace = await Place.findByIdAndUpdate(req.params.placeId, updateData, { new: true });
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
