// FeedbackModel.js
const mongoose = require('mongoose');

const feedbackSchema = new mongoose.Schema({
  name: { type: String, required: true },
  phone: { type: String }, // Change phonenumber to phone and specify type as String
  place: { type: String },
  feedback: { type: String, required: true } // Make sure to specify the feedback field
});

const Feedback = mongoose.model('Feedback', feedbackSchema); // Change feedback to Feedback

module.exports = Feedback;
