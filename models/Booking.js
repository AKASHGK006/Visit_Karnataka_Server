const mongoose = require('mongoose');

// Define a booking schema
const BookingSchema = new mongoose.Schema({
  name: { type: String, required: true },
  mobileNumber: { type: String, required: true },
  place: { type: String, required: true },
  participants: { type: Number, required: true },
  date: { type: Date, required: true },
  time: { type: String, required: true },
  language: { type: String, required: true },
  totalPrice: { type: Number, required: true }
});

const Booking = mongoose.model('Booking', BookingSchema);

module.exports = Booking;