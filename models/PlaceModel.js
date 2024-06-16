// PlaceModel.js
const mongoose = require('mongoose');

const placeSchema = new mongoose.Schema({
  placetitle: { type: String, required: true },
  placelocation: { type: String, required: true },
  guidename: String,
  guidemobile: String,
  guidelanguage: String,
  residentialdetails: String,
  policestation: String,
  firestation: String,
  maplink: String,
  description: { type: String, required: true },
  image: String // Assuming this will store the URL of the image
});

const Place = mongoose.model('Place', placeSchema);

module.exports = Place;
