const mongoose = require('mongoose');

const SignupSchema = new mongoose.Schema({
    name: String,
    phone: Number,
    password: String,
    role:{
        type: String,
        default:"User"
    }
}, { collection: 'Cred' });

const SignupModel = mongoose.model("Cred", SignupSchema);
module.exports = SignupModel;
