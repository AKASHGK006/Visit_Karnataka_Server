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