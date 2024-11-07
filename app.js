const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const { createUser, findUserByUsername } = require("./models/user");
const app = express();
const port = 3000;

// Use cookie-parser middleware to parse cookies
app.use(cookieParser());
// Middleware to parse incoming JSON
app.use(express.json()); // For JSON body parsing
app.use(express.urlencoded({ extended: true })); // For form data parsing

// JWT Secret key (store this securely, not hardcoded in production)
const JWT_SECRET = "your_jwt_secret_key";

// Utility to generate JWT
const generateToken = (user) => {
  return jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: "1h" });
};

// Utility to generate refresh token
const generateRefreshToken = (user) => {
  return jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: "7d" }); // Refresh token expires in 7 days
};

// Routes
app.get("/", (req, res) => {
  const token = req.cookies.auth_token; // Get token from cookies
  if (!token) {
    return res.status(401).json({ message: "Please log in" });
  }

  // Verify the token
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "Invalid or expired token" });
    }
    res.json({ message: `Welcome ${decoded.username}` });
  });
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = await findUserByUsername(username);
  if (!user) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  // Generate JWT token
  const token = generateToken(user);

  // Generate refresh token
  const refreshToken = generateRefreshToken(user);

  // Set JWT as a secure, HttpOnly cookie for access token
  res.cookie('auth_token', token, {
    httpOnly: true,        // Prevent access to the cookie from JavaScript
    secure: process.env.NODE_ENV === 'production',  // Use "secure" only in production (HTTPS)
    sameSite: 'Strict',    // Ensure the cookie is sent only to the same site
    maxAge: 3600000        // Token expiration in 1 hour
  });

  // Set refresh token as a secure, HttpOnly cookie
  res.cookie('refresh_token', refreshToken, {
    httpOnly: true, 
    secure: process.env.NODE_ENV === 'production', 
    sameSite: 'Strict', 
    maxAge: 604800000 // Refresh token expiration in 7 days
  });

  res.json({ message: "Logged in successfully" });
});

app.get("/logout", (req, res) => {
  // Clear both the access token and refresh token cookies
  res.clearCookie('auth_token');
  res.clearCookie('refresh_token');
  res.json({ message: "Logged out successfully" });
});

app.post("/refresh-token", (req, res) => {
  const refreshToken = req.cookies.refresh_token;
  if (!refreshToken) {
    return res.status(403).json({ message: "No refresh token provided" });
  }

  // Verify the refresh token
  jwt.verify(refreshToken, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "Invalid or expired refresh token" });
    }

    // Generate a new access token
    const newAccessToken = generateToken(decoded);

    res.json({ accessToken: newAccessToken });
  });
});

// Create a new user (signup route)
app.post("/signup", async (req, res) => {
  const { username, password } = req.body;

  // Check if the user already exists
  const existingUser = await findUserByUsername(username);
  if (existingUser) {
    return res.status(400).json({ message: "Username already exists" });
  }

  // Hash password before saving to the database
  const hashedPassword = await bcrypt.hash(password, 10);
  await createUser(username, hashedPassword);

  res.json({ message: "User created successfully", username });
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
