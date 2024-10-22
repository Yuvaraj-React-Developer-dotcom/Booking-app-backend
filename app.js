// # Main application setup (Express configuration)

const express = require('express');
const app = express();

// Middleware for parsing JSON requests
app.use(express.json());

// Basic route
app.get('/', (req, res) => {
  res.send('API is running...');
});

app.use('/api/auth', require('./routes/authRoutes'));

module.exports = app;
