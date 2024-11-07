const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

// Path to the JSON file where users will be stored
const usersFilePath = path.join(__dirname, 'users.json');

// Function to read users from the JSON file
const readUsersFromFile = () => {
  try {
    const data = fs.readFileSync(usersFilePath, 'utf8');
    return JSON.parse(data); // Parse the JSON data
  } catch (err) {
    return []; // If the file doesn't exist or is empty, return an empty array
  }
};

// Function to write users to the JSON file
const writeUsersToFile = (users) => {
  fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2)); // Pretty print with 2 spaces
};

// Create a new user and store it in the JSON file
const createUser = async (username, password) => {
  const user = { username, password };
  const users = readUsersFromFile();
  users.push(user);
  writeUsersToFile(users);
};

// Find a user by their username from the JSON file
const findUserByUsername = (username) => {
  const users = readUsersFromFile();
  return users.find(user => user.username === username);
};

module.exports = { createUser, findUserByUsername };
