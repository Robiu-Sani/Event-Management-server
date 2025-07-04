# Event Management Web Application (MERN Stack)

This is a fully functional **Event Management API** built with **Node.js**, **Express.js**, **MongoDB**, and **JWT authentication**.  
It allows **user registration**, **login**, **event CRUD operations**, **search**, **filter**, and **user-specific actions** securely.

---

## 📌 Features

- ✅ User registration with hashed passwords using **bcrypt**
- ✅ JWT authentication for secure access
- ✅ CRUD operations for events
- ✅ Event search, filter (today, week, month)
- ✅ Pagination for listing events
- ✅ Protected routes for user-specific data
- ✅ Join events as an attendee
- ✅ RESTful API design

---

## 🏗️ Tech Stack

- **Backend**: Node.js, Express.js
- **Database**: MongoDB (with native MongoDB driver)
- **Authentication**: JWT
- **Security**: bcrypt for password hashing, CORS enabled

---

## Installation:

1. Clone the repository.
2. Install dependencies using `npm install`.
3. Rename `.env.example` to `.env`.
4. Run the server using `npm run dev`.

## Configuration:

- Environment Variables:
  - `PORT`: Port number the server listens on. Default: 3000
  - `MONGODB_URI`: URI for MongoDB database.
  - `JWT_SECRET`: Secret key for JWT token generation.
  - `EXPIRES_IN`: Token expiration time.

## Dependencies:

- `bcrypt`: Library for hashing passwords.
- `cors`: Express middleware for enabling CORS.
- `dotenv`: Loads environment variables from .env file.
- `express`: Web framework for Node.js.
- `jsonwebtoken`: Library for generating and verifying JWT tokens.
- `mongodb`: MongoDB driver for Node.js.
- `nodemon`: Utility for automatically restarting the server during development.
