require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const { MongoClient } = require("mongodb");
const { ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");
const e = require("express");

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection URL
const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

async function run() {
  try {
    // Connect to MongoDB
    await client.connect();
    console.log("Connected to MongoDB");

    const db = client.db("EventManagement");
    const user = db.collection("users");
    const event = db.collection("events");

    // User Registration
    app.post("/api/v1/register", async (req, res) => {
      const { name, photoUrl, email, password } = req.body;
      // Check if email already exists
      const existingUser = await user.findOne({ email });
      if (existingUser) {
        return res.status(400).json({
          success: false,
          message: "User already exist!!!",
        });
      }

      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Generate JWT token
      const token = jwt.sign(
        { email: email, role: "user" },
        process.env.JWT_SECRET,
        {
          expiresIn: process.env.EXPIRES_IN,
        }
      );
      // Insert user into the database
      await user.insertOne({
        name,
        photoUrl,
        email,
        password: hashedPassword,
        role: "user",
      });

      res.status(201).json({
        success: true,
        accessToken: token,
        message: "User registered successfully!",
      });
    });

    // User Login
    app.post("/api/v1/login", async (req, res) => {
      try {
        const { email, password } = req.body;
        // Find user by email
        const checkuser = await user.findOne({ email });
        if (!checkuser) {
          return res.status(401).json({ message: "Invalid email or password" });
        }

        // Compare hashed password
        const isPasswordValid = await bcrypt.compare(
          password,
          checkuser.password
        );
        if (!isPasswordValid) {
          return res.status(401).json({ message: "Invalid email or password" });
        }

        // Generate JWT token
        const token = jwt.sign(
          { email: checkuser.email, role: checkuser.role },
          process.env.JWT_SECRET,
          {
            expiresIn: process.env.EXPIRES_IN,
          }
        );

        res.json({
          success: true,
          message: "User successfully logged in!",
          accessToken: token,
        });
      } catch (error) {
        console.error("Login error:", error);
        return res.status(500).json({
          success: false,
          message: "Internal server error",
        });
      }
    });

    app.post("/api/v1/event", async (req, res) => {
      const token = req.headers.authorization?.split(" ")[1];
      if (!token) {
        return res
          .status(401)
          .json({ success: false, message: "Authorization token required" });
      }

      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const userEmail = decoded.email;

      const IsUserHave = await user.findOne({ email: userEmail });
      if (!IsUserHave) {
        return res
          .status(404)
          .json({ success: false, message: "User not found" });
      }

      const eventData = {
        ...req.body,
        creatorEmail: userEmail,
        createdAt: new Date(),
      };

      const result = await event.insertOne(eventData);
      res.status(201).json({
        success: true,
        message: "Event created successfully!",
        data: result,
      });
    });

    app.get("/api/v1/events", async (req, res) => {
      try {
        const limit = Math.min(parseInt(req.query.limit) || 12, 100);
        const page = Math.max(parseInt(req.query.page) || 1, 1);
        const skip = (page - 1) * limit;

        const token = req.headers.authorization?.split(" ")[1];
        if (!token) {
          return res.status(401).json({
            success: false,
            message: "Authorization token required",
          });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const userExists = await user.findOne({ email: decoded.email });
        if (!userExists) {
          return res.status(403).json({
            success: false,
            message: "User not authorized",
          });
        }

        let filter = {};
        if (req.query.filter) {
          const today = new Date();
          today.setHours(0, 0, 0, 0);

          const tomorrow = new Date(today);
          tomorrow.setDate(tomorrow.getDate() + 1);

          const nextWeek = new Date(today);
          nextWeek.setDate(nextWeek.getDate() + 7);

          const nextMonth = new Date(today);
          nextMonth.setMonth(nextMonth.getMonth() + 1);

          const lastWeek = new Date(today);
          lastWeek.setDate(lastWeek.getDate() - 7);

          const lastMonth = new Date(today);
          lastMonth.setMonth(lastMonth.getMonth() - 1);

          switch (req.query.filter.toLowerCase()) {
            case "today":
              filter.date = {
                $gte: today.toISOString().split("T")[0],
                $lt: tomorrow.toISOString().split("T")[0],
              };
              break;

            case "thisweek":
              filter.date = {
                $gte: today.toISOString().split("T")[0],
                $lt: nextWeek.toISOString().split("T")[0],
              };
              break;

            case "thismonth":
              filter.date = {
                $gte: today.toISOString().split("T")[0],
                $lt: nextMonth.toISOString().split("T")[0],
              };

            case "lastweek":
              filter.date = {
                $gte: lastWeek.toISOString().split("T")[0],
                $lt: today.toISOString().split("T")[0],
              };
              break;

            case "lastmonth":
              filter.date = {
                $gte: lastMonth.toISOString().split("T")[0],
                $lt: today.toISOString().split("T")[0],
              };
              break;

            case "all":
            default:
              break;
          }
        }

        if (req.query.search) {
          filter.$or = [
            { title: { $regex: req.query.search, $options: "i" } },
            { description: { $regex: req.query.search, $options: "i" } },
          ];
        }

        if (req.query.date) {
          if (!/^\d{4}-\d{2}-\d{2}$/.test(req.query.date)) {
            return res.status(400).json({
              success: false,
              message: "Invalid date format. Use YYYY-MM-DD",
            });
          }
          filter.date = req.query.date;
        }

        if (req.query.category && req.query.category !== "all") {
          filter.category = req.query.category;
        }

        const today = new Date();
        today.setHours(0, 0, 0, 0);

        const [events, totalEvents] = await Promise.all([
          event
            .aggregate([
              {
                $match: filter,
              },
              {
                $addFields: {
                  eventDate: {
                    $cond: {
                      if: { $eq: [{ $type: "$date" }, "string"] },
                      then: { $dateFromString: { dateString: "$date" } },
                      else: "$date",
                    },
                  },
                  isToday: {
                    $eq: [
                      {
                        $cond: {
                          if: { $eq: [{ $type: "$date" }, "string"] },
                          then: { $dateFromString: { dateString: "$date" } },
                          else: "$date",
                        },
                      },
                      today,
                    ],
                  },
                  // Check if the event is in the future
                  isFuture: {
                    $gt: [
                      {
                        $cond: {
                          if: { $eq: [{ $type: "$date" }, "string"] },
                          then: { $dateFromString: { dateString: "$date" } },
                          else: "$date",
                        },
                      },
                      today,
                    ],
                  },
                },
              },
              {
                $sort: {
                  isToday: -1, // Today's events first (1 = true comes first)
                  isFuture: -1, // Future events before past events
                  date: 1, // Oldest first for past events (1 = ascending)
                },
              },
              { $skip: skip },
              { $limit: limit },
            ])
            .toArray(),

          event.countDocuments(filter),
        ]);

        // Format response
        res.json({
          success: true,
          data: events,
          pagination: {
            totalEvents,
            totalPages: Math.ceil(totalEvents / limit),
            currentPage: page,
            limit,
          },
        });
      } catch (error) {
        console.error("Error:", error);
        const status = error.name === "JsonWebTokenError" ? 401 : 500;
        res.status(status).json({
          success: false,
          message: status === 401 ? "Invalid token" : "Internal server error",
          error:
            process.env.NODE_ENV === "development" ? error.message : undefined,
        });
      }
    });

    app.get("/api/v1/events/home", async (req, res) => {
      try {
        const limit = 6;
        let filter = {};

        if (req.query.filter) {
          const today = new Date();
          today.setHours(0, 0, 0, 0);

          const tomorrow = new Date(today);
          tomorrow.setDate(tomorrow.getDate() + 1);

          const nextWeek = new Date(today);
          nextWeek.setDate(nextWeek.getDate() + 7);

          const nextMonth = new Date(today);
          nextMonth.setMonth(nextMonth.getMonth() + 1);

          switch (req.query.filter.toLowerCase()) {
            case "today":
              filter.date = {
                $gte: today.toISOString().split("T")[0],
                $lt: tomorrow.toISOString().split("T")[0],
              };
              break;

            case "thisweek":
              filter.date = {
                $gte: today.toISOString().split("T")[0],
                $lt: nextWeek.toISOString().split("T")[0],
              };
              break;

            case "thismonth":
              filter.date = {
                $gte: today.toISOString().split("T")[0],
                $lt: nextMonth.toISOString().split("T")[0],
              };
              break;

            case "all":
            default:
              break;
          }
        }

        if (req.query.search) {
          filter.$or = [
            { title: { $regex: req.query.search, $options: "i" } },
            { description: { $regex: req.query.search, $options: "i" } },
          ];
        }

        if (req.query.date) {
          if (!/^\d{4}-\d{2}-\d{2}$/.test(req.query.date)) {
            return res.status(400).json({
              success: false,
              message: "Invalid date format. Use YYYY-MM-DD",
            });
          }
          filter.date = req.query.date;
        }

        if (req.query.category && req.query.category !== "all") {
          filter.category = req.query.category;
        }

        const today = new Date();
        today.setHours(0, 0, 0, 0);

        const events = await event
          .aggregate([
            {
              $match: filter,
            },
            {
              $addFields: {
                eventDate: {
                  $cond: {
                    if: { $eq: [{ $type: "$date" }, "string"] },
                    then: { $dateFromString: { dateString: "$date" } },
                    else: "$date",
                  },
                },
                isToday: {
                  $eq: [
                    {
                      $cond: {
                        if: { $eq: [{ $type: "$date" }, "string"] },
                        then: { $dateFromString: { dateString: "$date" } },
                        else: "$date",
                      },
                    },
                    today,
                  ],
                },
                isFuture: {
                  $gt: [
                    {
                      $cond: {
                        if: { $eq: [{ $type: "$date" }, "string"] },
                        then: { $dateFromString: { dateString: "$date" } },
                        else: "$date",
                      },
                    },
                    today,
                  ],
                },
              },
            },
            {
              $sort: {
                isToday: -1,
                isFuture: -1,
                date: 1,
                createdAt: -1,
              },
            },
            { $limit: limit },
          ])
          .toArray();

        if (events.length === 0) {
          return res.status(404).json({
            success: false,
            message: "No events found matching your criteria",
          });
        }

        res.json({
          success: true,
          data: events,
        });
      } catch (error) {
        console.error("Error:", error);
        res.status(500).json({
          success: false,
          message: "Internal server error",
          error:
            process.env.NODE_ENV === "development" ? error.message : undefined,
        });
      }
    });

    app.get("/api/v1/my-events", async (req, res) => {
      const token = req.headers.authorization?.split(" ")[1];
      if (!token) {
        return res
          .status(401)
          .json({ success: false, message: "Authorization token required" });
      }
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const userEmail = decoded.email;

      const IsUserHave = await user.findOne({ email: userEmail });
      if (!IsUserHave) {
        return res
          .status(404)
          .json({ success: false, message: "You are not authorized" });
      }

      const myEvents = await event.find({ creatorEmail: userEmail }).toArray();
      if (myEvents.length === 0) {
        return res
          .status(404)
          .json({ success: false, message: "No events found for this user" });
      }
      res.json({ success: true, data: myEvents });
    });

    app.get("/api/v1/event/:id", async (req, res) => {
      const { id } = req.params;
      const token = req.headers.authorization?.split(" ")[1];
      if (!token) {
        return res
          .status(401)
          .json({ success: false, message: "Authorization token required" });
      }
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const userEmail = decoded.email;
      const IsUserHave = await user.findOne({ email: userEmail });
      if (!IsUserHave) {
        return res
          .status(404)
          .json({ success: false, message: "You are not authorized" });
      }
      const eventData = await event.findOne({
        _id: new ObjectId(id),
      });
      if (!eventData) {
        return res
          .status(404)
          .json({ success: false, message: "Event not found" });
      }
      res.json({ success: true, data: eventData });
    });

    app.put("/api/v1/event/:id", async (req, res) => {
      const { id } = req.params;
      const token = req.headers.authorization?.split(" ")[1];
      if (!token) {
        return res
          .status(401)
          .json({ success: false, message: "Authorization token required" });
      }
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const userEmail = decoded.email;
      const IsUserHave = await user.findOne({ email: userEmail });
      if (!IsUserHave) {
        return res
          .status(404)
          .json({ success: false, message: "You are not authorized" });
      }
      const eventData = await event.findOne({
        _id: new ObjectId(id),
      });
      if (!eventData) {
        return res
          .status(404)
          .json({ success: false, message: "Event not found" });
      }
      // Check if the user is the creator of the event
      if (eventData.creatorEmail !== userEmail) {
        return res.status(403).json({
          success: false,
          message: "You are not authorized to update this event",
        });
      }
      // Update the event
      const updatedEvent = {
        ...req.body,
        updatedAt: new Date(),
      };
      const result = await event.updateOne(
        { _id: new ObjectId(id) },
        { $set: updatedEvent }
      );
      if (result.modifiedCount === 0) {
        return res.status(404).json({
          success: false,
          message: "Event not found or no changes made",
        });
      }
      res.json({
        success: true,
        message: "Event updated successfully!",
        data: updatedEvent,
      });
    });

    app.delete("/api/v1/event/:id", async (req, res) => {
      const { id } = req.params;
      const token = req.headers.authorization?.split(" ")[1];
      if (!token) {
        return res
          .status(401)
          .json({ success: false, message: "Authorization token required" });
      }
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const userEmail = decoded.email;
      const IsUserHave = await user.findOne({ email: userEmail });
      if (!IsUserHave) {
        return res
          .status(404)
          .json({ success: false, message: "You are not authorized" });
      }
      const eventData = await event.findOne({
        _id: new ObjectId(id),
      });
      if (!eventData) {
        return res
          .status(404)
          .json({ success: false, message: "Event not found" });
      }
      // Check if the user is the creator of the event
      if (eventData.creatorEmail !== userEmail) {
        return res.status(403).json({
          success: false,
          message: "You are not authorized to delete this event",
        });
      }
      // Delete the event
      const result = await event.deleteOne({
        _id: new ObjectId(id),
      });
      if (result.deletedCount === 0) {
        return res
          .status(404)
          .json({ success: false, message: "Event not found" });
      }
      res.json({
        success: true,
        message: "Event deleted successfully!",
      });
    });

    app.put("/api/v1/event/:id/join", async (req, res) => {
      const { id } = req.params;
      const token = req.headers.authorization?.split(" ")[1];
      if (!token) {
        return res
          .status(401)
          .json({ success: false, message: "Authorization token required" });
      }
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const userEmail = decoded.email;
      const IsUserHave = await user.findOne({ email: userEmail });
      if (!IsUserHave) {
        return res
          .status(404)
          .json({ success: false, message: "You are not authorized" });
      }
      const eventData = await event.findOne({
        _id: new ObjectId(id),
      });
      if (!eventData) {
        return res
          .status(404)
          .json({ success: false, message: "Event not found" });
      }
      // Check if the user is already an attendee
      if (eventData.attendees && eventData.attendees.includes(userEmail)) {
        return res.status(400).json({
          success: false,
          message: "You are already an attendee of this event",
        });
      }
      // Update the event to add the user as an attendee
      const updatedEvent = {
        $inc: { attendeeCount: 1 },
        $addToSet: { attendees: userEmail },
      };
      const result = await event.updateOne(
        { _id: new ObjectId(id) },
        updatedEvent
      );
      if (result.modifiedCount === 0) {
        return res.status(404).json({
          success: false,
          message: "Event not found or no changes made",
        });
      }
      res.json({
        success: true,
        message: "You have successfully joined the event!",
        data: {
          attendeeCount: eventData.attendeeCount + 1,
          attendees: [...(eventData.attendees || []), userEmail],
        },
      });
    });

    app.get("/api/v1/me", async (req, res) => {
      const token = req.headers.authorization?.split(" ")[1];
      if (!token) {
        return res
          .status(401)
          .json({ success: false, message: "Authorization token required" });
      }

      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const userEmail = decoded.email;

        // Find the user by email
        const userData = await user.findOne({ email: userEmail });
        if (!userData) {
          return res.status(404).json({
            success: false,
            message: "User not found",
          });
        }

        res.json({
          success: true,
          data: userData,
        });
      } catch (error) {
        console.error("Error fetching user data:", error);
        res.status(500).json({
          success: false,
          message: "Internal server error",
        });
      }
    });

    app.put("/api/v1/me", async (req, res) => {
      const token = req.headers.authorization?.split(" ")[1];
      if (!token) {
        return res
          .status(401)
          .json({ success: false, message: "Authorization token required" });
      }

      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const userEmail = decoded.email;

        // Find the user by email
        const userData = await user.findOne({ email: userEmail });
        if (!userData) {
          return res.status(404).json({
            success: false,
            message: "User not found",
          });
        }

        // Update user data
        const updatedData = { ...req.body };
        await user.updateOne({ email: userEmail }, { $set: updatedData });

        res.json({
          success: true,
          message: "User data updated successfully",
          data: updatedData,
        });
      } catch (error) {
        console.error("Error updating user data:", error);
        res.status(500).json({
          success: false,
          message: "Internal server error",
        });
      }
    });

    app.listen(port, () => {
      console.log(`Server is running on http://localhost:${port}`);
    });
  } finally {
  }
}

run().catch(console.dir);

// Test route
app.get("/", (req, res) => {
  const serverStatus = {
    message: "Server is running smoothly",
    timestamp: new Date(),
  };
  res.json(serverStatus);
});
