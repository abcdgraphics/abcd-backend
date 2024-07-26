import express from "express";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import config from "./database/config.js";
import dotenv from "dotenv";
import pool from "./database/db.js";
dotenv.config();

const app = express();
const allowedOrigins = ["http://localhost:3000"];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg =
        "The CORS policy for this site does not allow access from the specified Origin.";
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
};

app.use(cors(corsOptions));
app.use(express.json());

function validateEmail(email) {
  const re = /\S+@\S+\.\S+/;
  return re.test(email);
}

function validatePassword(password) {
  return password.length >= 6 && typeof password === "string";
}

function validateStrings(name) {
  return typeof name === "string" && name.trim().length > 0;
}

app.post("/register", async (req, res) => {
  const { firstname, lastname, companyname, email, password } = req.body;

  if (!validateEmail(email)) {
    return res.send({ success: false, message: "Invalid email format" });
  }

  if (!validatePassword(password)) {
    return res.send({
      success: false,
      message: "Password must be at least 6 characters long",
    });
  }

  if (!validateStrings(firstname)) {
    return res.send({
      success: false,
      message: "Please fill this field",
    });
  }

  if (!validateStrings(lastname)) {
    return res.send({
      success: false,
      message: "Please fill this field",
    });
  }

  if (!validateStrings(companyname)) {
    return res.send({
      success: false,
      message: "Please fill this field",
    });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const connection = await pool.getConnection();
    try {
      const [results] = await connection.query(
        "SELECT * FROM registrations WHERE email = ?",
        email
      );

      if (results.length > 0) {
        return res.json({
          success: true,
          message: "Account already registered",
        });
      }

      const newRegistration = {
        firstname: firstname,
        lastname: lastname,
        email: email,
        companyname: companyname,
        password: hashedPassword,
      };

      const [insertResult] = await connection.query(
        "INSERT INTO registrations SET ?",
        newRegistration
      );

      console.log("Inserted new registration. ID:", insertResult.insertId);
      return res.json({
        success: true,
        message: "Registration successfull",
      });
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error("Error during registration:", error);
    return res.json({ success: false, message: "Internal Server Error" });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!validateEmail(email)) {
    return res.send({ success: false, message: "Invalid Email or Password" });
  }

  if (!validatePassword(password)) {
    return res.send({
      success: false,
      message: "Invalid Email or Password",
    });
  }

  try {
    const connection = await pool.getConnection();
    try {
      const [results] = await connection.query(
        "SELECT * FROM registrations WHERE email = ?",
        email
      );

      if (results.length === 0) {
        return res.json({ success: false, message: "User not found" });
      }

      const user = results[0];

      const isMatch = await bcrypt.compare(password, user.password);

      if (!isMatch) {
        return res.json({ success: false, message: "Incorrect password" });
      }

      const token = jwt.sign(
        { id: user.id, email: user.email },
        config.jwtSecret,
        { expiresIn: "1h" }
      );

      res.json({
        success: true,
        message: "Logged in successfully",
        token: token,
      });
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error("Error during login:", error);
    return res.json({ success: false, message: "Internal Server Error" });
  }
});

app.post("/google/login", async (req, res) => {
  const { email, family_name, given_name } = req.body;

  if (!validateEmail(email)) {
    return res.send({ success: false, message: "Invalid email format" });
  }

  if (!validateStrings(family_name)) {
    return res.send({
      success: false,
      message: "Please fill this field",
    });
  }

  if (!validateStrings(given_name)) {
    return res.send({
      success: false,
      message: "Please fill this field",
    });
  }

  const userDetails = {
    email: email,
    firstname: family_name,
    lastname: given_name,
  };

  try {
    const connection = await pool.getConnection();
    try {
      const [results] = await connection.query(
        "SELECT * FROM registrations WHERE email = ?",
        email
      );
      if (results.length === 0) {
        const [insertResult] = await connection.query(
          "INSERT INTO registrations SET ?",
          userDetails
        );

        const token = jwt.sign(
          { id: insertResult.insertId, email: email },
          config.jwtSecret,
          { expiresIn: "1h" }
        );

        return res.json({
          success: true,
          message: "Registration successfull",
          token: token,
        });
      } else {
        const user = results[0];

        const token = jwt.sign(
          { id: user.id, email: user.email },
          config.jwtSecret,
          { expiresIn: "1h" }
        );

        return res.json({
          success: true,
          message: "Already Registered",
          token: token,
        });
      }
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/getAccessToken", async (req, res) => {
  let profileData;
  let emailData;
  try {
    const code = req.query.code;
    const params =
      "client_id=" +
      process.env.GITHUB_CLIENT_ID +
      "&client_secret=" +
      process.env.GITHUB_CLIENT_SECRET +
      "&code=" +
      code;

    await fetch("https://github.com/login/oauth/access_token?" + params, {
      method: "POST",
      headers: {
        Accept: "application/json",
      },
    })
      .then((response) => {
        return response.json();
      })
      .then(async (data) => {
        if (data.access_token) {
          await fetch("https://api.github.com/user/emails", {
            method: "GET",
            headers: {
              Authorization: `Bearer ${data.access_token}`,
              Accept: "application/vnd.github.v3+json",
            },
          })
            .then((response) => {
              return response.json();
            })
            .then((data) => {
              emailData = data;
            });

          await fetch("https://api.github.com/user", {
            method: "GET",
            headers: {
              Authorization: `Bearer ${data.access_token}`,
              Accept: "application/vnd.github.v3+json",
            },
          })
            .then((response) => {
              return response.json();
            })
            .then((data) => {
              profileData = data;
            });

          res.json({ profileData, emailData });
        }
      });
  } catch (e) {
    console.log(e);
    return null;
  }
});

app.listen(3002);
