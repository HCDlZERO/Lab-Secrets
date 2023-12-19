const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const saltRounds = 10; // Number of salt rounds for bcrypt
const encrypt = require("mongoose-encryption");
require("dotenv").config();

const app = express();
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

mongoose.connect("mongodb+srv://"+process.env.DB_USERNAME+":"+process.env.DB_PASSWORD+"@cluster0.r9t6yjm.mongodb.net/?retryWrites=true&w=majority");

// Define a secret key for encryption
const secretKey = "ThisIsASecretKey"; // Replace with your own secret key

const userSchema = new mongoose.Schema({
    email: String,
    password: String
});

// Use mongoose-encryption plugin to encrypt the 'password' field
userSchema.plugin(encrypt, { secret: secretKey, encryptedFields: ["password"] });

const User = new mongoose.model("User", userSchema);

app.get("/register", (req, res) => {
    res.render("register");
});

app.post("/register", async (req, res) => {
    try {
        const email = req.body.username;
        const password = req.body.password;

        // Hash the password before saving it to the database
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const newUser = new User({ email, password: hashedPassword });

        await newUser.save();
        res.redirect("/secrets");
    } catch (err) {
        console.error(err);
        res.send("Error occurred during registration.");
    }
});

app.get("/login", (req, res) => {
    res.render("login");
});

app.post("/login", async (req, res) => {
    try {
        const username = req.body.username;
        const password = req.body.password;

        const foundUser = await User.findOne({ email: username });

        if (foundUser) {
            // Compare the hashed password
            const isPasswordMatch = await bcrypt.compare(password, foundUser.password);

            if (isPasswordMatch) {
                res.redirect("/secrets");
            } else {
                // Debugging: Output the actual hashed password and entered password
                console.log("Actual Hashed Password:", foundUser.password);
                console.log("Entered Password:", password);
                
                res.send("Invalid password");
            }
        } else {
            res.send("Invalid username");
        }
    } catch (err) {
        console.error(err);
        res.send("Error occurred during login.");
    }
});


app.get("/secrets", (req, res) => {
    res.render("secrets");
});

app.get("/logout", (req, res) => {
    res.redirect("/");
});

app.get("/", (req, res) => {
    res.render("home");
});

app.listen(3000, () => {
    console.log("Server opened on port 3000");
});
