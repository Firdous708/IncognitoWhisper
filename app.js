//jshint esversion:6
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
require("dotenv").config();
const ejs = require("ejs");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

//setting up session
app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
  })
);

//intitializing passport
app.use(passport.initialize());
app.use(passport.session());

//connecting to db
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("Db connected Successfully"))
  .catch((err) => console.log(err));

//creating schema
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String, // Adding Google ID field
  secret: [String],
});

//setting up passport-local-mongoose
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

//setting up passport-local-mongoose
passport.use(User.createStrategy());
//using passport to serialize and deserialize user
passport.serializeUser(function (user, done) {
  done(null, user.id);
});
passport.deserializeUser(function (id, done) {
  //using findById without callback
  User.findById(id)
    .then((user) => {
      done(null, user);
    })
    .catch((err) => {
      console.log(err);
    });
});

//setting up google strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate(
        {
          googleId: profile.id,
        },
        function (err, user) {
          return cb(err, user);
        }
      );
    }
  )
);

app.get("/", (req, res) => {
  res.render("home");
});

//google auth route
//prettier-ignore
app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);
//prettier-ignore
app.get("/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
  }
);

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/secrets", (req, res) => {
  User.find({}, "secret")
    .then((users) => {
      res.render("secrets", { userWithSecret: users });
    })
    .catch((err) => {
      console.log(err);
    });
});

app.post("/register", (req, res) => {
  //prettier-ignore
  User.register({ username: req.body.username }, req.body.password, function (err, user) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      //prettier-ignore
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/login", (req, res) => {
  //prettier-ignore
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });
  //prettier-ignore
  req.login(user, function (err) {
    if (err) {
      console.log(err);
    } else {
      //prettier-ignore
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });
});

app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", (req, res) => {
  const submittedSecret = req.body.secret;
  User.findById(req.user.id)
    .then((user) => {
      user.secret = submittedSecret;
      user.save();
      res.redirect("/secrets");
    })
    .catch((err) => {
      console.log(err);
    });
});

app.get("/logout", (req, res) => {
  req.logout(() => {
    res.redirect("/");
  });
});

app.listen(3000, function () {
  console.log("Server is up and running on port 3000.");
});
