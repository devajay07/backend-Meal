// requiring modules
const express = require("express");
const bodyParser = require("body-parser");
const dotenv = require("dotenv");
const mongoose = require("mongoose");
const authRouter = require("./routes/userRoute");

dotenv.config({ path: "./.env" }); // setting up path for config file

const app = express(); // instance of express app

app.use(bodyParser.json());

// establishing database connection
const dbUrl = process.env.DATABASE_URL.replace(
  "<password>",
  process.env.DATABASE_PASSWORD
);
mongoose.connect(dbUrl).then(console.log("connected to database❤️"));
mongoose.set("strictQuery", true);

app.get("/", (req, res) => {
  res.send("<h1>Hello</h1>");
});

app.use("/api/v1/users", authRouter);

// starting the server
app.listen(process.env.PORT || 3000, () => {
  console.log("server is listening at port 3000");
});
