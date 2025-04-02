import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";
import axios from "axios";
import path from 'path';
import { fileURLToPath } from 'url';


// Fix __dirname in ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


const app = express();
const port = 3000;
const saltRounds = 10;
env.config();
let cachedTip = { tips_title: "Loading tip..." };
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
  ssl: { rejectUnauthorized: true },
});
db.connect();

app.get("/", (req, res) => {
  res.render("opening.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/intro", (req, res)=>{
  res.render("intro.ejs");
})

app.get("/dashboard", (req, res) => {
  if (req.isAuthenticated()) {
    var thatName =  req.user.name || profile.name.givenName + " " + profile.name.familyName ;
    res.render("dashboard.ejs", {theName : thatName});
  } else {
    res.redirect("/login");
  }
});

app.get('/loading', async (req, res) => {
  try {
    const response = await axios.get('https://tips-api-qkx8.onrender.com');  // Your tips API

    // If the response is valid, send the tip
    if (response.data && response.data.tips_title) {
      res.render("loading.ejs", { tips_title: response.data.tips_title });
      console.log(response.data.tips_title)
    } else {
      res.render("loading.ejs", { tips_title: 'No tips available at the moment.' });
    }
  } catch (error) {
    console.error('Error fetching tip:', error);
    res.render("loading.ejs", {tips_title: 'Error fetching tip' }); // If there's an error, send an error message
  }
});

app.get("/task", (req, res) => {

  // write llm fetching code


  if (req.isAuthenticated()) {
    res.render("task.ejs");
    } else {
      res.redirect("/login");
      }
});
app.get("/todo", (req, res) =>{
  if (req.isAuthenticated()) {
    res.render("todo.ejs");
    } else {
      res.redirect("/login");
      }
})

// app.get('/loading', (req, res) => {
//   res.render('loading', { tip: cachedTip });
// });

app.get("/news", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("news.ejs");
    } else {
      res.redirect("/login");
      }
});

app.get("/intro", (req, res) =>{
  res.render("intro.ejs");
});

// app.get("/loading", async (req, res) => {
//   try {
//     const response = await axios.get("https://tips-api-qkx8.onrender.com"); 
//     const tips = response.data;

//     res.render("loading.ejs", { tip: tips });
//   } catch (error) {
//     console.error("Error fetching tips:", error);
//     res.render("loading", { tips: [] }); 
//   }
// });

app.get("/input", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("input.ejs");
    } else {
      res.redirect("/login");
      }
});

app.get("/input", (req, res) => {
  res.render("input.ejs");
})

app.post('/input', async (req, res) => {
  try {
    console.log("Received form data:", req.body);
    
    // Retrieve user id from req.user if using authentication, otherwise fallback to req.body.user_id
    const userId = req.user ? req.user.id : req.body.user_id;
    
    const {
      b_name,
      loc,
      type_p_s,
      description,
      monthly_revenue,
      numOfEmp,
      challenges,
      govtschemeavail,
      b_type,
    } = req.body;

    const queryText = `
      INSERT INTO input 
        (b_name, loc, type_p_s, description, monthly_revenue, numofemp, challenges, govtschemeavail, b_type, user_id)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      RETURNING *
    `;
    const values = [
      b_name,
      loc,
      type_p_s,
      description,
      monthly_revenue,
      numOfEmp, // Corrected variable name
      challenges,
      govtschemeavail,
      b_type,
      userId
    ];

    const result = await pool.query(queryText, values);
    console.log("Insert result:", result.rows[0]);
    res.json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error('Error inserting data:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});


app.get("/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get("/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/input",
    failureRedirect: "/login",
  })
);

app.post("/login",
  passport.authenticate("local", {
    successRedirect: "/dashboard",
    failureRedirect: "/register",
  })
);

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;
  const name = req.body.name;

  thatUser = name;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      req.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *",
            [name, email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/input");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.get("/todo", (req, res) =>{
  res.render("todo", {title: "Todo List", user: req.user});
})

router.get('/task', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/login');
  }

  try {
    // Get the authenticated user's id
    const userId = req.user.id;

    // Retrieve the most recent input for the user (modify query as needed)
    const inputQuery = `
      SELECT * 
      FROM input 
      WHERE user_id = $1 
      ORDER BY data_id DESC 
      LIMIT 1
    `;
    const inputResult = await pool.query(inputQuery, [userId]);

    if (inputResult.rows.length === 0) {
      // No input data found; handle this accordingly
      return res.status(404).send('No input data found for the user.');
    }

    const inputData = inputResult.rows[0];

    // Call the external API with the input data.
    // Replace 'https://your-api-url.com/api/llm' with your actual API endpoint.
    const apiResponse = await axios.post('https://generate-plan.onrender.com', {
      b_name: inputData.b_name,
      loc: inputData.loc,
      type_p_s: inputData.type_p_s,
      description: inputData.description,
      monthly_revenue: inputData.monthly_revenue,
      numofemp: inputData.numofemp,
      challenges: inputData.challenges,
      govtschemeavail: inputData.govtschemeavail,
      b_type: inputData.b_type
    });

    // Destructure the returned data
    const { monthly_task, weekly_task, supportive_task } = apiResponse.data;

    // Insert the API response into the todo_llm table
    const insertQuery = `
      INSERT INTO todo_llm (user_id, input_id, monthly_task, weekly_task, supportive_hints)
      VALUES ($1, $2, $3, $4, $5)
    `;
    await db.query(insertQuery, [
      userId,
      inputData.data_id, // assuming your primary key in the input table is data_id
      monthly_task,
      weekly_task,
      supportive_task
    ]);

        // Render the task page with tasks data
        res.render('task.ejs', {
          monthly_task: monthly_task,
          weekly_task: weekly_task,
          supportive_task: supportive_task
        });
      } catch (err) {
        console.error('Error in /task route:', err);
        res.status(500).send('Server Error');
      }
    });
    
    export default router;
passport.use("local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1 ", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      console.log(err);
    }
  })
);

passport.use("google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "https://hackindia-spark-4-2025-geeky-goblins.onrender.com/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        console.log(profile);
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
          profile.email,
        ]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (name, email, password) VALUES ($1, $2, $3)",
            [profile.name.givenName + " " + profile.name.familyName ,profile.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);
passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
