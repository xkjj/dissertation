const express = require('express');
const app = express();
const path = require('path');
const mysql = require('mysql2');
const sessions = require('express-session');
const cookieParser = require('cookie-parser');
const hour = 1000 * 60 * 60;
const bcrypt = require('bcrypt');
const SALT_ROUNDS = 10;

//middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

app.use(express.urlencoded({ extended: true }));
app.use(sessions({
    secret: "thisismysecretkey599",
    saveUninitialized: true,
    cookie: { maxAge: hour },
    resave: false
}));

app.use(cookieParser());

const db = mysql.createConnection({

    host: "localhost",
    user: "root",
    database: "dissertation",
    password: "",
    port: "3306",
    multipleStatements: true,

});

db.connect((err) => {
    if (err) throw err;
});

function requireLogin(req, res, next) {
    if (!req.session.user) {
        return res.redirect('/');
    }
    next();
}

function requireRole(...allowedRoles) {
    return (req, res, next) => {
        if (!req.session.user) {
            return res.redirect('/');
        }

        if (!allowedRoles.includes(req.session.user.role)) {
            return res.status(403).send("Access denied");
        }

        next();
    };
}

//routes
app.get("/", (req, res) => {

    res.render('login');
});

app.post('/', (req, res) => {
    const { username_field, password_field } = req.body;

    const getUserSQL = "SELECT * FROM users WHERE username = ?";

    db.query(getUserSQL, [username_field], (err, results) => {
        if (err) return res.send("Database error");

        if (results.length === 0) {
            return res.send("Invalid username or password");
        }

        const user = results[0];

        bcrypt.compare(password_field, user.password, (err, match) => {
            if (err) return res.send("Authentication error");

            if (!match) {
                return res.send("Invalid username or password");
            }

            req.session.user = {
                user_id: user.user_id,
                username: user.username,
                role: user.role
            };

            if (user.role === 'sys_admin' || user.role === 'charity_admin') {
             return res.redirect('/admin/dashboard');
                }           

            res.redirect('/homepage');
        });
    });
});


app.get('/createaccount', (req, res) => {
    res.render('createaccount');
});

app.post('/createaccount', (req, res) => {
    const {
        firstname_field,
        surname_field,
        username_field,
        password_field,
        phone_field,
        address_field,
        postcode_field
    } = req.body;

    // Basic presence check
    if (
        !firstname_field || !surname_field || !username_field ||
        !password_field || !phone_field || !address_field || !postcode_field
    ) {
        return res.send("All fields are required");
    }

    // Length checks
    if (username_field.length < 4 || username_field.length > 20) {
        return res.send("Username must be 4–20 characters");
    }

    if (password_field.length < 8) {
        return res.send("Password must be at least 8 characters");
    }

    // Regex checks (server-side)
    const postcodeRegex = /^[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}$/i;
    if (!postcodeRegex.test(postcode_field)) {
        return res.send("Invalid postcode format");
    }

    // Check for duplicate username
    const checkUserSQL = "SELECT * FROM users WHERE username = ?";
    db.query(checkUserSQL, [username_field], (err, results) => {
        if (err) return res.send("Database error");

        if (results.length > 0) {
            return res.send("Username already exists");
        }

    const plainPassword = password_field;

bcrypt.hash(plainPassword, SALT_ROUNDS, (err, hashedPassword) => {
    if (err) return res.send("Error securing password");

    const insertUsersSQL = `
        INSERT INTO users
        (firstname, surname, username, password, role, phone, address, postcode)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `;

    db.query(
        insertUsersSQL,
        [
            firstname_field,
            surname_field,
            username_field,
            hashedPassword,  
            'user',
            phone_field,
            address_field,
            postcode_field
        ],
        err => {
            if (err) return res.send("Insert failed");
            res.redirect('/usercreated');
                }
            );
        });
    });
});

app.get("/homepage", requireLogin, (req, res) => {
    res.render("homepage", { user: req.session.user });
});

app.get("/usercreated", (req, res) => {
        res.render('usercreated');
});


app.get('/admin/dashboard',
    requireLogin,
    requireRole('sys_admin', 'charity_admin'),
    (req, res) => {

        const getUsersSQL = `
            SELECT user_id, firstname, surname, username, role, phone, postcode
            FROM users
            ORDER BY role, surname
        `;

        db.query(getUsersSQL, (err, users) => {
            if (err) {
                console.error(err);
                return res.send("Database error");
            }

            res.render('admin_dashboard', {
                admin: req.session.user,
                users
            });
        });
    }
);


app.get('/user/profile',
    requireLogin,
    requireRole('user'),
    (req, res) => {
        res.render('profile');
    }
);

app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/');
    });
});

//server
app.listen(process.env.PORT || 3000);
console.log('Server is listening//localhost:3000/');