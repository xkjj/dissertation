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

        if (user.is_active === 0) {
            return res.send("This account has been disabled");
        }

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
            SELECT user_id, firstname, surname, username, role, phone, postcode, is_active
            FROM users
            ORDER BY role, surname`;

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

app.post('/admin/update-role',
    requireLogin,
    requireRole('system_admin', 'charity_admin'),
    (req, res) => {

        const { user_id, role } = req.body;

        // Prevent changes to system admin
        const protectSQL = `
            SELECT role FROM users WHERE user_id = ?
        `;

        db.query(protectSQL, [user_id], (err, rows) => {
            if (err) {
                console.error(err);
                return res.send("Database error");
            }

            if (rows.length === 0) {
                return res.send("User not found");
            }

            if (rows[0].role === 'system_admin') {
                return res.send("System admin role cannot be changed");
            }

            const updateRoleSQL = `
                UPDATE users SET role = ? WHERE user_id = ?
            `;

            db.query(updateRoleSQL, [role, user_id], err => {
                if (err) {
                    console.error(err);
                    return res.send("Failed to update role");
                }
                res.redirect('/admin/dashboard');
            });
        });
    }
);


app.post('/admin/toggle-user',
    requireLogin,
    requireRole('sys_admin', 'charity_admin'),
    (req, res) => {

        const { user_id } = req.body;

        const protectSQL = `
            SELECT role FROM users WHERE user_id = ?`;

            db.query(protectSQL, [user_id], (err, rows) => {
                if (rows[0].role === 'sys_admin') {
                    return res.send("System admin cannot be disabled");
                }

                const toggleSQL = `UPDATE users
                                    SET is_active = IF(is_active = 1, 0, 1)
                                    WHERE user_id = ?`;

        db.query(toggleSQL, [user_id], err => {
            if (err) {
                console.error(err);
                return res.send("Failed to update user status");
            }
            res.redirect('/admin/dashboard');
        });
            });

    }
);

app.get('/items/new',
    requireLogin,
    (req, res) => {
        res.render('items/new');
    }
);

app.get('/items', (req, res) => {

    const sql = `
        SELECT clothing_items.*, users.username
        FROM clothing_items
        JOIN users ON clothing_items.user_id = users.user_id
        WHERE status = 'available'
        ORDER BY created_at DESC
    `;

    db.query(sql, (err, items) => {
        if (err) return res.send("Error loading items");
        res.render('items/index', { items });
    });
});


app.post('/items',
    requireLogin,
    (req, res) => {

        const { title, description, category, size, condition_desc } = req.body;

        const insertItemSQL = `
            INSERT INTO clothing_items
            (user_id, title, description, category, size, condition_desc)
            VALUES (?, ?, ?, ?, ?, ?)
        `;

        db.query(
            insertItemSQL,
            [
                req.session.user.user_id,
                title,
                description,
                category,
                size,
                condition_desc
            ],
            err => {
                if (err) {
                    console.error(err);
                    return res.send("Failed to create item");
                }
                res.redirect('/items/my');
            }
        );
    }
);

app.get('/items/my',
    requireLogin,
    (req, res) => {

        const sql = `
            SELECT *
            FROM clothing_items
            WHERE user_id = ?
        `;

        db.query(sql, [req.session.user.user_id], (err, items) => {
            if (err) return res.send("Error");
            res.render('items/my', { items });
        });
    }
);

app.get('/items/:id/edit',
    requireLogin,
    (req, res) => {

        const sql = `
            SELECT *
            FROM clothing_items
            WHERE item_id = ? AND user_id = ?
        `;

        db.query(sql, [req.params.id, req.session.user.user_id], (err, rows) => {
            if (rows.length === 0) return res.send("Not allowed");
            res.render('items/edit', { item: rows[0] });
        });
    }
);

app.post('/items/:id',
    requireLogin,
    (req, res) => {

        const { title, description, category, size, condition_desc } = req.body;

        const sql = `
            UPDATE clothing_items
            SET title = ?, description = ?, category = ?, size = ?, condition_desc = ?
            WHERE item_id = ? AND user_id = ?
        `;

        db.query(
            sql,
            [title, description, category, size, condition_desc, req.params.id, req.session.user.user_id],
            err => {
                if (err) return res.send("Update failed");
                res.redirect('/items/my');
            }
        );
    }
);

app.post('/items/:id/delete',
    requireLogin,
    (req, res) => {

        const sql = `
            DELETE FROM clothing_items
            WHERE item_id = ? AND user_id = ?
        `;

        db.query(sql, [req.params.id, req.session.user.user_id], err => {
            if (err) return res.send("Delete failed");
            res.redirect('/items/my');
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