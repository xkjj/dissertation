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

app.use((req, res, next) => {
    res.locals.user = req.session.user || null;
    next();
});


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

//routes - render login page on startup
app.get("/", (req, res) => {

    res.render('login');
});

//
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

        //match hashed password to password entered by user
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

            //redirect admin roles to dashboard
            if (user.role === 'sys_admin' || user.role === 'charity_admin') {
             return res.redirect('/admin/dashboard');
                }           
            res.redirect('/homepage');
        });
    });
});

//Account creation page
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

    //Basic presence check
    if (
        !firstname_field || !surname_field || !username_field ||
        !password_field || !phone_field || !address_field || !postcode_field
    ) {
        return res.send("All fields are required");
    }

    //Length checks
    if (username_field.length < 4 || username_field.length > 20) {
        return res.send("Username must be 4–20 characters");
    }

    if (password_field.length < 8) {
        return res.send("Password must be at least 8 characters");
    }

    //Regex checks (server-side)
    const postcodeRegex = /^[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}$/i;
    if (!postcodeRegex.test(postcode_field)) {
        return res.send("Invalid postcode format");
    }

    //Check for duplicate username
    const checkUserSQL = "SELECT * FROM users WHERE username = ?";
    db.query(checkUserSQL, [username_field], (err, results) => {
        if (err) return res.send("Database error");

        if (results.length > 0) {
            return res.send("Username already exists");
        }

    //Password hashing
    const plainPassword = password_field;

    bcrypt.hash(plainPassword, SALT_ROUNDS, (err, hashedPassword) => {
    if (err) return res.send("Error securing password");

    const insertUsersSQL = `
        INSERT INTO users
        (firstname, surname, username, password, role, phone, address, postcode)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `;

    //insert user into DB
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

//render homepage if user is logged in
app.get("/homepage", requireLogin, (req, res) => {
    res.render("homepage", { user: req.session.user });
});

//page for successful account creation
app.get("/usercreated", (req, res) => {
        res.render('usercreated');
});

//Admin dashboard
app.get('/admin/dashboard',
    requireLogin,
    requireRole('sys_admin', 'charity_admin'), //required roles to gain access
    (req, res) => {

        //query to list all users with accounts
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

//update user role
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

            //update role for selected user in dashboard
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

//disable accounts in dashboard
app.post('/admin/toggle-user',
    requireLogin,
    requireRole('sys_admin', 'charity_admin'),
    (req, res) => {

        const { user_id } = req.body;

        //prevent admin accounts from being disabled
        const protectSQL = `
            SELECT role FROM users WHERE user_id = ?`;

            db.query(protectSQL, [user_id], (err, rows) => {
                if (rows[0].role === 'sys_admin') {
                    return res.send("System admin cannot be disabled");
                }

                //update users to active/inactive accounts
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

//List all available items uploaded by other users
app.get('/items', (req, res) => {

    const userId = req.session.user ? req.session.user.user_id : null;

    const sql = `
        SELECT 
            clothing_items.item_id,
            clothing_items.title,
            clothing_items.description,
            clothing_items.category,
            clothing_items.size,
            clothing_items.condition_desc,
            clothing_items.status,
            clothing_items.charity_id,

            charity_centres.charity_name AS charity_name,
            users.username,

            (
                SELECT COUNT(*) 
                FROM item_requests 
                WHERE item_requests.item_id = clothing_items.item_id
                AND item_requests.requester_id = ?
            ) AS has_requested

        FROM clothing_items
        JOIN users ON clothing_items.user_id = users.user_id
        LEFT JOIN charity_centres ON clothing_items.charity_id = charity_centres.charity_id
        ORDER BY clothing_items.created_at DESC
    `;

    db.query(sql, [userId], (err, items) => {
        if (err) {
            console.error(err);
            return res.send("Error loading items");
        }

        res.render('items/index', { items });
    });
});



//item creation page
app.get('/items/new',
    requireLogin,
    (req, res) => {

        const sql = `
            SELECT charity_id, charity_name
            FROM charity_centres
            WHERE is_active = 1
        `;

        db.query(sql, (err, charities) => {
            if (err) {
                console.error(err);
                return res.send("Error loading charities");
            }

            res.render('items/new', { charities });
        });
    }
);


//create new clothing item and insert into DB
app.post('/items',
    requireLogin,
    (req, res) => {

        const {
            title,
            description,
            category,
            size,
            condition_desc,
            charity_id
        } = req.body;

        const insertItemSQL = `
            INSERT INTO clothing_items
            (user_id, title, description, category, size, condition_desc, charity_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `;

        db.query(
            insertItemSQL,
            [
                req.session.user.user_id,
                title,
                description,
                category,
                size,
                condition_desc,
                charity_id
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

//page for listing every clothing item uploaded by user
app.get('/items/my',
    requireLogin,
    (req, res) => {

        const sql = `
            SELECT
                clothing_items.*,
                charity_centres.charity_name AS charity_name
            FROM clothing_items
            LEFT JOIN charity_centres
            ON clothing_items.charity_id = charity_centres.charity_id
            WHERE clothing_items.user_id = ?
            ORDER BY clothing_items.created_at DESC
        `;

        db.query(sql, [req.session.user.user_id], (err, items) => {
            if (err){
                console.error(err);
                return res.send("Error");
            } 
            res.render('items/my', { items });
        });
    }
);

//edit items uploaded by user
app.get('/items/:id/edit', requireLogin, (req, res) => {

    const itemSQL = `
        SELECT * 
        FROM clothing_items 
        WHERE item_id = ?
    `;

    const charitySQL = `
        SELECT charity_id, charity_name 
        FROM charity_centres
        WHERE is_active = 1
        ORDER BY charity_name
    `;

    db.query(itemSQL, [req.params.id], (err, itemResults) => {
        if (err || itemResults.length === 0) {
            console.error(err);
            return res.send("Item not found");
        }

        db.query(charitySQL, (err, charityResults) => {
            if (err) {
                console.error(err);
                return res.send("Error loading charity centres");
            }
            res.render('items/edit', {
                item: itemResults[0],
                charity_centres: charityResults
            });
        });
    });
});


//update clothing item after editing
app.post('/items/:id',
    requireLogin,
    (req, res) => {

        const { title, description, category, size, condition_desc, charity_id } = req.body;

        const sql = `
            UPDATE clothing_items
            SET title = ?, description = ?, category = ?, size = ?, condition_desc = ?, charity_id = ?
            WHERE item_id = ? AND user_id = ?
        `;

        db.query(
            sql,
            [title, description, category, size, condition_desc, charity_id || null, req.params.id, req.session.user.user_id],
            err => {
                if (err) {
                    console.error(err);
                    return res.send("Update failed");
                } 
                res.redirect('/items/my');
            }
        );
    }
);

//delete clothing item
app.post('/items/:id/delete',
    requireLogin,
    (req, res) => {

        const sql = `
            DELETE FROM clothing_items
            WHERE item_id = ? AND user_id = ?
        `;

        db.query(sql, [req.params.id, req.session.user.user_id], err => {
            if (err) {
                console.error(err);
                return res.send("Delete failed");
            } 
            res.redirect('/items/my');
        });
    }
);

//admin feature for approving requests for clothing submitted by other users
app.get('/admin/requests',
    requireLogin,
    requireRole('sys_admin', 'charity_admin'),
    (req, res) => {

        const sql = `
            SELECT
                item_requests.request_id,
                item_requests.status,
                users.username AS requester,
                clothing_items.title
            FROM item_requests
            JOIN users ON item_requests.requester_id = users.user_id
            JOIN clothing_items ON item_requests.item_id = clothing_items.item_id
            WHERE item_requests.status = 'pending'
        `;

        db.query(sql, (err, requests) => {
            if (err) {
                console.error(err);
                return res.send("Error loading requests");
            }
            res.render('admin_requests', { requests });
        });
    }
);

//send requests into DB route
app.post('/requests',
    requireLogin,
    (req, res) => {

        const { item_id } = req.body;

        // Prevent duplicate requests
        const checkSQL = `
            SELECT * FROM item_requests
            WHERE item_id = ? AND requester_id = ?
        `;

        db.query(checkSQL, [item_id, req.session.user.user_id], (err, rows) => {
            if (rows.length > 0) {
                return res.send("You have already requested this item");
            }

            const insertSQL = `
                INSERT INTO item_requests (item_id, requester_id)
                VALUES (?, ?)
            `;

            db.query(insertSQL, [item_id, req.session.user.user_id], err => {
                if (err) {
                    console.error(err);
                    return res.send("Request failed");
                }
                res.redirect('/items');
            });
        });
    }
);

// admin approval of clothing requests
app.post('/admin/requests/:id/approve',
    requireLogin,
    requireRole('sys_admin', 'charity_admin'),
    (req, res) => {

        const requestId = req.params.id;

        const sql = `
            UPDATE item_requests
            JOIN clothing_items ON item_requests.item_id = clothing_items.item_id
            SET
                item_requests.status = 'approved',
                clothing_items.status = 'reserved'
            WHERE item_requests.request_id = ?
        `;

        db.query(sql, [requestId], err => {
            if (err) {
                console.error(err);
                return res.send("Approval failed");
            }
            res.redirect('/admin/requests');
        });
    }
);

//admin rejection of clothing requests
app.post('/admin/requests/:id/reject',
    requireLogin,
    requireRole('sys_admin', 'charity_admin'),
    (req, res) => {

        const sql = `
            UPDATE item_requests
            SET status = 'rejected'
            WHERE request_id = ?
        `;

        db.query(sql, [req.params.id], err => {
            if (err) {
                console.error(err);
                return res.send("Rejection failed");
            } 
            res.redirect('/admin/requests');
        });
    }
);

//view all requests for user
app.get('/requests/my',
    requireLogin,
    (req, res) => {

        const sql = `
            SELECT
                clothing_items.title,
                item_requests.status
            FROM item_requests
            JOIN clothing_items ON item_requests.item_id = clothing_items.item_id
            WHERE requester_id = ?
        `;

        db.query(sql, [req.session.user.user_id], (err, requests) => {
            if (err) {
                console.error(err);
                return res.send("Error");
            }
            res.render('requests/my', { requests });
        });
    }
);

// app.get('/user/profile',
//     requireLogin,
//     requireRole('user'),
//     (req, res) => {
//         res.render('profile');
//     }
// );

//Destroy session on logging out
app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/');
    });
});

//server
app.listen(process.env.PORT || 3000);
console.log('Server is listening//localhost:3000/');