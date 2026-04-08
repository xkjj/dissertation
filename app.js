const express = require('express');
const app = express();
const path = require('path');
const mysql = require('mysql2');
const sessions = require('express-session');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const fs = require('fs');
const hour = 1000 * 60 * 60;
const bcrypt = require('bcrypt');
const SALT_ROUNDS = 10;
const redirectByRole = require('./services/roleRedirect');
const {
    ITEM_STATUS,
    transitionItem,
    canChangeStatus,
    deleteItem,
    donorCanDelete,
    donorCanFullyEdit,
    donorCanChangeCharity,
    charityAdminCanEdit,
    charityAdminCanDelete,
    charityAdminCanMarkReceived,
    charityAdminCanReturn,
    charityAdminCanSend,
    recipientCanConfirm,
    determineInitialStatus,
    determineStatusAfterEdit,
} = require('./services/itemStateService');

// Multer setup
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, path.join(__dirname, 'public/uploads'));
    },
    filename: (req, file, cb) => {
        const uniqueName = Date.now() + path.extname(file.originalname);
        cb(null, uniqueName);
    }
});

const fileFilter = (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|webp/;

    if (allowedTypes.test(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error("Only image files allowed"), false);
    }
};

const upload = multer({
    storage,
    fileFilter,
    limits: { fileSize: 2 * 1024 * 1024 } // 2MB
});

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

function requireSystemAdmin(req, res, next) {
    if (!req.session.user || req.session.user.role !== 'sys_admin') {
        return res.status(403).send("Access denied");
    }
    next();
}


//routes - render login page on startup
app.get('/', (req, res) => {
    if (req.session.user) {
        return redirectByRole(req.session.user, res);
    }

    res.render('login');
});

//
app.post('/', (req, res) => {
    const { username_field, password_field } = req.body;

    const getUserSQL = `
            SELECT u.*, ca.charity_id
            FROM users u
            LEFT JOIN charity_admins ca ON u.user_id = ca.user_id
            WHERE u.username = ?
            `;

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
                role: user.role,
            };

            // Role-based redirect
            redirectByRole(user, res);

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
        role_field,
        phone_field,
        address_field,
        postcode_field
    } = req.body;

    const role = role_field;

    if (!['donor', 'recipient'].includes(role)) {
        return res.send("Invalid account type");
    }

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
            role,
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
    requireSystemAdmin, //required roles to gain access
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

            res.render('admin/dashboard', {
                admin: req.session.user,
                users
            });
        });
    }
);

//update user role
app.post('/admin/update-role',
    requireLogin,
    requireSystemAdmin,
    (req, res) => {

        const { user_id, role } = req.body;

        const getUserSQL = `
            SELECT role FROM users WHERE user_id = ?
        `;

        db.query(getUserSQL, [user_id], (err, rows) => {
            if (err) {
                console.error(err);
                return res.send("Database error");
            }

            if (rows.length === 0) {
                return res.send("User not found");
            }

            const currentRole = rows[0].role;

            // Prevent changes to system admin
            if (currentRole === 'sys_admin') {
                return res.send("System admin role cannot be changed");
            }

            // Update role in users table
            const updateRoleSQL = `
                UPDATE users SET role = ? WHERE user_id = ?
            `;

            db.query(updateRoleSQL, [role, user_id], err => {
                if (err) {
                    console.error(err);
                    return res.send("Failed to update role");
                }

                /*
                HANDLE charity_admins TABLE
                */

                // If promoted to charity_admin
                if (role === 'charity_admin' && currentRole !== 'charity_admin') {

                    const insertAdminSQL = `
                        INSERT INTO charity_admins (user_id, charity_id)
                        VALUES (?, NULL)
                    `;

                    db.query(insertAdminSQL, [user_id], err => {
                        if (err) {
                            console.error(err);
                            return res.send("Failed to add charity admin");
                        }

                        return res.redirect('/admin/dashboard');
                    });

                }
                // If demoted from charity_admin
                else if (currentRole === 'charity_admin' && role !== 'charity_admin') {

                    const deleteAdminSQL = `
                        DELETE FROM charity_admins
                        WHERE user_id = ?
                    `;

                    db.query(deleteAdminSQL, [user_id], err => {
                        if (err) {
                            console.error(err);
                            return res.send("Failed to remove charity admin");
                        }
                        return res.redirect('/admin/dashboard');
                    });

                }
                else {
                    res.redirect('/admin/dashboard');
                }
            });
        });
    }
);

//disable accounts in dashboard
app.post('/admin/toggle-user',
    requireLogin,
    requireSystemAdmin,
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

app.get('/admin/charitydashboard',
    requireLogin,
    requireRole('sys_admin', 'charity_admin'),
    (req, res) => {

        const userId = req.session.user.user_id;

        // Get charity assigned to this charity admin
        const charitySQL = `
            SELECT charity_id
            FROM charity_admins
            WHERE user_id = ?
        `;

        db.query(charitySQL, [userId], (err, charityResult) => {
            if (err) {
                console.error(err);
                return res.send("Error loading charity");
            }

            if (charityResult.length === 0 || !charityResult[0].charity_id) {
                return res.send("No charity assigned");
            }

            const charityId = charityResult[0].charity_id;

            const itemsSQL = `
                SELECT *
                FROM clothing_items
                WHERE charity_id = ?
                AND status != 'deleted'
            `;

            const requestsSQL = `
                SELECT 
                    ir.request_id,
                    ir.status,
                    ir.requested_at,
                    ci.title,
                    ci.status AS item_status,
                    u.username AS requester
                FROM item_requests ir
                JOIN clothing_items ci ON ir.item_id = ci.item_id
                JOIN users u ON ir.requester_id = u.user_id
                WHERE ci.charity_id = ?
            `;

            db.query(itemsSQL, [charityId], (err, items) => {
                if (err) {
                    console.error(err);
                    return res.send("Error loading items");
                }

                db.query(requestsSQL, [charityId], (err, requests) => {
                    if (err) {
                        console.error(err);
                        return res.send("Error loading requests");
                    }

                    res.render('admin/charitydashboard', {
                        items,
                        requests
                    });
                });
            });
        });
    }
);

app.post('/admin/charitydashboard/:id/approve',
    requireLogin,
    requireRole('sys_admin', 'charity_admin'),
    (req, res) => {

        const requestId = req.params.id;
        const userId = req.session.user.user_id;

        const charitySQL = `
            SELECT charity_id
            FROM charity_admins
            WHERE user_id = ?
        `;

        db.query(charitySQL, [userId], (err, charityResult) => {

            if (err || charityResult.length === 0)
                return res.send("No charity assigned");

            const charityId = charityResult[0].charity_id;

            const getRequestSQL = `
                SELECT ir.item_id
                FROM item_requests ir
                JOIN clothing_items ci ON ir.item_id = ci.item_id
                WHERE ir.request_id = ?
                AND ci.charity_id = ?
            `;

            db.query(getRequestSQL, [requestId, charityId], (err, result) => {

                if (err || result.length === 0)
                    return res.send("Invalid request");

                const itemId = result[0].item_id;

                const approveSQL = `
                    UPDATE item_requests
                    SET status = 'approved'
                    WHERE request_id = ?
                `;

                db.query(approveSQL, [requestId], err => {
                    if (err) return res.send("Approval failed");

                    const rejectOthersSQL = `
                        UPDATE item_requests
                        SET status = 'rejected'
                        WHERE item_id = ?
                        AND request_id != ?
                        AND status = 'pending'
                    `;

                    db.query(rejectOthersSQL, [itemId, requestId], err => {
                        if (err) return res.send("Failed rejecting others");

                        const updateItemSQL = `
                            UPDATE clothing_items
                            SET status = 'allocated'
                            WHERE item_id = ?
                        `;

                        db.query(updateItemSQL, [itemId], err => {
                            if (err) return res.send("Item update failed");

                            res.redirect('/admin/charitydashboard');
                        });
                    });
                });
            });
        });
    }
);

app.post('/admin/charitydashboard/:id/reject',
    requireLogin,
    requireRole('sys_admin', 'charity_admin'),
    (req, res) => {

        const requestId = req.params.id;
        const userId = req.session.user.user_id;

        const charitySQL = `
            SELECT charity_id
            FROM charity_admins
            WHERE user_id = ?
        `;

        db.query(charitySQL, [userId], (err, charityResult) => {

            if (err || charityResult.length === 0)
                return res.send("No charity assigned");

            const charityId = charityResult[0].charity_id;

            const rejectSQL = `
                UPDATE item_requests
                SET status = 'rejected'
                WHERE request_id = ?
            `;

            db.query(rejectSQL, [requestId], err => {
                if (err) return res.send("Reject failed");

                res.redirect('/admin/charitydashboard');
            });
        });
    }
);


// List all available items (with search)
app.get('/items', (req, res) => {

    const userId = req.session.user ? req.session.user.user_id : null;
    const search = req.query.search || '';

    let sql = `
        SELECT 
            clothing_items.item_id,
            clothing_items.title,
            clothing_items.description,
            clothing_items.category,
            clothing_items.size,
            clothing_items.condition_desc,
            clothing_items.status,
            clothing_items.charity_id,
            clothing_items.user_id AS owner_id,

            charity_centres.charity_name AS charity_name,
            users.username,

            (
                SELECT status
                FROM item_requests
                WHERE item_requests.item_id = clothing_items.item_id
                AND item_requests.requester_id = ?
                LIMIT 1
            ) AS request_status

        FROM clothing_items
        JOIN users ON clothing_items.user_id = users.user_id
        LEFT JOIN charity_centres ON clothing_items.charity_id = charity_centres.charity_id
        WHERE clothing_items.status = 'approved'
    `;

    const params = [userId];

    // search filter
    if (search) {
        sql += `
            AND (
                clothing_items.title LIKE ?
                OR clothing_items.description LIKE ?
                OR clothing_items.category LIKE ?
            )
        `;

        const like = `%${search}%`;
        params.push(like, like, like);
    }

    sql += ` ORDER BY clothing_items.created_at DESC`;

    db.query(sql, params, (err, items) => {
        if (err) {
            console.error(err);
            return res.send("Error loading items");
        }


        const imageSQL = `
            SELECT item_id, filename
            FROM item_images
        `;

        db.query(imageSQL, (err, images) => {

            if (err) {
                console.error(err);
                return res.send("Error loading images");
            }

            const imageMap = {};

            images.forEach(img => {
                if (!imageMap[img.item_id]) {
                    imageMap[img.item_id] = [];
                }
                imageMap[img.item_id].push(img.filename);
            });

            items.forEach(item => {
                item.images = imageMap[item.item_id] || [];
            });

            res.render('items/index', { 
                items,
                search
            });
        });
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
    upload.array('images', 5),
    (req, res) => {

        const {
            title,
            description,
            category,
            size,
            condition_desc,
            charity_id
        } = req.body;

        const images = req.files || [];

        // Validate
        if (images.length > 5) {
            return res.send("Maximum 5 images allowed");
        }

        const assignment = determineInitialStatus(charity_id);

        const insertItemSQL = `
            INSERT INTO clothing_items
            (user_id, title, description, category, size, condition_desc, status, charity_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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
                assignment.status,
                assignment.charity_id
            ],
            (err, result) => {

                if (err) {
                    console.error(err);
                    return res.send("Failed to create item");
                }

                const itemId = result.insertId;

                if (images.length > 0) {

                    const values = images.map(file => [itemId, file.filename]);

                    db.query(
                        'INSERT INTO item_images (item_id, filename) VALUES ?',
                        [values],
                        err => {
                            if (err) {
                                console.error("Image insert failed:", err);
                                return res.send("Image upload failed");
                            }

                            res.redirect('/items/my');
                        }
                    );

                } else {
                    res.redirect('/items/my');
                }
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
            AND clothing_items.status != 'deleted'
            ORDER BY clothing_items.created_at DESC
        `;

        db.query(sql, [req.session.user.user_id], (err, items) => {
        if (err){
            console.error(err);
            return res.send("Error");
        }

        const imageSQL = `
            SELECT item_id, filename
            FROM item_images
        `;

        db.query(imageSQL, (err, images) => {

            const imageMap = {};

            images.forEach(img => {
                if (!imageMap[img.item_id]) {
                    imageMap[img.item_id] = [];
                }
                imageMap[img.item_id].push(img.filename);
            });

            items.forEach(item => {
                item.images = imageMap[item.item_id] || [];
            });

            res.render('items/my', { 
                items, 
                donorCanDelete
            });
        });
    });
    }
);

app.get('/items/unassigned',
    requireLogin,
    (req, res) => {

        const sql = `
            SELECT *
            FROM clothing_items
            WHERE user_id = ?
            AND status = 'unassigned'
        `;

        db.query(sql, [req.session.user.user_id], (err, items) => {
            if (err) return res.send("Error loading items");

            res.render('items/unassigned', { items });
        });
    }
);

app.post('/items/:id/assign',
    requireLogin,
    (req, res) => {

        const itemId = req.params.id;
        const { charity_id } = req.body;

        if (!charity_id) {
            return res.send("Charity required");
        }

        db.query(
            "SELECT status FROM clothing_items WHERE item_id = ? AND user_id = ?",
            [itemId, req.session.user.user_id],
            (err, rows) => {

                if (err || rows.length === 0)
                    return res.send("Item not found");

                const currentStatus = rows[0].status;

                // Only allow assignment from valid states
                if (
                    currentStatus !== ITEM_STATUS.UNASSIGNED &&
                    currentStatus !== ITEM_STATUS.REJECTED
                ) {
                    return res.send("Cannot assign charity in current state");
                }

                db.query(
                    `
                    UPDATE clothing_items
                    SET charity_id = ?, status = ?
                    WHERE item_id = ?
                    `,
                    [charity_id, ITEM_STATUS.ASSIGNED, itemId],
                    err => {
                        if (err) return res.send("Update failed");

                        res.redirect('/items/my');
                    }
                );
            }
        );
    }
);


app.get('/items/:id', (req, res) => {

    const itemId = req.params.id;
    const userId = req.session.user ? req.session.user.user_id : null;

    const itemSQL = `
        SELECT 
            ci.*,
            u.username,
            cc.charity_name,

            (
                SELECT status
                FROM item_requests
                WHERE item_id = ci.item_id
                AND requester_id = ?
                LIMIT 1
            ) AS request_status

        FROM clothing_items ci
        JOIN users u ON ci.user_id = u.user_id
        LEFT JOIN charity_centres cc ON ci.charity_id = cc.charity_id
        WHERE ci.item_id = ?
        AND ci.status != 'deleted'
    `;

    db.query(itemSQL, [userId, itemId], (err, results) => {

        if (err || results.length === 0) {
            return res.send("Item not found");
        }

        const item = results[0];

        const imageSQL = `
            SELECT filename
            FROM item_images
            WHERE item_id = ?
        `;

        db.query(imageSQL, [itemId], (err, images) => {

            if (err) return res.send("Error loading images");

            item.images = images.map(img => img.filename);

            res.render('items/show', { item, user: req.session.user });
        });

    });
});

//edit items uploaded by user
app.get('/items/:id/edit', requireLogin, (req, res) => {

    const itemId = req.params.id;
    const user = req.session.user;

    const charitySQL = `
        SELECT charity_id
        FROM charity_admins
        WHERE user_id = ?
    `;

    const centresSQL = `
        SELECT charity_id, charity_name 
        FROM charity_centres
        WHERE is_active = 1
        ORDER BY charity_name
    `;

    // DONOR FLOW
    if (user.role === 'donor') {

        const itemSQL = `
            SELECT * 
            FROM clothing_items 
            WHERE item_id = ?
            AND user_id = ?
            AND status != 'deleted'
        `;

        db.query(itemSQL, [itemId, user.user_id], (err, itemResults) => {

            if (err || itemResults.length === 0) {
                return res.send("Item not found");
            }

            const item = itemResults[0];

            const imageSQL = `
            SELECT filename
            FROM item_images
            WHERE item_id = ?
            `;

            db.query(imageSQL, [itemId], (err, images) => {

                if (err) {
                    console.error(err);
                    return res.send("Error loading images");
                }

                item.images = images.map(img => img.filename);

                db.query(centresSQL, (err, charityResults) => {

                    if (err) {
                        console.error(err);
                        return res.send("Error loading charities");
                    }

                    res.render('items/edit', {
                        item,
                        charity_centres: charityResults,
                        donorCanFullyEdit: donorCanFullyEdit(item.status),
                        donorCanChangeCharity: donorCanChangeCharity(item.status),
                        isCharityAdmin: false,
                        canFullEdit: donorCanFullyEdit(item.status)
                    });

                });

            });
        });
    }

    // CHARITY ADMIN FLOW
    else if (user.role === 'charity_admin') {

        db.query(charitySQL, [user.user_id], (err, result) => {

            if (err || result.length === 0) {
                return res.send("No charity assigned");
            }

            const charityId = result[0].charity_id;

            const itemSQL = `
                SELECT *
                FROM clothing_items
                WHERE item_id = ?
                AND charity_id = ?
                AND status = 'received'
            `;

            db.query(itemSQL, [itemId, charityId], (err, itemResults) => {

                if (err || itemResults.length === 0) {
                    return res.send("Item not found or not editable");
                }

                const item = itemResults[0];

                // FETCH IMAGES
                const imageSQL = `
                    SELECT filename
                    FROM item_images
                    WHERE item_id = ?
                `;

                db.query(imageSQL, [itemId], (err, images) => {

                    if (err) {
                        console.error(err);
                        return res.send("Error loading images");
                    }

                    item.images = images.map(img => img.filename);

                    db.query(centresSQL, (err, charityResults) => {

                        res.render('items/edit', {
                            item,
                            charity_centres: charityResults,
                            donorCanFullyEdit: false,
                            donorCanChangeCharity: false,
                            isCharityAdmin: true,
                            canFullEdit: item.status === 'received'
                        });
                    });
                });
            });
        });
    }

    else {
        return res.send("Unauthorized");
    }

});

//update clothing item after editing
app.post('/items/:id',
requireLogin,
upload.array('images', 5), // max 5 images
(req, res) => {

    const itemId = req.params.id;
    const user = req.session.user;

    const {
        title,
        description,
        category,
        size,
        condition_desc,
        charity_id
    } = req.body;

    const newImages = req.files || [];

    // DONOR FLOW
    if (user.role === 'donor') {

        const userId = user.user_id;

        db.query(
            `
            SELECT status, charity_id
            FROM clothing_items
            WHERE item_id = ?
            AND user_id = ?
            `,
            [itemId, userId],
            (err, rows) => {

                if (err || rows.length === 0)
                    return res.send("Item not found");

                const currentStatus = rows[0].status;
                const oldCharityId = rows[0].charity_id;
                const newCharityId = charity_id || null;

                const newStatus = determineStatusAfterEdit(
                    currentStatus,
                    'donor',
                    oldCharityId,
                    newCharityId
                );

                let updateSQL;
                let params;

                if (donorCanFullyEdit(currentStatus)) {

                    updateSQL = `
                        UPDATE clothing_items
                        SET
                            title = ?,
                            description = ?,
                            category = ?,
                            size = ?,
                            condition_desc = ?,
                            charity_id = ?,
                            status = ?
                        WHERE item_id = ?
                    `;

                    params = [
                        title,
                        description,
                        category,
                        size,
                        condition_desc,
                        newCharityId,
                        newStatus,
                        itemId
                    ];
                }

                else if (donorCanChangeCharity(currentStatus)) {

                    updateSQL = `
                        UPDATE clothing_items
                        SET charity_id = ?, status = ?
                        WHERE item_id = ?
                    `;

                    params = [
                        newCharityId,
                        newStatus,
                        itemId
                    ];
                }

                else {
                    return res.send("This item can no longer be edited.");
                }

                db.query(updateSQL, params, err => {

                    if (err) return res.send("Update failed");

                    if (newImages.length > 0) {

                        const values = newImages.map(file => [itemId, file.filename]);

                        db.query(
                            'INSERT INTO item_images (item_id, filename) VALUES ?',
                            [values],
                            err => {
                                if (err) {
                                    console.error("Image insert failed:", err);
                                }
                            }
                        );
                    }
                    res.redirect('/items/my');
                });
            }
        );
    }

    // CHARITY ADMIN FLOW
    else if (user.role === 'charity_admin') {

        const charitySQL = `
            SELECT charity_id
            FROM charity_admins
            WHERE user_id = ?
        `;

        db.query(charitySQL, [user.user_id], (err, result) => {

            if (err || result.length === 0) {
                return res.send("No charity assigned");
            }

            const charityId = result[0].charity_id;

            db.query(
                `
                SELECT status
                FROM clothing_items
                WHERE item_id = ?
                AND charity_id = ?
                `,
                [itemId, charityId],
                (err, rows) => {

                    if (err || rows.length === 0)
                        return res.send("Item not found");

                    const currentStatus = rows[0].status;

                    if (currentStatus !== 'received') {
                        return res.send("Not allowed");
                    }

                    db.query(
                        `
                        UPDATE clothing_items
                        SET
                            title = ?,
                            description = ?,
                            category = ?,
                            size = ?,
                            condition_desc = ?
                        WHERE item_id = ?
                        `,
                        [
                            title,
                            description,
                            category,
                            size,
                            condition_desc,
                            itemId
                        ],
                        err => {

                            if (err) return res.send("Update failed");
                            
                            // Delete ONLY after successful update
                            if (newImages.length > 0) {

                                const values = newImages.map(file => [itemId, file.filename]);

                                db.query(
                                    'INSERT INTO item_images (item_id, filename) VALUES ?',
                                    [values],
                                    err => {
                                        if (err) {
                                            console.error("Image insert failed:", err);
                                        }
                                    }
                                );
                            }
                            res.redirect('/admin/incoming-items');
                        }
                    );
                }
            );
        });
    }
    else {
        return res.send("Unauthorized");
    }
});

//delete clothing item
app.post('/items/:id/delete',
requireLogin,
(req, res) => {

    const itemId = req.params.id;
    const userId = req.session.user.user_id;

    const sql = `
        SELECT status
        FROM clothing_items
        WHERE item_id = ?
        AND user_id = ?
    `;

    db.query(sql, [itemId, userId], (err, rows) => {

        if (err || rows.length === 0) {
            return res.send("Item not found");
        }

        const status = rows[0].status;

        if (!deleteItem(status, 'donor')) {
            return res.send("This item can no longer be deleted.");
        }

        const deleteSQL = `
            UPDATE clothing_items
            SET status = 'deleted'
            WHERE item_id = ?
        `;

        db.query(deleteSQL, [itemId], err => {

            if (err) {
                console.error(err);
                return res.send("Delete failed");
            }

            res.redirect('/items/my');

        });

    });

});

//delete item image when editing
app.post('/items/:id/images/delete',
requireLogin,
(req, res) => {

    const itemId = req.params.id;
    const { filename } = req.body;
    const user = req.session.user;

    // ensure user owns item
    db.query(
        `SELECT user_id FROM clothing_items WHERE item_id = ?`,
        [itemId],
        (err, rows) => {

            if (err || rows.length === 0) {
                return res.send("Item not found");
            }

            if (rows[0].user_id !== user.user_id && user.role !== 'charity_admin') {
                return res.status(403).send("Unauthorized");
            }

            // Delete from DB
            db.query(
                `DELETE FROM item_images WHERE item_id = ? AND filename = ?`,
                [itemId, filename],
                err => {

                    if (err) {
                        console.error(err);
                        return res.send("Failed to delete image");
                    }

                    // delete file from disk
                    const filePath = path.join(__dirname, 'public/uploads', filename);

                    fs.unlink(filePath, (err) => {
                        if (err) {
                            console.error("File delete error:", err);
                        }

                        res.redirect(`/items/${itemId}/edit`);
                    });

                }
            );

        }
    );

});

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
                item_requests.request_id,
                clothing_items.title,
                item_requests.status,
                clothing_items.status AS item_status
            FROM item_requests
            JOIN clothing_items 
                ON item_requests.item_id = clothing_items.item_id
            WHERE item_requests.requester_id = ?
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

app.get('/admin/charity-centres',
    requireLogin,
    requireSystemAdmin,
    (req, res) => {

        const charitiesSQL = `
            SELECT 
                cc.*,
                u.username AS admin_username
            FROM charity_centres cc
            LEFT JOIN charity_admins ca 
                ON cc.charity_id = ca.charity_id
            LEFT JOIN users u 
                ON ca.user_id = u.user_id
        `;

        const adminsSQL = `
                SELECT user_id, username, charity_id
                FROM users
                WHERE role = 'charity_admin'
                AND is_active = 1
            `;

        db.query(adminsSQL, (err, admins) => {
            if (err) return res.send("Error loading admins");

            db.query(charitiesSQL, (err, charities) => {
                if (err) return res.send("Error loading charities");

                res.render('admin/charity_centres/index', {
                    charities,
                    admins
                });
            });
        });
    }
);


app.get('/admin/charity-centres/new',
    requireLogin,
    requireSystemAdmin,
    (req, res) => {
        res.render('admin/charity_centres/new');
    }
);

app.post('/admin/charity-centres/new',
    requireLogin,
    requireSystemAdmin,
    (req, res) => {

        const { charity_name, charity_address, charity_postcode, charity_email, charity_phone } = req.body;

        if (!charity_name || !charity_address || !charity_postcode) {
            return res.send("Required fields missing");
        }

        const sql = `
            INSERT INTO charity_centres
            (charity_name, charity_address, charity_postcode, charity_email, charity_phone, is_active)
            VALUES (?, ?, ?, ?, ?, 1)
        `;

        db.query(sql, [charity_name, charity_address, charity_postcode, charity_email, charity_phone], err => {
            if (err) {
                console.error(err);
                return res.send("Insert failed");
            }
            res.redirect('/admin/charity-centres');
        });
    }
);

app.get('/admin/charity-centres/:id/edit',
    requireLogin,
    requireSystemAdmin,
    (req, res) => {

        const sql = `
            SELECT *
            FROM charity_centres
            WHERE charity_id = ?
        `;

        db.query(sql, [req.params.id], (err, results) => {
            if (err || results.length === 0) {
                return res.send("Charity centre not found");
            }

            res.render('admin/charity_centres/edit', {
                centre: results[0]
            });
        });
    }
);

app.post('/admin/charity-centres/:id/edit/',
    requireLogin,
    requireSystemAdmin,
    (req, res) => {

        const charityId = req.params.id;
        const {
            charity_name,
            charity_address,
            charity_postcode,
            charity_email,
            charity_phone,
            is_active
        } = req.body;

        const activeValue = is_active === '1' ? 1 : 0;

        const updateSQL = `
            UPDATE charity_centres
            SET charity_name = ?,
                charity_address = ?,
                charity_postcode = ?,
                charity_email = ?,
                charity_phone = ?,
                is_active = ?
            WHERE charity_id = ?
        `;

        db.query(updateSQL,
            [
                charity_name,
                charity_address,
                charity_postcode,
                charity_email,
                charity_phone,
                activeValue,
                charityId
            ],
            (err) => {

                if (err) {
                    console.error(err);
                    return res.send("Update failed");
                }

                // IF charity was deactivated — remove admin
                if (activeValue === 0) {

                    const removeAdminSQL = `
                        UPDATE charity_admins
                        SET charity_id = NULL
                        WHERE charity_id = ?
                    `;

                    db.query(removeAdminSQL, [charityId], (err) => {
                        if (err) {
                            console.error("Admin removal failed:", err);
                        }

                        return res.redirect('/admin/charity-centres');
                    });

                } else {
                    res.redirect('/admin/charity-centres');
                }

            }
        );
    }
);

app.post('/admin/charity-centres/assign-admin',
    requireLogin,
    requireSystemAdmin,
    (req, res) => {

        const { charity_id, user_id } = req.body;

        if (!charity_id || !user_id)
            return res.send("Invalid data");

        // Remove any existing admin for this charity
        const removeExisting = `
            UPDATE charity_admins
            SET charity_id = NULL
            WHERE charity_id = ?
        `;

        db.query(removeExisting, [charity_id], err => {
            if (err) return res.send("Error removing previous admin");

            // Assign new admin
            const assignAdmin = `
                UPDATE charity_admins
                SET charity_id = ?
                WHERE user_id = ?
            `;

            db.query(assignAdmin, [charity_id, user_id], err => {
                if (err) return res.send("Assignment failed");

                res.redirect('/admin/charity-centres');
            });
        });
    }
);

app.post('/admin/charity-centres/remove-admin',
    requireLogin,
    requireSystemAdmin,
    (req, res) => {

        const { charity_id } = req.body;

        if (!charity_id) {
            return res.send("Invalid request");
        }

        const removeSQL = `
            UPDATE charity_admins
            SET charity_id = NULL
            WHERE charity_id = ?
        `;

        db.query(removeSQL, [charity_id], (err) => {
            if (err) {
                console.error(err);
                return res.send("Failed to remove admin");
            }

            res.redirect('/admin/charity-centres');
        });
    }
);

app.get('/admin/charity-items',
requireLogin,
requireRole('charity_admin', 'sys_admin'),
(req, res) => {

    const userId = req.session.user.user_id;

    const charitySQL = `
        SELECT charity_id
        FROM charity_admins
        WHERE user_id = ?
    `;

    db.query(charitySQL, [userId], (err, charityResult) => {

        if (err) {
            console.error(err);
            return res.send("Error loading charity");
        }

        if (charityResult.length === 0 || !charityResult[0].charity_id) {
            return res.send("No charity assigned");
        }

        const charityId = charityResult[0].charity_id;

        const sql = `
            SELECT
                clothing_items.*,
                users.username AS donor
            FROM clothing_items
            JOIN users ON clothing_items.user_id = users.user_id
            WHERE clothing_items.charity_id = ?
            AND clothing_items.status = 'assigned'
            AND status != 'deleted'
        `;

        db.query(sql, [charityId], (err, items) => {

            if (err) {
                console.error(err);
                return res.send("Error loading items");
            }

            res.render('admin/charity_items', { items });

        });

    });

});

app.post('/admin/charity-items/:id/approve',
requireLogin,
requireRole('charity_admin'),
(req, res) => {

    const itemId = req.params.id;
    const userId = req.session.user.user_id;

    const charitySQL = `
        SELECT charity_id
        FROM charity_admins
        WHERE user_id = ?
    `;

    db.query(charitySQL, [userId], (err, result) => {

        if (err || result.length === 0)
            return res.send("Charity not found");

        const charityId = result[0].charity_id;

        const sql = `
            UPDATE clothing_items
            SET status = 'approved'
            WHERE item_id = ?
            AND charity_id = ?
            AND status = 'assigned'
        `;

        db.query(sql, [itemId, charityId], err => {

            if (err) {
                console.error(err);
                return res.send("Approval failed");
            }

            res.redirect('/admin/charity-items');

        });

    });

});

app.post('/admin/charity-items/:id/reject',
requireLogin,
requireRole('charity_admin'),
(req, res) => {

    const itemId = req.params.id;
    const userId = req.session.user.user_id;

    const charitySQL = `
        SELECT charity_id
        FROM charity_admins
        WHERE user_id = ?
    `;

    db.query(charitySQL, [userId], (err, result) => {

        if (err || result.length === 0)
            return res.send("Charity not found");

        const charityId = result[0].charity_id;

        const sql = `
            UPDATE clothing_items
            SET
                status = 'rejected',
                charity_id = NULL
            WHERE item_id = ?
            AND charity_id = ?
            AND status = 'assigned'
        `;

        db.query(sql, [itemId, charityId], err => {

            if (err) {
                console.error(err);
                return res.send("Reject failed");
            }

            res.redirect('/admin/charity-items');

        });

    });

});

app.get('/admin/incoming-items',
requireLogin,
requireRole('charity_admin'),
(req, res) => {

    const userId = req.session.user.user_id;

    // Get charity_id for this admin
    const charitySQL = `
        SELECT charity_id
        FROM charity_admins
        WHERE user_id = ?
    `;

    db.query(charitySQL, [userId], (err, result) => {

        if (err || result.length === 0 || !result[0].charity_id) {
            return res.send("No charity assigned");
        }

        const charityId = result[0].charity_id;

        const itemsSQL = `
            SELECT
                clothing_items.*,
                users.username AS donor
            FROM clothing_items
            JOIN users ON clothing_items.user_id = users.user_id
            WHERE clothing_items.charity_id = ?
            AND clothing_items.status = 'allocated'
            ORDER BY clothing_items.created_at DESC
        `;

        db.query(itemsSQL, [charityId], (err, items) => {

            if (err) {
                console.error(err);
                return res.send("Error loading items");
            }

            res.render('admin/incoming_items', { items });

        });

    });

});

//charity marks item as received
app.post('/admin/items/:id/received',
requireLogin,
requireRole('charity_admin'),
(req, res) => {

    const itemId = req.params.id;

    db.query(
        `SELECT status FROM clothing_items WHERE item_id = ?`,
        [itemId],
        (err, result) => {

            if (err || result.length === 0)
                return res.send("Item not found");

            const currentStatus = result[0].status;

            if (!charityAdminCanMarkReceived(currentStatus)) {
                return res.send("Not allowed");
            }

            const newStatus = transitionItem(currentStatus, 'received');

            db.query(
                `UPDATE clothing_items SET status = ? WHERE item_id = ?`,
                [newStatus, itemId],
                () => res.redirect('/admin/charitydashboard')
            );
        }
    );
});

//charity sends item to recipient
app.post('/admin/items/:id/send',
requireLogin,
requireRole('charity_admin'),
(req, res) => {

    const itemId = req.params.id;
    const userId = req.session.user.user_id;

    // Get charity_id of admin
    const charitySQL = `
        SELECT charity_id
        FROM charity_admins
        WHERE user_id = ?
    `;

    db.query(charitySQL, [userId], (err, result) => {

        if (err || result.length === 0) {
            return res.send("No charity assigned");
        }

        const charityId = result[0].charity_id;

        // Validate item belongs to charity AND is received
        const itemSQL = `
            SELECT status
            FROM clothing_items
            WHERE item_id = ?
            AND charity_id = ?
        `;

        db.query(itemSQL, [itemId, charityId], (err, rows) => {

            if (err || rows.length === 0)
                return res.send("Item not found");

            const currentStatus = rows[0].status;

            if (currentStatus !== 'received') {
                return res.send("Item must be received first");
            }

            // Update status → sent
            db.query(
                `UPDATE clothing_items SET status = 'sent' WHERE item_id = ?`,
                [itemId],
                err => {

                    if (err) {
                        console.error(err);
                        return res.send("Update failed");
                    }

                    res.redirect('/admin/charitydashboard');

                }
            );

        });

    });

});

//charity returns item
app.post('/admin/items/:id/return',
requireLogin,
requireRole('charity_admin'),
(req, res) => {

    const itemId = req.params.id;

    db.query(
        `SELECT status FROM clothing_items WHERE item_id = ?`,
        [itemId],
        (err, result) => {

            const currentStatus = result[0].status;

            if (!charityAdminCanReturn(currentStatus)) {
                return res.send("Not allowed");
            }

            const newStatus = transitionItem(currentStatus, 'returned');

            db.query(
                `UPDATE clothing_items SET status = ? WHERE item_id = ?`,
                [newStatus, itemId],
                () => res.redirect('/admin/charitydashboard')
            );
        }
    );
});

//recipient confirms delivery
app.post('/requests/:id/delivered',
requireLogin,
requireRole('recipient'),
(req, res) => {

    const requestId = req.params.id;
    const userId = req.session.user.user_id;

    const sql = `
        SELECT ci.item_id, ci.status
        FROM item_requests ir
        JOIN clothing_items ci ON ir.item_id = ci.item_id
        WHERE ir.request_id = ?
        AND ir.requester_id = ?
    `;

    db.query(sql, [requestId, userId], (err, rows) => {

        if (err || rows.length === 0)
            return res.send("Request not found");

        const { item_id, status } = rows[0];

        if (status !== 'sent') {
            return res.send("Item not sent yet");
        }

        db.query(
            `UPDATE clothing_items SET status = 'delivered' WHERE item_id = ?`,
            [item_id],
            err => {

                if (err) return res.send("Update failed");

                res.redirect('/requests/my');
            }
        );

    });

});

//recipient marks never arrived
app.post('/requests/:id/never-arrived',
requireLogin,
requireRole('recipient'),
(req, res) => {

    const requestId = req.params.id;
    const userId = req.session.user.user_id;

    const sql = `
        SELECT ci.item_id, ci.status
        FROM item_requests ir
        JOIN clothing_items ci ON ir.item_id = ci.item_id
        WHERE ir.request_id = ?
        AND ir.requester_id = ?
    `;

    db.query(sql, [requestId, userId], (err, rows) => {

        if (err || rows.length === 0)
            return res.send("Request not found");

        const { item_id, status } = rows[0];

        if (status !== 'sent') {
            return res.send("Item not sent yet");
        }

        db.query(
            `UPDATE clothing_items SET status = 'never_arrived' WHERE item_id = ?`,
            [item_id],
            err => {

                if (err) return res.send("Update failed");

                res.redirect('/requests/my');
            }
        );

    });

});

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