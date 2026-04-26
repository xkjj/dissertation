// initalisation
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

// module imports
const redirectByRole = require('./services/roleRedirect');
const {
    ITEM_STATUS,
    transitionItem,
    deleteItem,
    donorCanDelete,
    donorCanFullyEdit,
    donorCanChangeCharity,
    charityAdminCanEdit,
    charityAdminCanMarkReceived,
    charityAdminCanReturn,
    charityAdminCanSend,
    recipientCanConfirm,
    determineInitialStatus,
    determineStatusAfterEdit,
} = require('./services/itemStateService');

// Multer image uploading setup
const storage = multer.diskStorage({
    destination: (req, file, cb) => {

        const itemId = req.params.id; // use item's ID from URL params

        // set folder for image uploads - /uploads/items/{itemId}/ - Folder name for item images set to item's ID
        const uploadPath = path.join(__dirname, 'uploads', 'items', String(itemId));

        // create folder if it doesn't exist
        if (!fs.existsSync(uploadPath)) {
            fs.mkdirSync(uploadPath, { recursive: true });
        }

        cb(null, uploadPath);
    },

    // filename generation on image upload - uses unique timestamp to avoid overwriting existing images
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        cb(null, `image_${Date.now()}${ext}`);
    }
});

// disk storage configuration used when uploading images to an existing item's folder during item update
const itemStorage = multer.diskStorage({
    destination: (req, file, cb) => {

        const itemId = req.params.id;

        // mirror the same folder structure as above
        const itemPath = path.join(__dirname, 'uploads', 'items', String(itemId));

        // create folder if it doesn't exist
        if (!fs.existsSync(itemPath)) {
            fs.mkdirSync(itemPath, { recursive: true });
        }

        cb(null, itemPath);
    },

    // generate filename using both timestamp and random string
    filename: (req, file, cb) => {
        const unique = `${Date.now()}_${Math.random().toString(36).slice(2)}`;
        cb(null, `image_${unique}${path.extname(file.originalname)}`);
    }
});

// uploadItem middleware using itemStorage configuration
const uploadItem = multer({ storage: itemStorage });


const fileFilter = (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|webp/; // enforce filetypes

    if (allowedTypes.test(file.mimetype)) {
        cb(null, true); // accept file
    } else {
        cb(new Error("Only image files allowed"), false); // reject invalid uploaded file
    }
};

// Multer config used when creating an item
// Images upload to temp folder since item ID does not exist yet at upload time
// Files are then moved to correct item folder once item has been inserted into DB
const upload = multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => {
            const tempDir = path.join(__dirname, 'uploads', 'temp');
            fs.mkdirSync(tempDir, { recursive: true }); // create temp folder
            cb(null, tempDir);
        },
        filename: (req, file, cb) => {
            cb(null, `temp_${Date.now()}_${Math.random().toString(36).slice(2)}${path.extname(file.originalname)}`); // unique temp filename to avoid overwriting between concurrent uploads
        }
    }),
    fileFilter, // apply filetype validation 
    limits: { fileSize: 2 * 1024 * 1024 } // enforce 2MB maximum file size
});

// middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.json());
app.use(cookieParser());


// session parsing
app.use(express.urlencoded({ extended: true }));
app.use(sessions({
    secret: "thisismysecretkey599",
    saveUninitialized: true,
    cookie: { maxAge: hour },
    resave: false
}));

// runs on request to check if logged-in user account is active in database - destroy session if account is not present
app.use((req, res, next) => {
    if (!req.session.user) return next();

    const sql = `SELECT user_id, is_active FROM users WHERE user_id = ?`;

    db.query(sql, [req.session.user.user_id], (err, rows) => {
        if (err || rows.length === 0 || rows[0].is_active === 0) {
            return req.session.destroy(() => {
                res.redirect('/');
            });
        }
        next();
    });
});

// enable user data across all EJS views - templates can access user data without needed to be passed in every route
app.use((req, res, next) => {
    res.locals.user = req.session.user || null;
    next();
});

// database configuration
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

// protect routes from unauthorised access - user must be logged in otherwise they are redirected to login page
function requireLogin(req, res, next) {
    if (!req.session.user) {
        return res.redirect('/');
    }
    next();
}

// allow route access to specific roles - accepts one or more allowed roles are arguments
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

// restricts access exclusively to the system administrator role
// used on sensitive admin routes such as user management and charity centre configuration
function requireSystemAdmin(req, res, next) {
    if (!req.session.user || req.session.user.role !== 'sys_admin') {
        return res.status(403).send("Access denied");
    }
    next();
}


// ----------routes--------------------------------------------------------------------------------------------------

// render login page on startup
app.get('/', (req, res) => {
    if (req.session.user) {
        return redirectByRole(req.session.user, res);
    }

    res.render('login', { error: null });
});

// process POST request when user submits details
app.post('/', (req, res) => {
    const { username_field, password_field } = req.body;

    const getUserSQL = `
            SELECT u.*, ca.charity_id
            FROM users u
            LEFT JOIN charity_admins ca ON u.user_id = ca.user_id
            WHERE u.username = ?
            `;

    db.query(getUserSQL, [username_field], (err, results) => {
        if (err) {
            return res.render('login', { error: 'Database error' });
        }

        if (results.length === 0) {
            return res.render('login', { error: 'Invalid username or password' });
        }

        const user = results[0];

        if (user.is_active === 0) {
            return res.render('login', { error: 'This account has been disabled' });
        }

        // match hashed password to password entered by user
        bcrypt.compare(password_field, user.password, (err, match) => {
            if (err) {
                return res.render('login', { error: 'Authentication error' });
            }

            if (!match) {
                return res.render('login', { error: 'Invalid username or password' });
            }

            // create session for user on successful login
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

// account creation page
app.get('/createaccount', (req, res) => {
    res.render('createaccount');
});

// process POST request when user submits account creation
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

        // Password hashing
        const plainPassword = password_field;

        bcrypt.hash(plainPassword, SALT_ROUNDS, (err, hashedPassword) => {
            if (err) return res.send("Error securing password");

            const insertUsersSQL = `
                INSERT INTO users
                (firstname, surname, username, password, role, phone, address, postcode)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            `;

            // insert user into DB
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

// api endpoint for live username availability check during live account creation
app.get('/api/check-username', (req, res) => {

    // set username to lowercase and trim whitespace - ensures check is case-insensitive and not affected by
    // accidental spaces at the end of the username input
    const username = (req.query.username || '').toLowerCase().trim();

    // return unavailable username warning if username string is empty
    if (!username) {
        return res.json({ available: false });
    }

    // database query to check whether username already exists
    const sql = `SELECT user_id FROM users WHERE username = ?`;

    db.query(sql, [username], (err, results) => {

        // failsafe if query fails
        if (err) return res.json({ available: false });

        // return true if no matching username found, false if username taken
        res.json({
            available: results.length === 0
        });
    });
});

// landing page
app.get("/homepage", requireLogin, (req, res) => {
    const user = req.session.user || null;

    // recently delivered items
    const deliveredSQL = `
        SELECT ci.item_id, ci.title, ii.filename
        FROM clothing_items ci
        LEFT JOIN item_images ii ON ci.item_id = ii.item_id
        WHERE ci.status = 'delivered'
        GROUP BY ci.item_id
        LIMIT 6
    `;

    // featured available items
    const featuredSQL = `
        SELECT ci.item_id, ci.title, ci.description, ii.filename
        FROM clothing_items ci
        LEFT JOIN item_images ii ON ci.item_id = ii.item_id
        WHERE ci.status = 'approved'
        GROUP BY ci.item_id
        ORDER BY ci.created_at DESC
        LIMIT 6
    `;

    db.query(deliveredSQL, (err, deliveredItems) => {
        if (err) {
            console.error(err);
            return res.send("Error loading delivered items");
        }

        db.query(featuredSQL, (err, featuredItems) => {
            if (err) {
                console.error(err);
                return res.send("Error loading featured items");
            }

            res.render('homepage', {
                user,
                deliveredItems,
                featuredItems
            });
        });
    });
});

// page for successful account creation
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

// update user role in admin dashboard
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

                // If promoted to charity_admin
                if (role === 'charity_admin' && currentRole !== 'charity_admin') {

                    // insert promoted user into charity_admins table
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

                    // remove user from charity_admins table if demoted
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

// disable or enable accounts in dashboard
app.post('/admin/toggle-user',
    requireLogin,
    requireSystemAdmin,
    (req, res) => {

        const { user_id } = req.body;

        // prevent admin accounts from being disabled
        const protectSQL = `
            SELECT role FROM users WHERE user_id = ?`;

        db.query(protectSQL, [user_id], (err, rows) => {
            if (rows[0].role === 'sys_admin') {
                return res.send("System admin cannot be disabled");
            }

            // update users to active/inactive accounts
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

// dashboard for charity admin
app.get('/admin/charitydashboard',
    requireLogin,
    requireRole('sys_admin', 'charity_admin'), // restricted to system admin and charity admin
    (req, res) => {
        const userId = req.session.user.user_id;

        // look for charity that charity admin is assigned to
        const charitySQL = `SELECT charity_id FROM charity_admins WHERE user_id = ?`;

        db.query(charitySQL, [userId], (err, charityResult) => {

            // deny access if no charity assigned
            if (err || charityResult.length === 0 || !charityResult[0].charity_id) {
                return res.send("No charity assigned");
            }

            const charityId = charityResult[0].charity_id;

            // fetch non-deleted items belonging to charity
            // retrieves first image for each item to display on dashboard
            // ordered by most recently created
            const itemsSQL = `
                SELECT ci.*,
                    (SELECT filename FROM item_images WHERE item_id = ci.item_id LIMIT 1) AS image
                FROM clothing_items ci
                WHERE ci.charity_id = ? AND ci.status != 'deleted'
                ORDER BY ci.created_at DESC
            `;

            // Count pending donation requests from donors
            const pendingSQL = `
                SELECT COUNT(*) AS count
                FROM clothing_items
                WHERE charity_id = ? AND status = 'assigned'
            `;

            // count items with pending request status - count total shows in sidebar navigation for charity dashboard
            const pendingRecipientRequestsSQL = `
                SELECT COUNT(*) AS count
                FROM item_requests ir
                JOIN clothing_items ci ON ir.item_id = ci.item_id
                WHERE ci.charity_id = ?
                AND ir.status = 'pending'
            `;

            db.query(itemsSQL, [charityId], (err, items) => {
                if (err) return res.send("Error loading items");

                db.query(pendingSQL, [charityId], (err, pendingResult) => {
                    if (err) return res.send("Error loading pending count");

                    const pendingDonations = pendingResult[0].count;

                    db.query(pendingRecipientRequestsSQL, [charityId], (err, pendingRequestsResult) => {
                        if (err) return res.send("Error loading pending requests count");
                        const pendingRecipientRequests = pendingRequestsResult[0].count;

                        // pass items list, current session user and pending donations + recipient requests count for sidebar
                        res.render('admin/charitydashboard', {
                            items,
                            user: req.session.user,
                            pendingDonations,
                            pendingRecipientRequests });
                    });
                });
            });
        });
    }
);

// approve a recipient's request for a clothing item
app.post('/admin/charitydashboard/:id/approve',
    requireLogin,
    requireRole('sys_admin', 'charity_admin'),
    (req, res) => {

        const requestId = req.params.id;
        const userId = req.session.user.user_id;

        // check which charity this admin is assigned to
        const charitySQL = `
            SELECT charity_id
            FROM charity_admins
            WHERE user_id = ?
        `;

        db.query(charitySQL, [userId], (err, charityResult) => {

            if (err || charityResult.length === 0)
                return res.send("No charity assigned");

            const charityId = charityResult[0].charity_id;

            // verify the recipient request belongs to an item assigned to this charity
            // prevents charity admins from approving requests from other charities
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

                // mark request as approved
                const approveSQL = `
                    UPDATE item_requests
                    SET status = 'approved'
                    WHERE request_id = ?
                `;

                db.query(approveSQL, [requestId], err => {
                    if (err) return res.send("Approval failed");

                    // automatically reject all other requests for the same item - only one recipient can receive an item
                    const rejectOthersSQL = `
                        UPDATE item_requests
                        SET status = 'rejected'
                        WHERE item_id = ?
                        AND request_id != ?
                        AND status = 'pending'
                    `;

                    db.query(rejectOthersSQL, [itemId, requestId], err => {
                        if (err) return res.send("Failed rejecting others");

                        // update clothing item status to allocated - donor's item has been allocated to recipient and can now be sent physically to charity
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

// reject recipient's request for an item
app.post('/admin/charitydashboard/:id/reject',
    requireLogin,
    requireRole('sys_admin', 'charity_admin'),
    (req, res) => {

        const requestId = req.params.id;
        const userId = req.session.user.user_id;

        // check which charity this admin is assigned to
        const charitySQL = `
            SELECT charity_id
            FROM charity_admins
            WHERE user_id = ?
        `;

        db.query(charitySQL, [userId], (err, charityResult) => {

            if (err || charityResult.length === 0)
                return res.send("No charity assigned");

            const charityId = charityResult[0].charity_id;

            // mark request as rejected - item remains available
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

// view clothing requests from recipients
app.get('/admin/recipientrequests',
    requireLogin,
    requireRole('sys_admin', 'charity_admin'),
    (req, res) => {

        const userId = req.session.user.user_id;

        // check which charity this admin is assigned to
        const charitySQL = `
            SELECT charity_id
            FROM charity_admins
            WHERE user_id = ?
        `;

        db.query(charitySQL, [userId], (err, charityResult) => {
            if (err || charityResult.length === 0) {
                return res.send("Error loading charity");
            }

            const charityId = charityResult[0].charity_id;

            // fetch all item requests for clothing items belonging to this charity
            // join item_requests with clothing_items to display item details and with users to get requester's username
            // retrieves first image for each item for display
            const requestsSQL = `
                SELECT 
                    ir.request_id,
                    ir.status,
                    ir.requested_at,
                    ci.title,
                    ci.status AS item_status,
                    u.username AS requester,
                    (SELECT filename FROM item_images WHERE item_id = ci.item_id LIMIT 1) AS image
                FROM item_requests ir
                JOIN clothing_items ci ON ir.item_id = ci.item_id
                JOIN users u ON ir.requester_id = u.user_id
                WHERE ci.charity_id = ?
            `;
    
            // count items with assigned status - count total shows in sidebar navigation for charity dashboard
            const pendingDonationsSQL = `
                SELECT COUNT(*) AS count
                FROM clothing_items
                WHERE charity_id = ? AND status = 'assigned'
            `;

            // count items with pending request status - count total shows in sidebar navigation for charity dashboard
            const pendingRecipientRequestsSQL = `
                SELECT COUNT(*) AS count
                FROM item_requests ir
                JOIN clothing_items ci ON ir.item_id = ci.item_id
                WHERE ci.charity_id = ?
                AND ir.status = 'pending'
            `;

            db.query(requestsSQL, [charityId], (err, requests) => {
                if (err) return res.send("Error loading requests");

                    db.query(pendingDonationsSQL, [charityId], (err, pendingResult) => {
                        if (err) return res.send("Error loading pending count");

                        const pendingDonations = pendingResult[0].count;

                        db.query(pendingRecipientRequestsSQL, [charityId], (err, pendingRequestsResult) => {
                            if (err) return res.send("Error loading pending requests count");

                            const pendingRecipientRequests = pendingRequestsResult[0].count;

                        // pass items list, current session user and pending donations + recipient requests count for sidebar
                        res.render('admin/recipientrequests', { 
                            requests, 
                            user: req.session.user, 
                            pendingDonations,
                            pendingRecipientRequests });
                    });        
                });
            });
        });
    }
);

// List all available items (with search + pagination)
app.get('/items', (req, res) => {

    // extract userId from session if logged in - null if not logged in
    const userId = req.session.user ? req.session.user.user_id : null; 

    // search, filter, sort and pagination parameters from query string
    // default values set for each parameter to handle requests with no filters
    const {
        search = '',
        category = '',
        size = '',
        condition = '',
        sort = '',
        page = 1
    } = req.query;

    // limit 8 items per page and calculate offset based on current page
    const limit = 8;
    const offset = (page - 1) * limit;

    // base SQL query shared between count and data query
    // only returns items with approved status - items in other states are not visible to users
    let baseSQL = `
            FROM clothing_items
            JOIN users ON clothing_items.user_id = users.user_id
            LEFT JOIN charity_centres ON clothing_items.charity_id = charity_centres.charity_id
            WHERE clothing_items.status = 'approved'
        `;

    const params = [];

    // update search filter if a search term was provided
    // searches across item title and description using LIKE
    if (search) {
        baseSQL += ` AND (clothing_items.title LIKE ? OR clothing_items.description LIKE ?)`;
        params.push(`%${search}%`, `%${search}%`);
    }

    // update category filter if selected
    if (category) {
        baseSQL += ` AND clothing_items.category = ?`;
        params.push(category);
    }

    // update size filter if selected
    if (size) {
        baseSQL += ` AND clothing_items.size = ?`;
        params.push(size);
    }

    // update condition filter if selected
    if (condition) {
        baseSQL += ` AND clothing_items.condition_desc = ?`;
        params.push(condition);
    }

    // default sort is newest first - this is overridden if oldest/alphabetical sort is selected
    let orderBy = ` ORDER BY clothing_items.created_at DESC`;

    if (sort === 'oldest') {
        orderBy = ` ORDER BY clothing_items.created_at ASC`;
    } else if (sort === 'az') {
        orderBy = ` ORDER BY clothing_items.title ASC`;
    }

    // full data query which selects item details along with current user's request status for each item via subquery - enables UI to show correct state for action button 
    // per item for logged in user
    // (Request Item, Request Pending, Request Approved etc.)
    const dataSQL = `
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
                charity_centres.charity_name,
                users.username,

                (
                    SELECT status
                    FROM item_requests
                    WHERE item_requests.item_id = clothing_items.item_id
                    AND item_requests.requester_id = ?
                    LIMIT 1
                ) AS request_status

            ${baseSQL}
            ${orderBy}
            LIMIT ? OFFSET ?
        `;

    const dataParams = [userId, ...params, limit, offset];

    db.query(dataSQL, dataParams, (err, items) => {
        if (err) {
            console.error(err);
            return res.send("Error loading items");
        }

        // separate count query using same filters but without LIMIT or OFFSET
        // calculates total number of matching items for pagination
        const countSQL = `SELECT COUNT(*) AS total ${baseSQL}`;

        db.query(countSQL, params, (err, countResult) => {

            if (err) {
                console.error(err);
                return res.send("Error counting items");
            }

            const totalItems = countResult[0].total;
            const totalPages = Math.ceil(totalItems / limit);

            // fetch all item images and build map of itemId -> [filenames] - multiple imagees can be attached to each item
            const imageSQL = `
                SELECT item_id, filename
                FROM item_images
            `;

            db.query(imageSQL, (err, images) => {

                if (err) {
                    console.error(err);
                    return res.send("Error loading images");
                }

                // build image map - group filenames by item_id
                const imageMap = {};

                images.forEach(img => {
                    if (!imageMap[img.item_id]) {
                        imageMap[img.item_id] = [];
                    }
                    imageMap[img.item_id].push(img.filename);
                });

                // attach images array to each item before passing to view
                items.forEach(item => {
                    item.images = imageMap[item.item_id] || [];
                });

                // pass all items, active filters and pagination data
                res.render('items/index', {
                    items,
                    search,
                    category,
                    size,
                    condition,
                    sort,
                    currentPage: parseInt(page),
                    totalPages,
                });
            });
        });
    });
});

// API endpoint for live search and filtering on index page
// uses client-side call fetch() as user types or changes filters
// returns JSON instead of view, allowing update of page without full reload
app.get('/api/items', (req, res) => {

    const userId = req.session.user ? req.session.user.user_id : null;

    // search, filter, sort and pagination parameters from query string
    // default values are set to handle requests without filters
    const {
        search = '',
        category = '',
        size = '',
        condition = '',
        sort = '',
        page = 1
    } = req.query;

    // limit 8 items per page and calculate offset based on current page
    const limit = 8;
    const offset = (page - 1) * limit;

    // trim whitespace from search term to avoid empty-string matches
    const cleanSearch = (search || '').trim();

    // base SQL shared between count and data query
    // returns items with approved status
    let baseSQL = `
        FROM clothing_items
        JOIN users ON clothing_items.user_id = users.user_id
        LEFT JOIN charity_centres ON clothing_items.charity_id = charity_centres.charity_id
        WHERE clothing_items.status = 'approved'
    `;

    const params = [];

    // update search filter if search term provided
    // searches both title and description using LIKE
    if (cleanSearch) {
        baseSQL += ` AND (clothing_items.title LIKE ? OR clothing_items.description LIKE ?)`;
        params.push(`%${cleanSearch}%`, `%${cleanSearch}%`);
    }

    // update category filter if selected
    if (category) {
        baseSQL += ` AND clothing_items.category = ?`;
        params.push(category);
    }

    // update size filter if selected
    if (size) {
        baseSQL += ` AND clothing_items.size = ?`;
        params.push(size);
    }

    // update condition filter if selected
    if (condition) {
        baseSQL += ` AND clothing_items.condition_desc = ?`;
        params.push(condition);
    }

    // run the count query first using same filters but no LIMIT or OFFSET
    // determines total number of matching items for pagination
    db.query(`SELECT COUNT(*) AS total ${baseSQL}`, params, (err, countResult) => {

        const total = countResult[0].total;

        // full data query which includes current user's request status for each item via subquery
        // allows rendering of correct button state per item (Request, Pending, Approved etc.)
        let sql = `
            SELECT 
            clothing_items.*, 
            users.username, 
            charity_centres.charity_name,
            clothing_items.user_id AS owner_id,
            (SELECT status FROM item_requests 
             WHERE item_id = clothing_items.item_id 
             AND requester_id = ? LIMIT 1) AS request_status
        ${baseSQL}
        `;

        // update sort order - defaults to newest first if no other option is selected
        if (sort === 'oldest') {
            sql += ` ORDER BY created_at ASC`;
        } else if (sort === 'az') {
            sql += ` ORDER BY title ASC`;
        } else {
            sql += ` ORDER BY created_at DESC`;
        }

        // pagination constraints
        sql += ` LIMIT ? OFFSET ?`;

        db.query(sql, [userId, ...params, limit, offset], (err, items) => {
            if (err) {
                console.error("SQL Error:", err);
                return res.status(500).json({ error: "Database error" });
            }

            const imageSQL = `SELECT item_id, filename FROM item_images`;

            db.query(imageSQL, (err, images) => {

                // build image map and group filenames by item_id
                const imageMap = {};

                images.forEach(img => {
                    if (!imageMap[img.item_id]) imageMap[img.item_id] = [];
                    imageMap[img.item_id].push(img.filename);
                });

                // attach images array to each item
                items.forEach(item => {
                    item.images = imageMap[item.item_id] || [];
                });

                // return items and pagination as JSON
                // currentUserID is included so client can identify which items belong to currently logged-in user and render correct button states
                res.json({
                    items,
                    total,
                    totalPages: Math.ceil(total / limit),
                    currentPage: parseInt(page),
                    currentUserId: userId
                });
            });
        });
    });
});

// item creation page
app.get('/items/new',
    requireLogin,
    requireRole('donor'),
    (req, res) => {

        // check for active charity_centres for dropdown
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

            // pass returned active charity centres
            res.render('items/new', { charities });
        });
    }
);


// create new clothing item and insert into DB
app.post('/items',
    requireLogin,
    (req, res, next) => {

        // run multer upload middleware to handle image files
        // maximum 5 images allowed - returns error if limit is exceeded
        upload.array('images', 5)(req, res, (err) => {
            if (err) {
                if (err.code === 'LIMIT_UNEXPECTED_FILE' || err.message?.includes('Unexpected field')) {
                    return res.send("Maximum 5 images allowed.");
                }
                return res.send("Upload error: " + err.message);
            }
            next();
        });
    },
    (req, res) => {

        // extract item details from submitted form
        const {
            title,
            description,
            category,
            size,
            condition_desc,
            charity_id
        } = req.body;

        // retrieve uploaded image files - defaults to empty array if none uploaded
        const images = req.files || [];

        // determine initial status of item based on whether or not charity was selected from dropdown
        // charity selected = assigned, no charity selected = unassigned
        const assignment = determineInitialStatus(charity_id);

        // insert new clothing item into DB
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

                // retrieve auto-generated item ID from insert
                const itemId = result.insertId;

                // if no images uploaded, redirect immediately back to donor listings page
                if (images.length === 0) {
                    return res.redirect('/items/my');
                }

                // create permanent folder for item's images using its ID
                // images were initially uploaded to temp folder - item ID did not exist at upload time - now moved to correct location
                const itemDir = path.join(__dirname, 'uploads', 'items', String(itemId));
                fs.mkdirSync(itemDir, { recursive: true });

                const values = [];

                // move each image from temp folder to item's permanent folder
                // build values array for DB insert
                for (const file of images) {
                    const newFilename = `image_${Date.now()}_${Math.random().toString(36).slice(2)}.jpg`;
                    const newPath = path.join(itemDir, newFilename);

                    try {
                        fs.renameSync(file.path, newPath);
                        values.push([itemId, `items/${itemId}/${newFilename}`]);
                    } catch (moveErr) {
                        console.error("Failed to move file:", moveErr);
                    }
                }

                // if all file moves failed, redirect back to donor listings page without inserting images
                if (values.length === 0) {
                    return res.redirect('/items/my');
                }

                // insert all image filenames into item_images table - each image linked to newly created item
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
            }
        );
    }
);

// page for listing every clothing item uploaded by donor
app.get('/items/my',
    requireLogin,
    requireRole('donor', 'sys_admin'),
    (req, res) => {

        // fetch all items not deleted and belonging to current donor
        // left join on charity_centres to include charity name if item is assigned
        // ordered by newly created first
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
            if (err) {
                console.error(err);
                return res.send("Error");
            }

            // fetch all images for item to build image map
            // separate query is used rather than a JOIN to avoid duplicating item rows if an item has multiple images
            const imageSQL = `
                SELECT item_id, filename
                FROM item_images
            `;

            db.query(imageSQL, (err, images) => {

                // build a map of item_id -> [filenames] to group images by item
                const imageMap = {};

                images.forEach(img => {
                    if (!imageMap[img.item_id]) {
                        imageMap[img.item_id] = [];
                    }
                    imageMap[img.item_id].push(img.filename);
                });

                // attach images array to each item
                items.forEach(item => {
                    item.images = imageMap[item.item_id] || [];
                });

                // pass items list and donorCanDelete function so the view can show delete button based on item's status
                res.render('items/my', {
                    items,
                    donorCanDelete
                });
            });
        });
    }
);

// list donor items not assigned to charities
app.get('/items/unassigned',
    requireLogin,
    requireRole('donor', 'sys_admin'),
    (req, res) => {

        // return items belonging to donor that are not assigned
        const sql = `
            SELECT *
            FROM clothing_items
            WHERE user_id = ?
            AND status = 'unassigned'
        `;

        db.query(sql, [req.session.user.user_id], (err, items) => {
            if (err) return res.send("Error loading items");

            // render unassigned page with unassigned items passed through
            res.render('items/unassigned', { items });
        });
    }
);

// list donor items that are allocated to recipients and can be sent to charity
app.get('/items/to-send',
    requireLogin,
    requireRole('donor', 'sys_admin'),
    (req, res) => {

        const userId = req.session.user.user_id;

        // return all items belonging to currently logged in donor with allocated status
        // retrives charity's contact details so donor knows where to send item
        const sql = `
                SELECT 
                    ci.*,
                    cc.charity_name,
                    cc.charity_address,
                    cc.charity_postcode,
                    cc.charity_email,
                    cc.charity_phone
                FROM clothing_items ci
                LEFT JOIN charity_centres cc 
                    ON ci.charity_id = cc.charity_id
                WHERE ci.user_id = ?
                AND ci.status = 'allocated'
                ORDER BY ci.created_at DESC
            `;

        db.query(sql, [userId], (err, items) => {

            if (err) {
                console.error(err);
                return res.send("Error loading items");
            }

            // fetch image records and attach to respective items
            // separate query used to avoid duplicating item rows from JOIN
            db.query(`SELECT item_id, filename FROM item_images`, (err, images) => {

                // Build a map of item_id -> [filenames] to group images by item
                const imageMap = {};

                images.forEach(img => {
                    if (!imageMap[img.item_id]) {
                        imageMap[img.item_id] = [];
                    }
                    imageMap[img.item_id].push(img.filename);
                });

                // attach images array to each item
                items.forEach(item => {
                    item.images = imageMap[item.item_id] || [];
                });

                // render to-send list with list of allocated items + charity contact details
                res.render('items/to_send', { items });

            });

        });

    }
);

// assign charity to item that is currently in assigned/rejected state
// used on unassigned items page 
app.post('/items/:id/assign',
    requireLogin,
    (req, res) => {

        const itemId = req.params.id;
        const { charity_id } = req.body;

        // reject request if no charity was selected
        if (!charity_id) {
            return res.send("Charity required");
        }

        // verify the item exists and belongs to logged-in donor
        db.query(
            "SELECT status FROM clothing_items WHERE item_id = ? AND user_id = ?",
            [itemId, req.session.user.user_id],
            (err, rows) => {

                if (err || rows.length === 0)
                    return res.send("Item not found");

                const currentStatus = rows[0].status;

                // Only allow assignment from valid states
                // prevents donors from reassigning items in donation pipleline
                if (
                    currentStatus !== ITEM_STATUS.UNASSIGNED &&
                    currentStatus !== ITEM_STATUS.REJECTED
                ) {
                    return res.send("Cannot assign charity in current state");
                }

                // update item with selected charity and set status to assigned
                // item is then populated in charity dashboard incoming donations page for charity admin to review
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

// page showing donor's impact metrics - shows items successfully delivered to recipients + summary statistics of contributions
app.get('/items/impact',
    requireLogin,
    requireRole('donor', 'sys_admin'),
    (req, res) => {

        const userId = req.session.user.user_id;

        // return all delivered items belonging to donor
        // joins charity_centres to show which charity handled each items
        // joins item_requests to return delivery date for approved request
        // retrieves first image for each item for display
        // ordered by most recently delivered
        const sql = `
            SELECT
                ci.item_id,
                ci.title,
                ci.description,
                ci.category,
                ci.size,
                ci.condition_desc,
                ci.created_at,
                cc.charity_name,
                ir.requested_at AS delivered_at,
                (SELECT filename
                 FROM item_images
                 WHERE item_id = ci.item_id
                 LIMIT 1) AS image
            FROM clothing_items ci
            LEFT JOIN charity_centres cc ON ci.charity_id = cc.charity_id
            LEFT JOIN item_requests ir ON ci.item_id = ir.item_id
                AND ir.status = 'approved'
            WHERE ci.user_id = ?
            AND ci.status = 'delivered'
            ORDER BY ir.requested_at DESC
        `;

        db.query(sql, [userId], (err, items) => {
            if (err) {
                console.error(err);
                return res.send("Error loading impact data");
            }

            // calculate summary stats

            // total number of items successfully delivered to recipients
            const totalDelivered = items.length;

            // unique list of charities this donor has contributed to
            const charities = [...new Set(items.map(i => i.charity_name).filter(Boolean))];

            // breakdown of delivered items by category
            const categories = items.reduce((acc, item) => {
                acc[item.category] = (acc[item.category] || 0) + 1;
                return acc;
            }, {});

            // render impact view with delivered items list, summary stats and current session user passed through
            res.render('items/impact', {
                items,
                totalDelivered,
                charitiesCount: charities.length,
                categories,
                user: req.session.user
            });
        });
    }
);

// view full item details for a single item from the index
app.get('/items/:id', (req, res) => {

    const itemId = req.params.id;
    const userId = req.session.user ? req.session.user.user_id : null;

    // fetch full item's details along with donor's username (only visible to charity/sys admin) and charity name
    // retrieves current user's request status for selected item via subquery for correct button state
    // excludes deleted items
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

        // fetch all images for selected item
        const imageSQL = `
            SELECT filename
            FROM item_images
            WHERE item_id = ?
        `;

        db.query(imageSQL, [itemId], (err, images) => {

            if (err) return res.send("Error loading images");

            // attach image filenames array to item object before passing to view
            item.images = images.map(img => img.filename);

            // render single item view, passing item data and current session user
            res.render('items/show', { item, user: req.session.user });
        });

    });
});

// edit form for item
// handles two separate flows based on user's role
// donors edit their own items, charity admins edit items only when received from donors
app.get('/items/:id/edit', 
    requireLogin, 
    requireRole('donor', 'sys_admin', 'charity_admin'), 
    (req, res) => {

    const itemId = req.params.id;
    const user = req.session.user;

    // check which charity this admin is assigned to
    const charitySQL = `
        SELECT charity_id
        FROM charity_admins
        WHERE user_id = ?
    `;

    // retrieve active charity centres for charity assignment dropdown
    const centresSQL = `
        SELECT charity_id, charity_name 
        FROM charity_centres
        WHERE is_active = 1
        ORDER BY charity_name
    `;

    // DONOR FLOW
    // donors can only edit their items that have not been deleted
    // editing level depends on item status - determined by donorCanFullyEdit and donorCanChangeCharity functions
    if (user.role === 'donor') {

        // check if item belongs to donor and has not been deleted
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

            // fetch all images belonging to item for display in the edit form
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

                    // pass item and edit permission flags based on item's current status - allows template to enable/disable appropriate fields
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
    // charity admins can only edit items that belong to their charity i.e. received from donor
    else if (user.role === 'charity_admin') {

        db.query(charitySQL, [user.user_id], (err, result) => {

            if (err || result.length === 0) {
                return res.send("No charity assigned");
            }

            const charityId = result[0].charity_id;

            // check the item belongs to this charity and has received status
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

                // fetch images associated with this item for display in edit form
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

                        // render edit form with charity permissions - charity admins cannot change charity assignment
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

// update clothing item after editing
// handles two separate flows depending on user's role
// runs uploadItem middleware to process newly uploaded images
app.post('/items/:id',
    requireLogin,
    (req, res, next) => {

        // process newly uploaded images before main handler runs
        // accepts up to 5 images
        uploadItem.array('images', 5)(req, res, (err) => {
            if (err) {
                if (err.code === 'LIMIT_UNEXPECTED_FILE' || err.message?.includes('Unexpected field')) {
                    return res.send("Maximum 5 images allowed.");
                }
                return res.send("Upload error: " + err.message);
            }
            next();
        });
    },
    (req, res) => {

        const itemId = req.params.id;
        const user = req.session.user;

        // extract updated item details from submitted form
        const {
            title,
            description,
            category,
            size,
            condition_desc,
            charity_id
        } = req.body;

        // retrieve newly uploaded image files - defaults to empty array if none
        const newImages = req.files || [];

        // DONOR FLOW
        // donors can edit their own items with varying levels of access depending on item's current status
        if (user.role === 'donor') {

            const userId = user.user_id;

            // fetch item's current status + charity assignment - determines what level of editing is permitted
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

                    // determine what the item's new status should be after changes are made
                    // e.g. if charity has changed, status needs reset to assigned
                    const newStatus = determineStatusAfterEdit(
                        currentStatus,
                        'donor',
                        oldCharityId,
                        newCharityId
                    );

                    let updateSQL;
                    let params;

                    // if donor has full edit access based on matched item status, update all item fields
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

                    // if donor can only change charity assignment, update only charity_id and reassign status
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

                    // if item is in a state where it cannot be edited e.g. received by charity, reject request
                    else {
                        return res.send("This item can no longer be edited.");
                    }

                    db.query(updateSQL, params, err => {

                        if (err) return res.send("Update failed");

                        // if new images were uploaded, insert filenames into item_images table record linked to this item
                        if (newImages.length > 0) {
                            const values = newImages.map(file => [
                                itemId,
                                `items/${itemId}/${file.filename}`
                            ]);

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

                        // redirect back to donor's listings page after saving changes
                        res.redirect('/items/my');
                    });
                }
            );
        }

        // CHARITY ADMIN FLOW
        // charity admin can only edit items belonging to their charity i.e. received from donor
        else if (user.role === 'charity_admin') {

            // check which charity this admin is assigned to
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

                // verify the item belongs to charity before updating
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

                        // check if item is in an editable state for charity admins
                        if (!charityAdminCanEdit(currentStatus)) {
                            return res.send("Not allowed");
                        }

                        // charity admins cannot change charity assignment
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

                                // if new images were uploaded, insert filenames into item_images table record linked to this item
                                if (newImages.length > 0) {
                                    const values = newImages.map(file => [
                                        itemId,
                                        `items/${itemId}/${file.filename}`
                                    ]);

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

                                // redirect back to charity dashboard after saving
                                res.redirect('/admin/charitydashboard');
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

// delete clothing item
// items not permanently removed from DB - status is set to deleted so records are preserved for auditing purposes
app.post('/items/:id/delete',
    requireLogin,
    (req, res) => {

        const itemId = req.params.id;
        const userId = req.session.user.user_id;

        // verify item exists and belongs to logged-in donor
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

            // check whether item is in a state that permits deletion
            // items already in progress through donation pipeline cannot be deleted by donor e.g. received by charity
            if (!deleteItem(status, 'donor')) {
                return res.send("This item can no longer be deleted.");
            }

            // update item's status to deleted and rather than deleting record entirely
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

                // redirect to donor's lsitings page after deletion
                res.redirect('/items/my');

            });

        });

    });

// delete item image belonging to clothing item when editing
// called client-side via fetch() when the donor or charity admin clicks the delete button on an image
app.post('/items/:id/images/delete',
    requireLogin,
    (req, res) => {

        const itemId = req.params.id;
        const { filename } = req.body;
        const user = req.session.user;

        // fetch item's owner to verify requesting user has permission to delete images
        db.query(
            `SELECT user_id FROM clothing_items WHERE item_id = ?`,
            [itemId],
            (err, rows) => {

                if (err || rows.length === 0) {
                    return res.send("Item not found");
                }

                // only allow deletion if user owns the item or is a charity admin
                // prevents users from deleting images belonging to other donors' items
                if (rows[0].user_id !== user.user_id && user.role !== 'charity_admin') {
                    return res.status(403).send("Unauthorized");
                }

                // remove image from DB
                db.query(
                    `DELETE FROM item_images WHERE item_id = ? AND filename = ?`,
                    [itemId, filename],
                    err => {

                        if (err) {
                            console.error(err);
                            return res.send("Failed to delete image");
                        }

                        // delete file from disk
                        const filePath = path.join(__dirname, 'uploads', filename);

                        if (fs.existsSync(filePath)) {
                            fs.unlink(filePath, err => {
                                if (err) console.error("File delete error:", err);
                            });
                        } else {
                            // log warning if file was not found in disk
                            // can happen if the file was manually removed from backend or not saved correctly
                            console.warn("File not found:", filePath);
                        }

                        // Return a 200 OK response so the client-side JS can remove the image preview from the UI without need for a page reload
                        res.sendStatus(200);
                    }
                );
            }
        );
    });

// submit recipient's request for clothing item through index/ single item view page
app.post('/requests',
    requireLogin,
    (req, res) => {

        const { item_id } = req.body;

        // check whether user has already submitted a request for this item - prevent duplicate requests
        const checkSQL = `
            SELECT * FROM item_requests
            WHERE item_id = ? AND requester_id = ?
        `;

        db.query(checkSQL, [item_id, req.session.user.user_id], (err, rows) => {

            // reject if already requsted
            if (rows.length > 0) {
                return res.send("You have already requested this item");
            }

            // insert new request into item_requests table - status defaults to 'pending' and will be reviewed by charity admin
            // via recipient requests page
            const insertSQL = `
                INSERT INTO item_requests (item_id, requester_id)
                VALUES (?, ?)
            `;

            db.query(insertSQL, [item_id, req.session.user.user_id], err => {
                if (err) {
                    console.error(err);
                    return res.send("Request failed");
                }

                // redirect to item index page after submitting a request
                res.redirect('/items');
            });
        });
    }
);

// view all requests for currently logged-in recipient
app.get('/requests/my',
    requireLogin,
    (req, res) => {


        // fetch all requests made by this user
        // join on clothing_items to retrieve item details alongside request status
        // retrieves first image for each item for display
        // request status and item status are fetched separately
        // request status tracks charity's decision (pending, approved, rejected)
        // item status tracls where the item is in the donation pipeline (sent/delivered)
        const sql = `
            SELECT 
                item_requests.request_id,
                clothing_items.title,
                item_requests.status,
                clothing_items.status AS item_status,
                (SELECT filename FROM item_images WHERE item_id = clothing_items.item_id LIMIT 1) AS image,
                clothing_items.category,
                clothing_items.size,
                clothing_items.condition_desc
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

            // pass full list of request into recipient's request page
            res.render('requests/my', { requests });
        });
    }
);

// system admin only page to view all charity centres registered in the system
app.get('/admin/charity-centres',
    requireLogin,
    requireSystemAdmin,
    (req, res) => {

        // fetch all charity centres alongside username of assigned charity admin
        // left joins used so charity centres without assigned charity admin are still returned
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

        // fetch all active charity admins
        // used to populate assignment dropdown on charity centres page
        // left join with charity_centres to show which charity each admin is assigned to
        const adminsSQL = `
                SELECT 
                    u.user_id, 
                    u.username, 
                    ca.charity_id
                FROM users u
                LEFT JOIN charity_admins ca ON u.user_id = ca.user_id
                WHERE u.role = 'charity_admin'
                AND u.is_active = 1
            `;

        // fetch admins first then charities
        // both datasets passed to the view so the admin can manage charity centres and their assigned admins from the same page    
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

// get route for charity centre creation form for system admin
app.get('/admin/charity-centres/new',
    requireLogin,
    requireSystemAdmin,
    (req, res) => {
        res.render('admin/charity_centres/new', { user: req.session.user });
    }
);

// create new charity centres entry and insert into DB
app.post('/admin/charity-centres/new',
    requireLogin,
    requireSystemAdmin,
    (req, res) => {

        // extract charity centre details from submitted form
        const { charity_name, charity_address, charity_postcode, charity_email, charity_phone } = req.body;

        // validate that required fields are present before attempting insert
        // email and phone are optional but name, address and postcode are mandatory
        if (!charity_name || !charity_address || !charity_postcode) {
            return res.send("Required fields missing");
        }

        // insert the new charity centre into the database
        // is_active set to 1 by default so centre is immediately available for donors to assign items to
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

            // redirect back to chatiy centres management dashboard after successful creation
            res.redirect('/admin/charity-centres');
        });
    }
);

// view form to edit details for existing charity centre
app.get('/admin/charity-centres/:id/edit',
    requireLogin,
    requireSystemAdmin,
    (req, res) => {

        // fetch charity centre' current details using ID from URL params
        const sql = `SELECT * FROM charity_centres WHERE charity_id = ?`;
        db.query(sql, [req.params.id], (err, results) => {

            // return error if query fails or if no matching charity centre is found
            if (err || results.length === 0) return res.send("Charity centre not found");

            // pass charity centre's current details so form fields are pre-populated for system admin to update
            res.render('admin/charity_centres/edit', {
                centre: results[0],
                user: req.session.user
            });
        });
    }
);

// update existing centre's details
app.post('/admin/charity-centres/:id/edit/',
    requireLogin,
    requireSystemAdmin,
    (req, res) => {

        const charityId = req.params.id;

        // extract updated charity centre details from submitted form
        const {
            charity_name,
            charity_address,
            charity_postcode,
            charity_email,
            charity_phone,
            is_active
        } = req.body;

        // change is_active value from string to int
        // form values are always strings so '1' must be explicitly compared
        const activeValue = is_active === '1' ? 1 : 0;

        // update all charity centre fields within DB
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

                // If charity was deactivated — automatically remove assigned charity admin
                // prevents admin from managing a centre that is no longer operational
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

                        // redirect back to charity centres page after deactivation
                        return res.redirect('/admin/charity-centres');
                    });

                } else {

                    // redirect back to charity centres page after standard update
                    res.redirect('/admin/charity-centres');
                }

            }
        );
    }
);

// assign a charity admin to a specific charity centre
app.post('/admin/charity-centres/assign-admin',
    requireLogin,
    requireSystemAdmin,
    (req, res) => {

        const { charity_id, user_id } = req.body;

        // validate that both charity and user have been selected
        if (!charity_id || !user_id)
            return res.send("Invalid data");

        // remove any existing admin for this charity
        // ensures only one admin is assigned to a charity at any given time
        // previous admin's record is kept in charity_admins but charity_id set to NULL
        const removeExisting = `
            UPDATE charity_admins
            SET charity_id = NULL
            WHERE charity_id = ?
        `;

        db.query(removeExisting, [charity_id], err => {
            if (err) return res.send("Error removing previous admin");

            // assign new admin
            // updates charity_admins record for selected charity admin with chosen charity_id
            const assignAdmin = `
                UPDATE charity_admins
                SET charity_id = ?
                WHERE user_id = ?
            `;

            db.query(assignAdmin, [charity_id, user_id], err => {
                if (err) return res.send("Assignment failed");

                // redirect back to charity centre management page after assigning
                res.redirect('/admin/charity-centres');
            });
        });
    }
);

// remove a charity admin from a specific centre
app.post('/admin/charity-centres/remove-admin',
    requireLogin,
    requireSystemAdmin,
    (req, res) => {

        const { charity_id } = req.body;

        // validate that charity ID was provided
        if (!charity_id) {
            return res.send("Invalid request");
        }

        // set charity admin's charity_id to NULL in charity_admins table
        // role is preserved but charity associated is removed
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

            // redirect to charity centre management page after removing 
            res.redirect('/admin/charity-centres');
        });
    }
);

// display all incoming donation requests for charity
// shows items with assigned status i.e. donated by donors and awaiting approval
app.get('/admin/charity-items',
    requireLogin,
    requireRole('charity_admin', 'sys_admin'),
    (req, res) => {

        const userId = req.session.user.user_id;

        // check which charity this admin is assigned to
        const charitySQL = `
            SELECT charity_id
            FROM charity_admins
            WHERE user_id = ?
        `;

        db.query(charitySQL, [userId], (err, charityResult) => {
            if (err) return res.send("Error loading charity");

            // If the admin has no charity assigned, deny access
            if (charityResult.length === 0 || !charityResult[0].charity_id) {
                return res.send("No charity assigned");
            }

            const charityId = charityResult[0].charity_id;

            // return all items assigned to this charity with assigned status
            // i.e. donations submitted by donors awaiting charity's approval
            // retrieves donor's username and first image for each item
            const sql = `
                SELECT 
                    ci.*,
                    u.username AS donor,
                    (SELECT filename 
                     FROM item_images 
                     WHERE item_id = ci.item_id 
                     LIMIT 1) AS image
                FROM clothing_items ci
                JOIN users u ON ci.user_id = u.user_id
                WHERE ci.charity_id = ?
                AND ci.status = 'assigned'
            `;

            // count number of pending donation requests for sidebar badge
            const pendingSQL = `
                SELECT COUNT(*) AS count
                FROM clothing_items
                WHERE charity_id = ? AND status = 'assigned'
            `;

            // count items with pending request status - count total shows in sidebar navigation for charity dashboard
            const pendingRecipientRequestsSQL = `
                SELECT COUNT(*) AS count
                FROM item_requests ir
                JOIN clothing_items ci ON ir.item_id = ci.item_id
                WHERE ci.charity_id = ?
                AND ir.status = 'pending'
            `;

            db.query(sql, [charityId], (err, items) => {
                if (err) return res.send("Error loading items");

                db.query(pendingSQL, [charityId], (err, pendingResult) => {
                    if (err) return res.send("Error loading pending count");

                    const pendingDonations = pendingResult[0].count;

                    db.query(pendingRecipientRequestsSQL, [charityId], (err, pendingRequestsResult) => {
                        if (err) return res.send("Error loading pending requests count");
                        const pendingRecipientRequests = pendingRequestsResult[0].count;

                    // pass items list, current session user and pending donations + recipient requests count for sidebar
                    res.render('admin/charity_items', {
                        items,
                        user: req.session.user,
                        pendingDonations,
                        pendingRecipientRequests });
                    });
                });
            });
        });
    }
);

// approve incoming donation request from donors
// changes status to approved, making it visible to recipients on item index page
app.post('/admin/charity-items/:id/approve',
    requireLogin,
    requireRole('charity_admin', 'sys_admin'),
    (req, res) => {

        const itemId = req.params.id;
        const userId = req.session.user.user_id;

        // check which charity this admin belongs to
        const charitySQL = `
            SELECT charity_id
            FROM charity_admins
            WHERE user_id = ?
        `;

        db.query(charitySQL, [userId], (err, result) => {

            if (err || result.length === 0)
                return res.send("Charity not found");

            const charityId = result[0].charity_id;

            // update item's status to approved
            // WHERE clause ensures item belongs to this charity and is currently in assigned status
            // prevents charity admins from approving items belonging to other charities
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

// reject incoming donation requests from donors
// changes status to rejected and removes charity assignment for item
app.post('/admin/charity-items/:id/reject',
    requireLogin,
    requireRole('charity_admin', 'sys_admin'),
    (req, res) => {

        const itemId = req.params.id;
        const userId = req.session.user.user_id;

        // check which charity this admin belongs to
        const charitySQL = `
            SELECT charity_id
            FROM charity_admins
            WHERE user_id = ?
        `;

        db.query(charitySQL, [userId], (err, result) => {

            if (err || result.length === 0)
                return res.send("Charity not found");

            const charityId = result[0].charity_id;

            // update donated item's status to rejected 
            // sets charity assignment to NULL
            // donor has to reassign charity for submitted item
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

// display all items that are allocated to a recipient
// physically en route to charity
// donor needs to send item to the charity
app.get('/admin/incoming-items',
    requireLogin,
    requireRole('charity_admin', 'sys_admin'),
    (req, res) => {

        const userId = req.session.user.user_id;

        // check which charity this admin is assigned to
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

            // fetch all items belonging to this charity with allocated status
            // retrieves donor's username and first image for each item
            // ordered by most recently created
            const itemsSQL = `
                SELECT 
                    clothing_items.*, 
                    users.username AS donor,
                    (SELECT filename FROM item_images WHERE item_id = clothing_items.item_id LIMIT 1) AS image
                FROM clothing_items
                JOIN users ON clothing_items.user_id = users.user_id
                WHERE clothing_items.charity_id = ?
                AND clothing_items.status = 'allocated'
                ORDER BY clothing_items.created_at DESC
            `;

            // count items with assigned status to display pending donations on sidebar
            const pendingSQL = `
                SELECT COUNT(*) AS count
                FROM clothing_items
                WHERE charity_id = ? AND status = 'assigned'
            `;

            // count items with pending request status - count total shows in sidebar navigation for charity dashboard
            const pendingRecipientRequestsSQL = `
                SELECT COUNT(*) AS count
                FROM item_requests ir
                JOIN clothing_items ci ON ir.item_id = ci.item_id
                WHERE ci.charity_id = ?
                AND ir.status = 'pending'
            `;

            db.query(itemsSQL, [charityId], (err, items) => {
                if (err) return res.send("Error loading items");

                db.query(pendingSQL, [charityId], (err, pendingResult) => {
                    if (err) return res.send("Error loading pending count");

                    const pendingDonations = pendingResult[0].count;

                        db.query(pendingRecipientRequestsSQL, [charityId], (err, pendingRequestsResult) => {
                            if (err) return res.send("Error loading pending requests count");
                            const pendingRecipientRequests = pendingRequestsResult[0].count;

                    // pass items list, current session user and pending donations + recipient requests count for sidebar
                    res.render('admin/incoming_items', {
                        items,
                        user: req.session.user,
                        pendingDonations,
                        pendingRecipientRequests });
                    });
                });
            });
        });
    }
);

// display all items that have been received by the charity and are ready to be sent to their allocated recipient
app.get('/admin/items-to-send',
    requireLogin,
    requireRole('charity_admin', 'sys_admin'),
    (req, res) => {

        const userId = req.session.user.user_id;

        // check which charity this admin belongs to
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

            // fetch all received items belonging to this charity
            // join on item_requests to get the approved recipient's details
            // join on users to get the recipient's username and contact info
            // only fetches items with an approved request so recipient details are available
            const itemsSQL = `
                SELECT 
                    ci.*,
                    u_donor.username AS donor,
                    u_recipient.username AS recipient_username,
                    u_recipient.phone AS recipient_phone,
                    u_recipient.address AS recipient_address,
                    u_recipient.postcode AS recipient_postcode,
                    ir.request_id,
                    (SELECT filename FROM item_images WHERE item_id = ci.item_id LIMIT 1) AS image
                FROM clothing_items ci
                JOIN users u_donor ON ci.user_id = u_donor.user_id
                LEFT JOIN item_requests ir ON ci.item_id = ir.item_id
                    AND ir.status = 'approved'
                LEFT JOIN users u_recipient ON ir.requester_id = u_recipient.user_id
                WHERE ci.charity_id = ?
                AND ci.status = 'received'
                ORDER BY ci.created_at DESC
            `;

            // count pending donation requests for the sidebar badge
            const pendingSQL = `
                SELECT COUNT(*) AS count
                FROM clothing_items
                WHERE charity_id = ? AND status = 'assigned'
            `;

            // count pending recipient requests for the sidebar badge
            const pendingRequestsSQL = `
                SELECT COUNT(*) AS count
                FROM item_requests ir
                JOIN clothing_items ci ON ir.item_id = ci.item_id
                WHERE ci.charity_id = ?
                AND ir.status = 'pending'
            `;

            // count allocated items for the Items to Receive sidebar badge
            const allocatedSQL = `
                SELECT COUNT(*) AS count
                FROM clothing_items
                WHERE charity_id = ?
                AND status = 'allocated'
            `;

            db.query(itemsSQL, [charityId], (err, items) => {
                if (err) return res.send("Error loading items");

                db.query(pendingSQL, [charityId], (err, pendingResult) => {
                    if (err) return res.send("Error loading pending count");

                    const pendingDonations = pendingResult[0].count;

                    db.query(pendingRequestsSQL, [charityId], (err, pendingRequestsResult) => {
                        if (err) return res.send("Error loading pending requests count");

                        const pendingRecipientRequests = pendingRequestsResult[0].count;

                            // render items to send with all required sidebar counts
                            res.render('admin/items_to_send', {
                                items,
                                user: req.session.user,
                                pendingDonations,
                                pendingRecipientRequests,
                        });
                    });
                });
            });
        });
    }
);

// charity marks item as received
app.post('/admin/items/:id/received',
    requireLogin,
    requireRole('charity_admin', 'sys_admin'),
    (req, res) => {

        const itemId = req.params.id;

        // fetch item's current status before transition
        db.query(
            `SELECT status FROM clothing_items WHERE item_id = ?`,
            [itemId],
            (err, result) => {

                if (err || result.length === 0)
                    return res.send("Item not found");

                const currentStatus = result[0].status;

                // verify item is in a valid state to be marked as received
                // prevents invalid state transitions e.g. marking already delivered item as received
                if (!charityAdminCanMarkReceived(currentStatus)) {
                    return res.send("Not allowed");
                }

                // calculate new status - enforces item state machine
                const newStatus = transitionItem(currentStatus, 'received');

                // update item's status in DB and redirect to charity dashboard
                db.query(
                    `UPDATE clothing_items SET status = ? WHERE item_id = ?`,
                    [newStatus, itemId],
                    () => res.redirect('/admin/charitydashboard')
                );
            }
        );
    });

// charity marks item as sent to recipient
// i.e. charity confirms they have dispatched the item
app.post('/admin/items/:id/send',
    requireLogin,
    requireRole('charity_admin', 'sys_admin'),
    (req, res) => {

        const itemId = req.params.id;
        const userId = req.session.user.user_id;

        // check what charity this admin is assigned to
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

            // validate item belongs to charity AND is received before allowing status update
            // prevents charity admins from marking items belonging to other charities as sent
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

                // verify item has been marked as received before it can be sent - item must be physically at the charity before dispatch
                if (!charityAdminCanSend(currentStatus)) {
                    return res.send("Item must be received first");
                }

                // update item status to sent
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

// charity returns item
// e.g. if item was incorrectly marked as received
app.post('/admin/items/:id/return',
    requireLogin,
    requireRole('charity_admin', 'sys_admin'),
    (req, res) => {

        const itemId = req.params.id;

        // fetch item's current status
        db.query(
            `SELECT status FROM clothing_items WHERE item_id = ?`,
            [itemId],
            (err, result) => {

                const currentStatus = result[0].status;

                // verify item is in a valid state to be returned
                // prevents invalid state transition
                if (!charityAdminCanReturn(currentStatus)) {
                    return res.send("Not allowed");
                }

                // calculate new status - enforces item state machine
                const newStatus = transitionItem(currentStatus, 'returned');

                // update item's status in DB
                db.query(
                    `UPDATE clothing_items SET status = ? WHERE item_id = ?`,
                    [newStatus, itemId],
                    () => res.redirect('/admin/charitydashboard')
                );
            }
        );
    });

// recipient confirms they have received their item
app.post('/requests/:id/delivered',
    requireLogin,
    requireRole('recipient'),
    (req, res) => {

        const requestId = req.params.id;
        const userId = req.session.user.user_id;

        // fetch item linked to recipient's request
        // verifies request belongs to currently logged-in recipient
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

            // verify the item has been marked as sent before allowing delivery confirmation
            // ensures recipients cannot confirm delivery of items that have not yet been dispatched
            if (!recipientCanConfirm(status)) {
                return res.send("Item not sent yet");
            }

            // update item's status to delivered - completes donation pipeline
            // item then appears on donor's impact page
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

// recipient confirms they have never received their item
app.post('/requests/:id/never-arrived',
    requireLogin,
    requireRole('recipient'),
    (req, res) => {

        const requestId = req.params.id;
        const userId = req.session.user.user_id;

        // fetch item linked to recipient's request
        // verifies request belongs to currently logged-in recipient
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

            // verify the item has been marked as sent
            // recipients can only report non-arrival for items that have been dispatched
            if (status !== 'sent') {
                return res.send("Item not sent yet");
            }

            // update item's status to never_arrived
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

// destroy session on logging out
app.get('/logout', (req, res) => {
    req.session.destroy(() => {

        // redirect back to login page after destroyed session
        res.redirect('/');
    });
});

// server set to listen on localhost port 3000
app.listen(process.env.PORT || 3000);
console.log('Server is listening: localhost:3000/');