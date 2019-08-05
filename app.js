var express = require("express"); // This line calls the express framework to action.
var app = express(); // Invokes the express package into action.

var mysql = require("mysql"); // This line calls the sql middleware to action.

var flash = require('connect-flash'); // Uses a flash message system to notify the user about potential errors.
var passport = require('passport'); // This line calls passport to handle the logic of log-in and registration.

var LocalStrategy = require('passport-local').Strategy; // Node passport-local allows to store user details (username, email, password) in local database.
var localStorage = require('node-localstorage'); // Node local-storage handles the local storage data.
var session = require('express-session'); // The login is based on a session.
var cookieParser = require('cookie-parser'); // Cookie-parser to parse cookie information as required.

var bcrypt = require('bcrypt-nodejs'); // Bcrypt-nodejs is a password hashing function.

app.use(cookieParser()); // This line allows to read cookies (needed for authorization).


// The following lines are required for the proper functioning of the npm passport.
app.use(session({
    secret: 'secretdatakeythecommunitytree', // The session secret is a key used for signing and/or encrypting cookies set by the application to maintain session state.
    resave: true,
    saveUninitialized: true
    } )); // session secret
    app.use(passport.initialize());
    app.use(passport.session()); // Persistent login sessions.
    app.use(flash()); // Uses connect-flash for flash messages stored in session.


app.set("view engine", "ejs"); // Sets default view engine (we can save .html file as .ejs).

var fs= require('fs'); // Common use for the File System module: method is used to read files.

var bodyParser = require("body-parser"); // This module parses the JSON, buffer, string and URL encoded data submitted using HTTP POST request.
app.use(bodyParser.urlencoded({extended:true}));

const fileUpload = require('express-fileupload'); // This line calls the FileUpload middleware.
app.use(fileUpload());


var contact = require("./model/contact.json"); // This line declares the content of the contact.json file as a variable called contact 
var reviews = require("./model/reviews.json"); // This line declares the content of the reviews.json file as a variable called reviews
var report = require("./model/report.json"); // This line declares the content of the report.json file as a variable called report
var upgrade = require("./model/upgrade.json"); // This line declares the content of the upgrade.json file as a variable called upgrade


app.use(express.static("views")); // Calls the access to the views folder and allows content to be rendered.
app.use(express.static("styles")); // Calls the access to the styles folder with CSS and allows content to be rendered.
app.use(express.static("images")); // Calls the access to the images folder and allow content to be rendered.
app.use(express.static("images-upgrade")); // Calls the access to the images-upgrade folder and allow content to be rendered.


// ############################################################################################################
// -------------------------------------- Connectivity to MySQL database -------------------------------------
// ############################################################################################################

// Details for gear host database account:
const db = mysql.createConnection ({
    host: '###############',
    user: '###############',
    password: '###############',
    database: '###############'
});

// Informations about the connection status.
db.connect((err) => {
    if(err) {
        console.log("The connection failed...Please check gearhost account details")
   }
    else {
       console.log("Connection to db is correct.")
    }
});


// ########################################################################################################################################################  
// ------------------------------------------------------ ALL ROUTES TO DIFFERENT PAGES ---------------------------------------------------------------
// ########################################################################################################################################################  

// Root page (in this case, it is an index page).
app.get('/', function (req, res) { // This line calls a get request on the '/' url of our application.
    res.render("index")
    console.log("The HOME page has been displayed")  // This line adds a comment, that is displayed in the terminal.
});

app.get('/beHelp', function(req, res){  // Route to beHelp page (main information about this section).
    res.render("beHelp")
    console.log("The BEHELP page has been displayed") 
});

app.get('/needHelp', function(req, res){ // Route to needHelp page (main information about this section).
    res.render("needHelp")
    console.log("The NEEDHELP page has been displayed") 
});

app.get('/contact', function(req,res){ // Route to Contact page (contact form).
    res.render('contact', {
        contact
    });
    console.log("The CONTACT page has been displayed")
});

app.get('/review', function(req, res){ // Route to Review page (displays all reviews added by registered users).
    res.render('review', {
        reviews
    });
    console.log("The REVIEW page has been displayed")
});

app.get('/add-review', isLoggedIn, function(req, res){  // Add new review, only for registered users. Access from dashboard.
    res.render('add-review',  {
        user : req.user // gets the user out of session and pass to template
    });
    console.log("The ADD-REVIEW page has been displayed")
});

app.get('/edit-review', isLoggedIn, function(req, res){ // Edit review, only for registered users. Access from dashboard.
    res.render('edit-review')
    console.log("The EDIT-REVIEW page has been displayed")
});

app.get('/login', function(req, res){ // Route to LOGIN page.
    res.render("login", {
        message: req.flash('loginMessage') 
    });
    console.log("The LOGIN page has been displayed") 
});

app.get('/login-admin', function(req, res){ // Route to LOGIN page for Admin only.
    res.render("login-admin", {
        message: req.flash('loginMessage')
    });
    console.log("The LOGIN-ADMIN page has been displayed") 
});

app.get('/logout', function(req, res) { 
    req.logout();
    res.redirect('/');
    console.log("User logout from dashboard")
});

app.get('/user', isLoggedIn, function(req, res){ // User dashboard.
    res.render('user', {
        user : req.user // gets the user out of session and pass to template
    });
    console.log("The USER dashboard has been displayed") 
});

app.get('/admin', isLoggedIn, isAdmin, function(req, res,){ // Admin dashboard.
    res.render('admin', {
        reviews, 
        contact, 
        report, 
        upgrade,
        user : req.user 
    });
    console.log("The ADMIN dashboard has been displayed") 
});

app.get('/profile',  isLoggedIn, // List of all users, only for Admin.
 function(req, res) {
    res.render('profile', {
        user : req.user 
    });
});

app.get('/add-upgrade', isLoggedIn, function(req, res){ //Route to send the necessary documents to the admin to receive the 'trusted user' mark.
    res.render('add-upgrade', {
        user : req.user
    });
    console.log("The add-upgrade page has been displayed")
});

app.get('/send-message', isLoggedIn, function(req, res){ //Route to send messages between users.
    res.render('send-message',  {
        user : req.user
    });
    console.log("send-message")
});

app.get('/show-messages', isLoggedIn, function(req, res){ //Route to display all received messages.
    res.render('show-messages',  {
        user : req.user
    });
    console.log("show-messages")
});

app.get('/show-sent-messages', isLoggedIn, function(req, res){ //Route to display all sent messages.
    res.render('show-sent-messages',  {
        user : req.user
    });
    console.log("show-sent-messages")
});

app.get('/confirmation-contact', function(req,res){ //Confirmation that the message has been correctly sent (Contact Form).
    res.render('confirmation-contact');
    console.log("The CONFIRMATION CONTACT page has been displayed")
});

app.get('/confirmation-upgrade', function(req,res){ //Confirmation that the upgrade documents has been correctly sent (Upgrade Account in Dashboard panel).
    res.render('confirmation-upgrade');
    console.log("The CONFIRMATION UPGRADE page has been displayed")
});

app.get('/confirmation-report', function(req,res){ //Confirmation that the report has been correctly sent (Report in post pages)
    res.render('confirmation-report')
    console.log("The CONFIRMATION REPORT page has been displayed")
});



// ########################################################################################################################################################
// -------------------------------------------------------------------  REGISTRATION PROCESS  -------------------------------------------------------------
// ########################################################################################################################################################                                       
    
app.get('/registration', function(req, res){ 
    res.render("registration", { 
        message: req.flash('signupMessage') 
    });
    console.log("The registration page has been displayed.") 
});

// process the signup form
app.post('/registration', passport.authenticate('local-signup', {
    successRedirect : '/user', // Redirect to the user dashboard section.
    failureRedirect : '/registration', // Redirect back to the registration page if there is an error.
    failureFlash : true // This line allows flash messages.
}));

   
// Required for persistent login sessions (used to serialize the user for the session).
// Passport needs ability to serialize and unserialize users out of session.
passport.serializeUser(function(user, done) {
    done(null, user.Id); // Id from the database table must be the same as it is here.
    });
    // used to deserialize the
    passport.deserializeUser(function(Id, done) { 

// ===========================================================================================
// ================================= LOCAL REGISTRATION ======================================
// ===========================================================================================
    db.query("SELECT * FROM users WHERE Id = ? ",[Id], function(err, rows){
        done(err, rows[0]);
    });
});

// Uses strategies name - we have one for login and one for signup (by default, it is called 'local').
    passport.use(
    'local-signup',
    new LocalStrategy({
        // By default, local strategy uses username and password.
        usernameField : 'username',
        passwordField : 'password',
        passReqToCallback : true // Allows to pass back the entire request to the callback.
        },
    function(req, username, password, done) {

// Finds a user whose email is the same as the forms email
// and checks to see if the user trying to login already exists.
    db.query("SELECT * FROM users WHERE username = ?",[username], function(err, rows) {
        if (err)
        return done(err);
        if (rows.length) {
            return done(null, false, req.flash('signupMessage', 'Sorry, that username is already taken.'));
        } 
        else {

        // If there is no user with that username create new user.
        var newUserMysql = {
            username: username,
            email: req.body.email,
            password: bcrypt.hashSync(password, null, null) // Uses the generate Hash function in user model.
        };
    var insertQuery = "INSERT INTO users ( username, email, password ) values (?,?,?)";
    db.query(insertQuery,[newUserMysql.username, newUserMysql.email, newUserMysql.password],function(err, rows) {
    newUserMysql.Id = rows.insertId;
    return done(null, newUserMysql);
        });
        }
    });
    })
    );


// --------------------------------------------------------------------------------------------------
// The following lines create a function limiting access to some parts of app (only for logged users).
// --------------------------------------------------------------------------------------------------
function isLoggedIn(req, res, next) {
	// If user is authenticated in the session, carry on:
	if (req.isAuthenticated())
		return next();
	// If they aren't redirect them to the login page:
	res.redirect('/login');
}

// --------------------------------------------------------------------------------------------------
// The following lines create a function limiting access to some parts of app (only for administrator).
// --------------------------------------------------------------------------------------------------
function isAdmin(req, res, next) {
	// If user is authenticated in the session, carry on:
	if (req.user.admin)
		return next();
	// If they aren't redirect them to the login page:
	res.redirect('/login');
}


// ########################################################################################################################################################
// -------------------------------------------------------------------  LOGIN PROCESS  ---------------------------------------------------------------------
// ########################################################################################################################################################                                       

// ===========================================================================================
// ================================= USER DASHBOARD  =========================================
// ===========================================================================================
app.post('/login', passport.authenticate('local-login', {
    successRedirect : '/user', // Redirect to the user dashboard section.
    failureRedirect : '/login', // Redirect back to the login page if there is an error.
    failureFlash : true // This line allows flash messages.
    }),
    function(req, res) {
    console.log("user is logged to appication");
    if (req.body.remember) {
        req.session.cookie.maxAge = 1000 * 60 * 3;
    } else {
        req.session.cookie.expires = false;
    }
        res.redirect('/');
    });

// ===========================================================================================
// ================================= ADMIN DASHBOARD  ========================================
// ===========================================================================================
    app.post('/login-admin', passport.authenticate('local-login', {
        successRedirect : '/admin', // Redirect to the admin dashboard section.
        failureRedirect : '/login', // redirect back to the login page if there is an error.
        failureFlash : true // this line allows flash messages.
        }),
        function(req, res) {
        console.log("admin is logged to appication");
        if (req.body.remember) {
            req.session.cookie.maxAge = 1000 * 60 * 3;
        } else {
        req.session.cookie.expires = false;
        }
        res.redirect('/');
        });

// ===========================================================================================
// ================================= LOCAL REGISTRATION ======================================
// ===========================================================================================
// Uses strategies name - we have one for login and one for signup (by default, it is called 'local').
passport.use(
    'local-login',
    new LocalStrategy({
        // By default, local strategy uses username and password.
        usernameField : 'username',
        passwordField : 'password',
        passReqToCallback : true // Allows to pass back the entire request to the callback.
    },
    function(req, username, password, done) { // Callback with email and password from our form.
    db.query("SELECT * FROM users WHERE username = ?",[username], function(err, rows){
    if (err)
    return done(err);

    if (!rows.length) {
    return done(null, false, req.flash('loginMessage', 'Sorry, no user found. Please try again or register')); // req.flash is the way to set flashdata using connect-flash.
    }

    // If the user is found but the password is wrong.
    if (!bcrypt.compareSync(password, rows[0].password))
    return done(null, false, req.flash('loginMessage', 'Oops! Wrong password. Plase, try again.')); // Creates the loginMessage and save it to session as flashdata.
    // all is well, return successful user
    return done(null, rows[0]);
    });
    })
);
  

// #######################################################################################################################################################
// -------------------------------------------------------------------  SQL DATABASE  ---------------------------------------------------------------------
// ########################################################################################################################################################                                       
                                                            
// =========================================================================================================================================================
// ====================================================================  BeHelp PAGE  ======================================================================
// =========================================================================================================================================================

// =======================================================
// Route to create a new table - BeHelp.
// =======================================================   
//app.get('/createtable', isLoggedIn, isAdmin, function (req, res) {
// let sql = "CREATE TABLE beHelp (IDbehelp int NOT NULL AUTO_INCREMENT PRIMARY KEY, Id int NOT NULL, Date varchar(255) NOT NULL, County varchar(255) NOT NULL, City varchar(255) NOT NULL, Description text(2555) NOT NULL);"
// let query = db.query(sql, (err, res) => {
//     if(err) throw err;  
//  });
//      res.send("SQL worked - you created new table called beHelp");
///});

// =======================================================
// Route to alter BeHelp table - added new column.
// =======================================================    
//app.get('/altertable', isLoggedIn, isAdmin, function(req, res){
 //   let sql = 'ALTER TABLE behelp ADD CONSTRAINT FK_User_behelp FOREIGN KEY (Id) REFERENCES users(Id);'
 //   let query = db.query(sql, (err, res) => {
 //     if(err) throw err;
 //   console.log(res);
 //   });
 //     res.send("Table behelp is altered");
 //   });

// =======================================================
// Route to show all data from beHelp and users tabels.
// =======================================================
app.get('/allbehelp', function (req, res) {
    let sql = 'SELECT * FROM beHelp INNER JOIN users ON behelp.id = users.id ORDER BY Date DESC;'
    let query = db.query (sql, (err, res1) => {
        if(err) throw err; 
        res.render('showbehelp', {res1, 
            user: req.user
        });
    });
});  

// =======================================================
// Route to show all posts from database (Admin Panel).
// =======================================================
app.get('/admin-allbehelp', isLoggedIn, isAdmin, function (req, res) {
    let sql = 'SELECT * FROM beHelp INNER JOIN users ON behelp.id = users.id ORDER BY Date DESC;'
    let query = db.query (sql, (err, res1) => {
        if(err) throw err; 
        res.render('admin-showbehelp', {res1})
    });
});  

// =======================================================
// Route to display all posts added by current user.
// =======================================================
app.get('/user-allposts', isLoggedIn, function (req, res) {
    console.log(req.user)
    let sql = 'SELECT * FROM beHelp WHERE Id = '+req.user.Id+' ORDER BY Date DESC;'
    let query = db.query (sql, (err, res1) => {
        if(err) throw err; 
        res.render('user-showallposts', {res1, 
            user: req.user
        });
    });
});  

// =======================================================
// Route to delete a post from database.
// =======================================================
app.get('/deletebehelp/:IDbehelp', isLoggedIn, function(req, res) {
    let sql = 'DELETE FROM beHelp WHERE IDbehelp='+req.params.IDbehelp+' AND Id = '+req.user.Id+' ;' 
    let query = db.query(sql, (err, res1) => {
        if(err) throw err;  
    });
        res.redirect('/user');
    console.log("Post in beHelp page was delete.");
});   

// =======================================================
// Route to delete a post from database - Admin access.
// =======================================================
app.get('/deletebehelp-admin/:IDbehelp', isLoggedIn, isAdmin, function(req, res) {
    let sql = 'DELETE FROM beHelp WHERE IDbehelp='+req.params.IDbehelp+' ;'
    let query = db.query(sql, (err, res1) => {
        if(err) throw err;  
    });
        res.redirect('/admin');
    console.log("Post in beHelp page was delete.");
});   

// =======================================================
// Route to render add-behelp.ejs page.
// =======================================================
app.get('/add-behelp', isLoggedIn, function(req,res){
    res.render('add-behelp', {
        user : req.user 
    });
});

// =======================================================
// Route to add a new post in BeHelp page.
// =======================================================
app.post('/add-behelp', isLoggedIn, function (req, res) {
    let sql = 'INSERT INTO beHelp (Id, Date, County, City, Description) VALUES ("'+req.body.id+'", "'+req.body.date+'", "'+req.body.county+'", "'+req.body.city+'", "'+req.body.description+'");'
    let query = db.query(sql, (err, res) => {
        if(err) throw err;  
    });

    res.redirect("/allbehelp");
    console.log("New post to beHelp page is added");
}); 

// ======================================================
// Route to edit post in BeHelp page.
// ======================================================
app.get('/edit-behelp/:IDbehelp', isLoggedIn, function (req,res) {
    let sql= 'SELECT * FROM beHelp WHERE IDbehelp='+req.params.IDbehelp+' AND Id = '+req.user.Id+' ;'
    let query = db.query (sql, (err,res1) => {
        if(err) throw err;
        console.log(res1);

        res.render('edit-behelp', {res1});
    });
});

// ======================================================
// Route to edit post in BeHelp page - Admin access.
// ======================================================
app.get('/edit-behelp-admin/:IDbehelp', isLoggedIn, isAdmin, function (req,res) {
    let sql= 'SELECT * FROM beHelp WHERE IDbehelp='+req.params.IDbehelp+' ;'
    let query = db.query (sql, (err,res1) => {
        if(err) throw err;
        console.log(res1);

        res.render('edit-behelp', {res1});
    });
});

// =======================================================
// Post request url to edit post with sql
// =======================================================
app.post ('/edit-behelp/:IDbehelp', isLoggedIn, function (req, res) {
    let sql = 'UPDATE beHelp SET Date = "'+req.body.date+'", County = "'+req.body.county+'", City = "'+req.body.city+'", Description = "'+req.body.description+'" WHERE IDbehelp='+req.params.IDbehelp+';'
    let query = db.query(sql, (err, res) => {
         if(err) throw err;  
    });
    
    res.redirect("/allbehelp");
    console.log("The post in beHelp page is updated.");
});


// =======================================================
// Route to show specific post from behelp table
// =======================================================
app.get('/show1behelp/:IDbehelp', isLoggedIn, function (req, res) {
    let sql = 'SELECT * FROM behelp INNER JOIN users ON behelp.id = users.id  WHERE IDbehelp = '+req.params.IDbehelp+';'
    let query = db.query(sql, (err, res1) => {
        if(err) throw err; 
        res.render('show1behelp', {res1, 
            user : req.user 
        });
    });
});  

// =======================================================
// Allows users to report invalid entries
// =======================================================
app.get('/add-report/:IDbehelp', function(req, res){
    let sql= 'SELECT * FROM behelp INNER JOIN users ON behelp.id = users.id  WHERE IDbehelp = '+req.params.IDbehelp+'; '
    let query = db.query (sql, (err,res1) => {
        if(err) throw err;

        res.render('add-report', {res1})
    });
});


// =========================================================================================================================================================
// ====================================================================  NeedHelp PAGE  ======================================================================
// =========================================================================================================================================================

// =======================================================
// Route to create a new table - NeedHelp.  
// =======================================================   
//app.get('/createtable2', isLoggedIn, isAdmin, function (req, res) {
//let sql = "CREATE TABLE needHelp (IDneedhelp int NOT NULL AUTO_INCREMENT PRIMARY KEY, Id int NOT NULL, Date varchar(255) NOT NULL, County varchar(255) NOT NULL, City varchar(255) NOT NULL, Description text(2555) NOT NULL);"
//let query = db.query(sql, (err, res) => {
//     if(err) throw err;  
//    });
//    res.send("SQL worked - you created new table - needHelp");
//});

// =======================================================
// Route to alter needHelp table - added Foreign Key.
// =======================================================    
//app.get('/altertable2', isLoggedIn, isAdmin, function(req, res){
 //   let sql = 'ALTER TABLE needhelp ADD CONSTRAINT FK_User_needhelp FOREIGN KEY (Id) REFERENCES users(Id);'
 //   let query = db.query(sql, (err, res) => {
 //     if(err) throw err;
 //   console.log(res);
 //   });
 //     res.send("Table needhelp is altered");
 //   });

// =======================================================
// Route to show all data from needHelp and users tabels.
// =======================================================
app.get('/all-needhelp', function (req, res) {
    let sql = 'SELECT * FROM needHelp INNER JOIN users ON needhelp.id = users.id ORDER BY Date DESC;'
    let query = db.query (sql, (err, res1) => {
        if(err) throw err; 
        res.render('show-needhelp', {res1, 
            user: req.user
        });
    });
});  

// =======================================================
// Route to show all posts from needHelp table (Admin Panel).
// =======================================================
app.get('/admin-allneedhelp', isLoggedIn, isAdmin, function (req, res) {
    let sql = 'SELECT * FROM needHelp INNER JOIN users ON needhelp.id = users.id ORDER BY Date DESC;'
    let query = db.query (sql, (err, res1) => {
        if(err) throw err; 
        res.render('admin-showneedhelp', {res1})
    });
});  

// =======================================================
// Route to display all posts added by current user.
// =======================================================
app.get('/user-all-needhelp-posts', isLoggedIn, function (req, res) {
    console.log(req.user)
    let sql = 'SELECT * FROM needHelp WHERE Id = '+req.user.Id+' ORDER BY Date DESC;'
    let query = db.query (sql, (err, res1) => {
        if(err) throw err; 
        res.render('user-show-all-needhelp-posts', {res1, 
            user: req.user
        });
    });
});  

// =======================================================
// Route to delete a post from database.
// =======================================================
app.get('/deleteneedhelp/:IDneedhelp', isLoggedIn, function(req, res) {
    let sql = 'DELETE FROM needHelp WHERE IDneedhelp='+req.params.IDneedhelp+' AND Id = '+req.user.Id+' ;' 
    let query = db.query(sql, (err, res1) => {
        if(err) throw err;  
    });
        res.redirect('/user');
    console.log("Post in needHelp page was delete.");
});   

// =======================================================
// Route to delete a post from database - Admin access.
// =======================================================
app.get('/deleteneedhelp-admin/:IDneedhelp', isLoggedIn, isAdmin, function(req, res) {
    let sql = 'DELETE FROM needHelp WHERE IDneedhelp='+req.params.IDneedhelp+';' 
    let query = db.query(sql, (err, res1) => {
        if(err) throw err;  
    });
        res.redirect('/admin');
        console.log("Post in needHelp page was delete.");
});   

// =======================================================
// Route to render add-needhelp.ejs page.
// =======================================================
app.get('/add-needhelp', isLoggedIn, function(req,res){
    res.render('add-needhelp', {
        user: req.user
    });
});

// =======================================================
// Route to add a new post in needHelp page.
// =======================================================
app.post('/add-needhelp', isLoggedIn, function (req, res) {
    
    let sql = 'INSERT INTO needHelp (Id, Date, County, City, Description) VALUES ("'+req.body.id+'", "'+req.body.date+'", "'+req.body.county+'", "'+req.body.city+'", "'+req.body.description+'");'
    let query = db.query(sql, (err, res) => {
        if(err) throw err;  
    });
    
    res.redirect("/all-needhelp");
    console.log("New post in needHelp page is added");
}); 

// ======================================================
// Route to edit post in needHelp page.
// ======================================================
app.get('/edit-needhelp/:IDneedhelp', isLoggedIn, function (req,res) {
    let sql= 'SELECT * FROM needHelp WHERE IDneedhelp='+req.params.IDneedhelp+' AND Id = '+req.user.Id+' ;'
    let query = db.query (sql, (err,res1) => {
        if(err) throw err;
        console.log(res1);

        res.render('edit-needhelp', {res1});
    });
});


// ======================================================
// Route to edit post in needHelp page - Admin access.
// ======================================================
app.get('/edit-needhelp-admin/:IDneedhelp', isLoggedIn, isAdmin, function (req,res) {
    let sql= 'SELECT * FROM needHelp WHERE IDneedhelp='+req.params.IDneedhelp+';'
    let query = db.query (sql, (err,res1) => {
        if(err) throw err;
        console.log(res1);

        res.render('edit-needhelp', {res1})
    });
});

// =======================================================
// Post request url to edit post with sql
// =======================================================
app.post ('/edit-needhelp/:IDneedhelp', isLoggedIn, function (req, res) {
    let sql = 'UPDATE needHelp SET Date = "'+req.body.date+'", County = "'+req.body.county+'", City = "'+req.body.city+'", Description = "'+req.body.description+'" WHERE IDneedhelp='+req.params.IDneedhelp+';'
    let query = db.query(sql, (err, res) => {
         if(err) throw err;  
    });
    
    res.redirect("/all-needhelp");
    console.log("The post in needHelp page is updated.");
});


// =======================================================
// Route to show specific post from needhelp table
// =======================================================
app.get('/show1needhelp/:IDneedhelp', isLoggedIn, function (req, res) {
    let sql = 'SELECT * FROM needhelp INNER JOIN users ON needhelp .id = users.id  WHERE IDneedhelp  = '+req.params.IDneedhelp +';'
    let query = db.query(sql, (err, res1) => {
        if(err) throw err; 
        res.render('show1needhelp', {res1, 
            user : req.user 
        });
    });
});  

// =======================================================
// Allows users to report invalid entries
// =======================================================
app.get('/add-report-needhelp/:IDneedhelp', function(req, res){
    let sql= 'SELECT * FROM needhelp INNER JOIN users ON needhelp.id = users.id  WHERE IDneedhelp = '+req.params.IDneedhelp+';'
    let query = db.query (sql, (err,res1) => {
        if(err) throw err;

        res.render('add-report-needhelp', {res1})
    });
});



// =========================================================================================================================================================
// ====================================================================  Users table  ======================================================================
// =========================================================================================================================================================

// =======================================================
// Create a new users tabel.
// =======================================================
//app.get('/createuser', isLoggedIn, isAdmin, function(req, res){
//    let sql = 'CREATE TABLE users (Id int NOT NULL AUTO_INCREMENT PRIMARY KEY, username varchar(255) NOT NULL, email varchar(255) NOT NULL, password varchar(255) NOT NULL);'
//    let query = db.query(sql, (err,res) => {
//    if(err) throw err;
//    });
//    res.send("SQL worked - you created new table called users");
 //   });


// =======================================================
// Alter table, add new column - admin.
// =======================================================
//app.get('/alter',  isLoggedIn, isAdmin, function(req, res){
//    let sql = 'ALTER TABLE users ADD COLUMN admin BOOLEAN DEFAULT FALSE;'
 //   let query = db.query(sql, (err, res) => {
 //   if(err) throw err;
 //   console.log(res);
 //   });
 //   res.send("Table users is altered");
 //   });


// =======================================================
// Alter table, add new columns - firstname, lastname, photo, trusted.
// =======================================================
//app.get('/alteruserstable', isLoggedIn, isAdmin, function(req, res){
 //   let sql = 'ALTER TABLE users ADD COLUMN (firstname varchar(255), lastname varchar(255), photo varchar(255), trusted BOOLEAN DEFAULT FALSE);'
 //   let query = db.query(sql, (err, res) => {
 //   if(err) throw err;
  //  console.log(res);
 //   });
 //  res.send("Added new colums to users table");
 //   });

    
// =======================================================
// Route to show all users from database.
// =======================================================
app.get('/allusers',isLoggedIn, isAdmin, function (req, res) {
    let sql = 'SELECT * FROM users'
    let query = db.query (sql, (err, res1) => {
        if(err) throw err; 
        res.render('showusers', {res1})
    });
});  


// =======================================================
// Route to delete a user from database.
// =======================================================
app.get('/deleteuser/:id', isLoggedIn, function(req, res) {
    let sql = 'DELETE FROM users WHERE Id='+req.params.id+' AND Id = '+req.user.Id+' ;'
    let query = db.query(sql, (err, res1) => {
        if(err) throw err; 
    });
        res.redirect('/');
    console.log("User was delete.");
});   

// =======================================================
// Route to delete a user from database - Admin access.
// =======================================================
app.get('/deleteuser-admin/:id', isLoggedIn, isAdmin, function(req, res) {
    let sql = 'DELETE FROM users WHERE Id='+req.params.id+';'
    let query = db.query(sql, (err, res1) => {
        if(err) throw err; 
    });
        res.redirect('/admin');
     console.log("User was delete.");
});   


// =======================================================
// Route to edit user details.
// =======================================================
app.get('/edituser/:id', isLoggedIn, function (req,res) {
    let sql= 'SELECT * FROM users WHERE Id= '+req.params.id+' AND Id = '+req.user.Id+';'
    let query = db.query (sql, (err,res1) => {
        if(err) throw err;
        console.log(res1);

        res.render('edituser', {res1})
    });
});

// =======================================================
// Post request url to edit user details.
// =======================================================
app.post ('/edituser/:id', isLoggedIn, function (req, res) {

    let sql = 'UPDATE users SET username = "'+req.body.username+'", firstname = "'+req.body.firstname+'", lastname = "'+req.body.lastname+'", email = "'+req.body.email+'" WHERE Id= "'+req.params.id+'";'
    let query = db.query(sql, (err, res) => {
         if(err) throw err;  
    });
    
    res.redirect("/user");
    console.log("The user details was update.");
});

// =======================================================
// Route to edit user details (FOR ADMIN - more details).
// =======================================================
app.get('/edituser-admin/:id', isLoggedIn, function (req,res) {
    let sql= 'SELECT * FROM users WHERE Id= "'+req.params.id+'";'
    let query = db.query (sql, (err,res1) => {
        if(err) throw err;
        console.log(res1);

        res.render('edituser-admin', {res1})
    });
});

// =======================================================
// Post request url to edit user (FOR ADMIN - more details).
// =======================================================
app.post ('/edituser-admin/:id', isLoggedIn, function (req, res) {

    // Upload image
    if (!req.files)
    return res.status(400).send('To add a new post you have to upload a photo.');
     
    // The name of the input field (here imageFile) is used to retrieve the uploaded file
    let imageFile = req.files.imageFile;
    filename = imageFile.name;
    // I used the mv() method to place the file on the server - here in images folder
    imageFile.mv('./images/' + filename, function(err) {
        if (err)
            return res.status(500).send(err);
    console.log("New image was upladed " + req.files.imageFile)
    });


    let sql = 'UPDATE users SET username = "'+req.body.username+'", firstname = "'+req.body.firstname+'", lastname = "'+req.body.lastname+'", email = "'+req.body.email+'", password = "'+req.body.password+'", admin = "'+req.body.admin+'", trusted = "'+req.body.trusted+'", photo = "'+filename+'" WHERE Id= "'+req.params.id+'";'
    let query = db.query(sql, (err, res) => {
         if(err) throw err;  
    });
    
    res.redirect("/admin");
    console.log("The user details was update.");
});


// =========================================================================================================================================================
// ====================================================================  Messages table  ======================================================================
// =========================================================================================================================================================

// =======================================================
// Create Messages table.
// =======================================================
//app.get('/createmessage', isLoggedIn, isAdmin, function(req, res){
 //   let sql = 'CREATE TABLE messages (Id int NOT NULL AUTO_INCREMENT PRIMARY KEY, sender varchar(255) NOT NULL, senderID int NOT NULL, receiver varchar(255) NOT NULL, receiverID int NOT NULL, message text(2555) NOT NULL, Date varchar(255) NOT NULL);'
 //   let query = db.query(sql, (err,res) => {
 //   if(err) throw err;
 //   });
 //   res.send("SQL worked - you created new table called messages");
 //   });

// =======================================================
// Route to alter Messages table - added Foreign Key.
// =======================================================    
//app.get('/altertablemessages', isLoggedIn, isAdmin, function(req, res){
  //  let sql = 'ALTER TABLE messages ADD CONSTRAINT FK_messages_users FOREIGN KEY (receiverID) REFERENCES users(Id);'
  //  let query = db.query(sql, (err, res) => {
  //    if(err) throw err;
  //  console.log(res);
  //  });
  //    res.send("Table messages is altered");
  //  });


// =======================================================
// Route to add a new message .
// =======================================================
app.post('/send-message', isLoggedIn, function (req, res) {
    let sql = 'INSERT INTO messages (sender, senderID, receiver, receiverID, message, Date) VALUES ( "'+req.body.sender+'", "'+req.body.senderID+'", "'+req.body.receiver+'", "'+req.body.receiverID+'", "'+req.body.message+'", "'+req.body.Date+'");'
    let query = db.query(sql, (err, res) => {
        if(err) throw err;  
    });
    
    res.redirect("/user");
    console.log("New post was added to beHelp page");
}); 

// =======================================================
// Route to show messages by current user.
// =======================================================
app.get('/allmessages', isLoggedIn, function (req, res) {
    let sql = 'SELECT * FROM messages WHERE receiverID = '+req.user.Id+' ORDER BY Date DESC;'
    let query = db.query (sql, (err, res1) => {
        if(err) throw err; 
        res.render('show-messages', {res1, 
            user: req.user
        });
    });
});  

// =======================================================
// Route to show all sent messages by current user.
// =======================================================
app.get('/sentmessages', isLoggedIn, function (req, res) {
    let sql = 'SELECT * FROM messages WHERE senderID = '+req.user.Id+' ORDER BY Date DESC;'
    let query = db.query (sql, (err, res1) => {
        if(err) throw err; 
        res.render('show-sent-messages', {res1, 
            user: req.user
        });
    });
});  

// =======================================================
// Route to delete a message.
// =======================================================
app.get('/deletemessage/:Id', isLoggedIn, function(req, res) {
    let sql = 'DELETE FROM messages WHERE Id='+req.params.Id+' ;' 
    let query = db.query(sql, (err, res1) => {
        if(err) throw err;  
    });
        res.redirect('/user');
        console.log("Message is deleted.");
});   


// ########################################################################################################################################################
// ----------------------------------------------------------------  JSON DATABASE  -----------------------------------------------------------------------
// ########################################################################################################################################################

// ================================================================================================
// ----------------------- Function to contact with Admin (Contact Page) --------------------------
// ================================================================================================
app.post('/contact', function (req,res) {
    // Function to find the max id in review JSON file.
    function getMax (contact, id) {
        var max
            for (var i=0; i<contact.length; i++){
                if(!max || parseInt(contact[i][id]) > parseInt (max[id]))
                max=contact[i];
            }
        return max;
    }

    // Call the getMAx function .
    var maxRid=getMax(contact, "id")
    var newId=maxRid.id+1; // Make a new variable for id which is 1 large than the current max.
    console.log("The new id is:" +newId)

    var json=JSON.stringify(contact)

    // These lines create a new JSON object.
    var newContact = {
        id: newId,
        name: req.body.name,
        email: req.body.email,
        tel: req.body.tel,
        message: req.body.message
    }

    // These lines push the new data to the contact.json file.
    fs.readFile('./model/contact.json', 'utf8', function readfileCallback(err){
        if (err) {
            throw(err)
        } else
        contact.push(newContact) // Adds new message to the JSON file.
        var json = JSON.stringify(contact, null, 5)
        fs.writeFileSync('./model/contact.json', json, 'utf8')
    })
    res.redirect('/confirmation-contact')
});

// ================================================================================================
// --------------------- Function to delete a message (access only for admin) ---------------------
// ================================================================================================
app.get('/deletecontact/:id', isLoggedIn, isAdmin, function (req,res) {

    var json = JSON.stringify(contact);
    var keyToFind = parseInt(req.params.id); // Gets the id to delete from the url parameter.

    var data = contact // Declares the JSON file as a variable called data.

    var index = data.map(function(contact){return contact.id;}).indexOf(keyToFind) // Finds needed information.
    
    contact.splice(index, 1); // Deletes only 1 item from the index variable above.
        var json = JSON.stringify(contact, null, 5)
        fs.writeFileSync('./model/contact.json', json, 'utf8')

        console.log("Deleted contact/message to admin")
        res.redirect('/admin')
});



// ================================================================================================
// --------------------------------- Function to add a new review --------------------------------
// ================================================================================================
app.post('/add-review', isLoggedIn, function (req,res) {
    // Function to find the max id in review JSON file.
    function getMax (reviews, id) {
        var max
            for (var i=0; i<reviews.length; i++){
                if(!max || parseInt(reviews[i][id]) > parseInt (max[id]))
                max=reviews[i];
            }
        return max;
    }

    // Call the getMAx function. 
    var maxRid=getMax(reviews, "id")
    var newId=maxRid.id+1; // Make a new variable for id which is 1 large than the current max.
    console.log("The new id is:" +newId)

    var json=JSON.stringify(reviews)

    // These lines create a new JSON object.
    var newReview = {
        id: newId,
        name: req.body.name,
        date: req.body.date,
        description: req.body.description
    }

    // These lines push the new data to the reviews.json file.
    fs.readFile('./model/reviews.json', 'utf8', function readfileCallback(err){
        if (err) {
            throw(err)
        } else
        reviews.push(newReview) // Adds new review to the json file.
        var json = JSON.stringify(reviews, null, 4)
        fs.writeFileSync('./model/reviews.json', json, 'utf8')
    })
    res.redirect('/review')
});

// ================================================================================================
// -------------------- Function to delete a review (access only for admin) -----------------------
// ================================================================================================
app.get('/deletereview/:id', isLoggedIn, isAdmin, function (req,res) {

    var json = JSON.stringify(reviews);
    var keyToFind = parseInt(req.params.id); // Gets the id to delete from the url parameter.

    var data = reviews // Declares the JSON file as a variable called data.

    var index = data.map(function(reviews){return reviews.id;}).indexOf(keyToFind) // Finds needed information.
    
    reviews.splice(index, 1); // Deletes only 1 item from the index variable above.
        var json = JSON.stringify(reviews, null, 4)
        fs.writeFileSync('./model/reviews.json', json, 'utf8')

        console.log("The review is delated")
        res.redirect('/review')
});
 
// ================================================================================================
// ------------------------ Function to edit review (only admin) ----------------------------------
// ================================================================================================
app.get('/editreview/:id', isLoggedIn, isAdmin,  function(req, res) { 
    
    function chooseReview(indOne) {
        return indOne.id === parseInt(req.params.id);  // parseInt(req.params.id) -jest to wazne !!! wyjasnij w dokumentacji
    } 
    
    var indOne = reviews.filter(chooseReview)
    res.render('editreview', {res:indOne});
});

app.post('/editreview/:id', isLoggedIn, isAdmin, function(req,res) { // Saves all changes in JSON file.
    
    var json = JSON.stringify(reviews); // Modify the reviews file.
    
    var keyToFind = parseInt(req.params.id); // Finds the data we need to edit.
    var data = reviews; // Declares the JSON file as a variable called data.
    var index = data.map(function(reviews){return reviews.id;}).indexOf(keyToFind)  //Lets map the data and find the needed information.
    
   // Changes only 1 comment:
    reviews.splice(index, 1, {
        id: parseInt(req.params.id),
        name: req.body.name, 
        date: req.body.date,
        description: req.body.description
    }); 
    
    json = JSON.stringify(reviews, null, 4);
    fs.writeFileSync('./model/reviews.json', json, 'utf8')
    
    res.redirect('/review');
    console.log("Review is updated.")
 
});


// ================================================================================================
// --------------------- Function to report post (BeHelp/NeedHelp Pages) -------------------------
// ================================================================================================
app.post('/add-report', function (req,res) {
    // Function to find the max id in report JSON file.
    function getMax (report, id) {
        var max
            for (var i=0; i<report.length; i++){
                if(!max || parseInt(report[i][id]) > parseInt (max[id]))
                max=report[i];
            }
        return max;
    }

    // Calls the getMAx function.
    var maxRid=getMax(report, "id")
    var newId=maxRid.id+1; // Make a new variable for id which is 1 large than the current max.
    console.log("The new id is:" +newId)

    var json=JSON.stringify(report)

    // These lines create a new JSON object.
    var newReport = {
        id: newId,
        idpost: req.body.idpost,
        username: req.body.username,
        table: req.body.table,
        date: req.body.date,
        description: req.body.description,
        name: req.body.name,
        description2: req.body.description2
    }

    // These lines push the new data to the report.json file.
    fs.readFile('./model/report.json', 'utf8', function readfileCallback(err){
        if (err) {
            throw(err)
        } else
        report.push(newReport) // Adds new report to the json file.
        var json = JSON.stringify(report, null, 8)
        fs.writeFileSync('./model/report.json', json, 'utf8')
    })
    res.redirect('/confirmation-report')
});

// ================================================================================================
// --------------------------------- Function to delete a report ----------------------------------
// ================================================================================================
app.get('/deletereport/:id', isLoggedIn, isAdmin, function (req,res) {

   var json = JSON.stringify(report);
   var keyToFind = parseInt(req.params.id); // Gets the id to delete from the url parameter.

    var data = report // Declares the JSON file as a variable called data.

    var index = data.map(function(report){return report.id;}).indexOf(keyToFind) // Finds needed information.
    
   report.splice(index, 1); // Deletes only 1 item from the index variable above.
       var json = JSON.stringify(report, null, 8)
       fs.writeFileSync('./model/report.json', json, 'utf8')

       console.log("The report is delated")
       res.redirect('/admin')
});



// ================================================================================================
// --------------------------------- Function to upgrade account  ---------------------------------
// ================================================================================================
app.post('/add-upgrade', isLoggedIn, function (req,res) {
    //function to find the max id in upgrade JSON file
    function getMax (upgrade, id) {
        var max
            for (var i=0; i<upgrade.length; i++){
                if(!max || parseInt(upgrade[i][id]) > parseInt (max[id]))
                max=upgrade[i];
            }
        return max;
    }

    // Upload document - copy of user's ID/passport and address.
    if (!req.files)
    return res.status(400).send('Please add copy of your ID or passport');
     
    // The name of the input field (imageFileJSON) is used to retrieve the uploaded file (ID cart or passport).
    let imageFileJSON = req.files.imageFileJSON;
    filenameJSON = imageFileJSON.name;
    // Uses the mv() method to place the file on the server. Here in 'images-upgrade' folder.
    imageFileJSON.mv('./images-upgrade/' + filenameJSON, function(err) {
        if (err)
            return res.status(500).send(err);
    console.log("New document (ID/passport) was upladed " + req.files.imageFileJSON)
    });

     // The name of the input field (imageFileJSON2) is used to retrieve the uploaded file (bill with current address).
     let imageFileJSON2 = req.files.imageFileJSON2;
     filenameJSON2 = imageFileJSON2.name;
     // Uses the mv() method to place the file on the server. Here in 'images-upgrade' folder.
     imageFileJSON2.mv('./images-upgrade/' + filenameJSON2, function(err) {
         if (err)
             return res.status(500).send(err);
     console.log("New document (current address) was upladed " + req.files.imageFileJSON2)
     });

    // Calls the getMAx function.
    var maxRid=getMax(upgrade, "id")
    var newId=maxRid.id+1; // Makes a new variable for id which is 1 large than the current max.
    console.log("The new upgrade id is:" +newId)

    var json=JSON.stringify(upgrade)

    // These lines create a new JSON object.
    var newUpgrade = {
        id: newId,
        username: req.body.username,
        date: req.body.date,
        Q1: req.body.Q1,
        Q2: req.body.Q2,
        Q3: req.body.Q3,
        Doc1: filenameJSON,
        Doc2: filenameJSON2     
    }

    // These lines push the new data to the upgrade.json file.
    fs.readFile('./model/upgrade.json', 'utf8', function readfileCallback(err){
        if (err) {
            throw(err)
        } else
        upgrade.push(newUpgrade) // Adds new upgrade to the json file.
        var json = JSON.stringify(upgrade, null, 8)
        fs.writeFileSync('./model/upgrade.json', json, 'utf8')
    })
    res.redirect('/confirmation-upgrade')
});

// ================================================================================================
// ---------------------------------- Function to delete upgrade ----------------------------------
// ================================================================================================
app.get('/deleteupgrade/:id', isLoggedIn, isAdmin, function (req,res) {

    var json = JSON.stringify(upgrade);
    var keyToFind = parseInt(req.params.id); // Gets the id to delete from the url parameter.
 
     var data = upgrade // Declares the JSON file as a variable called data.
 
     var index = data.map(function(upgrade){return upgrade.id;}).indexOf(keyToFind) // Finds needed information.
     
     upgrade.splice(index, 1); // Deletes only 1 item from the index variable above.
        var json = JSON.stringify(upgrade, null, 8)
        fs.writeFileSync('./model/upgrade.json', json, 'utf8')
 
        console.log("The upgrade is delated")
        res.redirect('/admin')
 });


// ########################################################################################################################################################
// ---------------------------------------------------------  SEARCH BARS / SORTING POSTS  -----------------------------------------------------------------
// ########################################################################################################################################################


// ================================================================================================
// ------------------------------------ SEARCH BAR in BeHelp page ---------------------------------
// ================================================================================================

// Post request url to search database and use an existing page to display results.
app.post('/search', function (req, res) {
    let sql = 'SELECT * FROM beHelp INNER JOIN users ON behelp.id = users.id WHERE username LIKE "%'+req.body.search+'%" OR County LIKE "%'+req.body.search+'%" OR  City LIKE "%'+req.body.search+'%" OR Description LIKE "%'+req.body.search+'%" ';
    let query = db.query(sql, (err, res1) => {
         if(err) throw err;  
        res.render('showbehelp', {res1})
    });
});  

// ================================================================================================
// ----------------------------------- SEARCH BAR in NeedHelp page --------------------------------
// ================================================================================================

// Post request url to search database and use an existing page to display results.
app.post('/search-needhelp', function (req, res) {
    let sql = 'SELECT * FROM needHelp INNER JOIN users ON needhelp.id = users.id WHERE username LIKE "%'+req.body.search+'%" OR County LIKE "%'+req.body.search+'%" OR  City LIKE "%'+req.body.search+'%" OR Description LIKE "%'+req.body.search+'%" ';
    let query = db.query(sql, (err, res1) => {
         if(err) throw err;  
        res.render('show-needhelp', {res1})
    });
});  

// ================================================================================================
// ---------------------- SORTING POSTS (by County, City, Date) - BeHelp Posts --------------------
// ================================================================================================

// Posts request url to search database and displays all posts added by trusted users.
app.post('/show-trusted-users', function (req, res) {
    let sql = 'SELECT * FROM beHelp INNER JOIN users ON behelp.id = users.id WHERE trusted = 1 ';
    let query = db.query(sql, (err, res1) => {
         if(err) throw err;  
        res.render('showbehelp', {res1})
    });
});  

// Posts request url to search database and displays all posts sorted by County.
app.post('/sorting-by-county', function (req, res) {
    let sql = 'SELECT * FROM beHelp INNER JOIN users ON behelp.id = users.id ORDER BY County ASC';
    let query = db.query(sql, (err, res1) => {
         if(err) throw err;  
        res.render('showbehelp', {res1})
    });
});  

// Posts request url to search database and displays all posts sorted by City.
app.post('/sorting-by-city', function (req, res) {
    let sql = 'SELECT * FROM beHelp INNER JOIN users ON behelp.id = users.id ORDER BY City ASC';
    let query = db.query(sql, (err, res1) => {
         if(err) throw err;  
        res.render('showbehelp', {res1})
    });
});  

// Posts request url to search database and displays all posts sorted by added date (new posts).
app.post('/sorting-by-new-date', function (req, res) {
    let sql = 'SELECT * FROM beHelp INNER JOIN users ON behelp.id = users.id ORDER BY Date DESC';
    let query = db.query(sql, (err, res1) => {
         if(err) throw err;  
        res.render('showbehelp', {res1})
    });
});  

// Posts request url to search database and displays all posts sorted by added date (old posts).
app.post('/sorting-by-old-date', function (req, res) {
    let sql = 'SELECT * FROM beHelp INNER JOIN users ON behelp.id = users.id ORDER BY Date ASC';
    let query = db.query(sql, (err, res1) => {
         if(err) throw err;  
        res.render('showbehelp', {res1})
    });
}); 

// ================================================================================================
// ---------------------- SORTING POSTS (by County, City, Date) - NeedHelp Posts ------------------
// ================================================================================================
// Posts request url to search database and displays all posts added by trusted users.
app.post('/show-trusted-users-needhelp', function (req, res) {
    let sql = 'SELECT * FROM needHelp INNER JOIN users ON needhelp.id = users.id WHERE trusted = 1 ';
    let query = db.query(sql, (err, res1) => {
         if(err) throw err;  
        res.render('show-needhelp', {res1})
    });
});  

// Posts request url to search database and displays all posts sorted by County.
app.post('/sorting-by-county-needhelp', function (req, res) {
    let sql = 'SELECT * FROM needHelp INNER JOIN users ON needhelp.id = users.id ORDER BY County ASC';
    let query = db.query(sql, (err, res1) => {
         if(err) throw err;  
        res.render('show-needhelp', {res1})
    });
});  

// Posts request url to search database and displays all posts sorted by City.
app.post('/sorting-by-city-needhelp', function (req, res) {
    let sql = 'SELECT * FROM needHelp INNER JOIN users ON needhelp.id = users.id ORDER BY City ASC';
    let query = db.query(sql, (err, res1) => {
         if(err) throw err;  
        res.render('show-needhelp', {res1})
    });
});  

// Posts request url to search database and displays all posts sorted by added date (new posts).
app.post('/sorting-by-new-date-needhelp', function (req, res) {
    let sql = 'SELECT * FROM needHelp INNER JOIN users ON needhelp.id = users.id ORDER BY Date DESC';
    let query = db.query(sql, (err, res1) => {
         if(err) throw err;  
        res.render('show-needhelp', {res1})
    });
});  

// Posts request url to search database and displays all posts sorted by added date (old posts).
app.post('/sorting-by-old-date-needhelp', function (req, res) {
    let sql = 'SELECT * FROM needHelp INNER JOIN users ON needhelp.id = users.id ORDER BY Date ASC';
    let query = db.query(sql, (err, res1) => {
         if(err) throw err;  
        res.render('show-needhelp', {res1})
    });
}); 


// ================================================================================================
// -------------------------- SEARCH BAR in Admin Panel (all users list) --------------------------
// ================================================================================================

// Post request url to search database and use an existing page to display results.
app.post('/search-users', function (req, res) {
    let sql = 'SELECT * FROM users WHERE username LIKE "%'+req.body.search+'%" OR  Id LIKE "%'+req.body.search+'%" OR lastname LIKE "%'+req.body.search+'%" OR firstname LIKE "%'+req.body.search+'%"';
    let query = db.query(sql, (err, res1) => {
         if(err) throw err;  
        res.render('showusers', {res1})
    });
});  




// #########################################################################################################################################################
// ------------------------------------------------------------ The way of launching the application  --------------------------------------------------- 
// #########################################################################################################################################################

app.listen(process.env.PORT || 8000, process.env.IP || "0.0.0.0", function() {
   
    console.log("The application works correctly.") 
     
 });