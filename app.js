const express = require('express');
const app = express();
const User = require('./Models/user');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const PORT = process.env.PORT || 3003;
global.TextEncoder = require("util").TextEncoder;
app.set('view engine', 'ejs');
app.set('views', 'views');
app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: 'Secret message!' }));
app.use('/css', express.static("css"));
app.use(cookieParser());

//Middleware
const requireLogin = (req, res, next) => {
    if (!req.session.user_id)
        return res.redirect('/login');
    next();
}

//Homepage route
app.get('/', (req, res) => {
    if (req.session.user_id) {
        return res.redirect('/secret');
    }
    res.render('login');
})

//Signup route
app.get('/signup', (req, res) => {
    if (req.session.user_id)
        res.redirect('/secret')
    else
        res.render('signup');
})

//Signup post
app.post('/signup', async (req, res) => {
    const { username, password } = req.body;
    const verifiedSignup = await User.isValidUserCredentials(username, password);
    if (!verifiedSignup)
        return res.redirect('/signup')
    const hashedPassword = await bcrypt.hash(password, 12);
    const user = new User({ username, password: hashedPassword })
    await user.save();
    req.session.user_id = user._id;
    res.cookie('username', username, { expires: new Date(Date.now() + (1 * 60 * 1000)), httpOnly: true })
    return res.redirect('/secret');
})

//Login route
app.get('/login', (req, res) => {
    const { username } = req.body;
    if (req.session.user_id)
        res.redirect('/secret')
    else
        res.render('login');
})

//Login post
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const verifiedLogin = await User.isLoggedIn(username, password);
    if (verifiedLogin) {
        req.session.user_id = verifiedLogin._id;
        res.cookie('username', username, { expires: new Date(Date.now() + (30 * 60 * 1000)), httpOnly: true })
        return res.redirect('/secret');
    } else {
        return res.redirect('/signup')
    }
})

//Logout post
app.post('/logout', (req, res) => {
    res.clearCookie('username')
    req.session.destroy((err) => {
        if (err)
            throw err;
    });
    return res.redirect('/login');
})

//Secret route
app.get('/secret', requireLogin, async (req, res) => {
    const userID = await User.findById(req.session.user_id);
    if (req.cookies['username'] === userID.username) {
        res.render('secret', { userID });
    }
    else {
        req.session.destroy();
        res.render('login');
    }
})

//Catch undefined routes and redirect to login page
app.get('*', (req, res) => {
    res.redirect('/login');
})

//connect to the database
mongoose.connect('mongodb://localhost:27017/usersDB', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
    .then(() => {
        console.log("Successfully connected to the database!");
        app.listen(PORT, () => {
            console.log(`Connected to: http://localhost:${PORT}`)
        })
    })
    .catch(err => {
        console.log(err);
    })

