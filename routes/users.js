const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');

const User = require('../model/User');

//User login
router.get('/login', (req, res) => res.render('login'));

//User register
router.get('/register', (req, res) => res.render('register'));

//Get user registration details
router.post('/register', (req, res) => {
    const { name, email, password, password2 } = req.body;

    let errors = [];

    if (!name || !email || !password || !password2) {
        errors.push({ message: 'Please fill in all form' });
    } 
    
    if (password.length < 6) {
        errors.push({ message: 'Password must be at least 6 characters'})
    } else if (password !== password2) {
        errors.push({ message: 'Password does not match' });
    }

    if (errors.length > 0) {
        // res.send(errors);
        res.render('register', {
            errors,
            name,
            email,
            password,
            password2,
        });
    } else {
        //Validation passed
        User.findOne({ email: email })
            .then(user => {
                //User already registered
                if (user) {
                    errors.push({ message: 'Email is already registered' });
                    res.render('register', {
                        errors,
                        name,
                        email,
                        password,
                        password2
                    });
                } else {
                    //User not existed
                    const newUser = new User({
                        name,
                        email,
                        password
                    });
                    //Password need to be hashed before saved                    
                    bcrypt.genSalt(10, (err, salt) => {
                        bcrypt.hash(newUser.password, salt, (err, hash) => {
                            if(err) throw err;
                            //Password changed to hashed password
                            newUser.password = hash;
                            //Save newUser to database
                            newUser.save()
                                .then((user) => {
                                    req.flash('success_msg', 'You are now registered and can log in');
                                    res.redirect('/users/login');
                                })
                                .catch(err => console.log(err));
                        });
                    });
                }
                
            });
    }

});

//Login handler
router.post('/login', (req, res, next) => {
    passport.authenticate('local', {
        successRedirect: '/dashboard',
        failureRedirect: '/users/login',
        failureFlash: true    
    })(req, res, next);
});

//Logout handler
router.get('/logout', (req, res) => {
    req.logOut();
    req.flash('success_msg', 'You are logged out!');
    res.redirect('/users/login');
});

module.exports = router;