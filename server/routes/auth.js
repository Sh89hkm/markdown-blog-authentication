const express = require('express');
const User = require('./../models/user');
const router = express.Router();
const bcrypt = require('bcrypt');

// @TODO: Assignment here

router.post('/signin', async (req, res) => {
  const { username, password, rememberMe } = req.body;
  // @TODO: Complete user sign in
  // User must exist in the database for sign in request
  const user = await User.findOne({ username });
  if (!user) {
    return res
      .status(400)
      .render('user/signin', { error: 'Wrong username or password' });
  }
  // bcrypt compare is used to validate the plain text password sent in the request body with the hashed password stored in the database
  const isValidPassword = await bcrypt.compare(password, user.password_hash);
  if (!isValidPassword) {
    return res
      .status(400)
      .render('user/signin', { error: 'Wrong username or password' });
  }
  // If password is valid, it's a sign in success
  // Return user details and redirect to confirm sign in
  res.setHeader('user', user.id);
  req.user = user;
  res.redirect('/user/authenticated');
});

router.post('/signup', async (req, res) => {
  const {
    firstname,
    lastname,
    username,
    password,
    password2,
    acceptTos, // either "on" or undefined
    avatar,
  } = req.body;
  // @TODO: Complete user sign up
  // Check password typed correctly by user twice
  if (password !== password2) {
    return res
      .status(400)
      .render('user/signup', { error: 'passwords do not match' });
  }
  // User must not exist in the database for sign up request
  let user = await User.findOne({ username });
  if (user) {
    return res
      .status(400)
      .render('user/signup', { error: `${username}: username already used` });
  }

  // bcrypt is used to hash the user's plain text password with 10 salt rounds
  /* The higher the saltRounds value, the more time the hashing algorithm takes.
  should select a number that is high enough to prevent attacks,
  but not slower than potential user patience. The default value is 10.
  */
  const password_hash = await bcrypt.hash(password, 10);

  // Create the user record on the database
  user = await User.create({
    firstname,
    lastname,
    username,
    avatar,
    password_hash,
  });

  // Once user record is created, it's a sign up success
  // Return user details and redirect to confirm sign up
  res.setHeader('user', user.id);
  req.user = user;
  res.redirect('/user/authenticated');
});

router.get('/signout', (req, res) => {
  // @TODO: Complete user sign out

});

// renders sign up page
router.get('/signup', (req, res) => {
  res.render('user/signup');
});

// renders sign in page
router.get('/signin', (req, res) => {
  res.render('user/signin');
});

router.get('/authenticated', (req, res) => {
  res.render('user/authenticated');
});

module.exports = router;
