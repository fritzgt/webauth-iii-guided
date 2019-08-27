const router = require('express').Router();
const bcrypt = require('bcryptjs');

// installed JWT json web token library
const jwt = require('jsonwebtoken');
//Import the scret for the JWT
const secrets = require('./config/secrets');

const Users = require('../users/users-model.js');

// for endpoints beginning with /api/auth
router.post('/register', (req, res) => {
  let user = req.body;
  const hash = bcrypt.hashSync(user.password, 10); // 2 ^ n
  user.password = hash;

  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

router.post('/login', (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        //Creating a JWT token after user has been authenticated
        //This normally happen automatically
        //But we will do it manually here
        const token = generateToken(user);

        res.status(200).json({
          message: `Welcome ${user.username}!`,
          //passing the token generated using JWT
          token
        });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});
//Creating token function
function generateToken(user) {
  //Set basic data
  const payload = {
    subject: user.id,
    username: user.username
    //other optiona data
  };
  //Options object
  const options = {
    expiresIn: '1d'
  };
  // extract the secret away so it can be required and used where needed
  return jwt.sign(payload, secrets.jwtSecret, options); // this method is synchronous
}

module.exports = router;
