// installed JWT json web token library
const jwt = require('jsonwebtoken');
//Import the scret for the JWT
const secrets = require('./config/secrets');

module.exports = (req, res, next) => {
  //the token will be on the headers
  //use postman to manually enter the needed data in headers
  const token = req.headers.authorization;
  if (token) {
    jwt.verify(token, secrets.jwtSecret, (err, decodedToken) => {
      if (err) {
        //Invalid token
        res.status(401).json({ message: 'Invalid token!' });
      } else {
        //save decored token for other end points
        req.decodedJwt = decodedToken;
        next();
      }
    });
  } else {
    //No token found
    res.status(401).json({ message: 'Missing token!' });
  }
};
