const jwt = require('jsonwebtoken')
const { AuthenticationError } = require('apollo-server-express')
const bcrypt = require('bcrypt')
require('dotenv').config()

// set token secret and expiration date
const secret = process.env.JWT_SECRET
const expiration = '2h'


const authMiddleware = (context) => {
  const authorization = context.req.headers.authorization

  if (authorization) {
    const token = authorization.replace('Bearer', '')
    if (token) {
      try {
        const { data } = jwt.verify(token, secret, { maxAge: expiration });
        req.user = data;
      } catch {
        console.log('Invalid token');
        return res.status(400).json({ message: 'invalid token!' });
      }
      next()
    }
    throw new AuthenticationError('Authorization header needs to be provided')
  }

}
module.exports = authMiddleware




module.exports = {
  // function for our authenticated routes
  authMiddleware: function (req, res, next) {
    // allows token to be sent via  req.query or headers
    let token = req.query.token || req.headers.authorization;

    // ["Bearer", "<tokenvalue>"]
    if (req.headers.authorization) {
      token = token.split(' ').pop().trim();
    }

    if (!token) {
      return res.status(400).json({ message: 'You have no token!' });
    }

    // verify token and get user data out of it
    try {
      const { data } = jwt.verify(token, secret, { maxAge: expiration });
      req.user = data;
    } catch {
      console.log('Invalid token');
      return res.status(400).json({ message: 'invalid token!' });
    }

    // send to next endpoint
    next();
  },
  signToken: function ({ username, email, _id }) {
    const payload = { username, email, _id };

    return jwt.sign({ data: payload }, secret, { expiresIn: expiration });
  },
};
