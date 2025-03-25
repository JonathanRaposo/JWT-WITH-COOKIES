
const jwt = require('jsonwebtoken');

function generateToken(payload) {
    return jwt.sign(payload, process.env.TOKEN_SECRET, { algorithm: 'HS256', expiresIn: '1h' })
}
module.exports = generateToken;