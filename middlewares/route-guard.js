const jwt = require('jsonwebtoken');


// Helper function to parse cookies

function parseCookies(req) {

    const rawCookies = req.headers.cookie;
    if (!rawCookies) {
        return {}
    }
    const cookies = {};
    const cookiePairs = rawCookies.split('; ');

    for (const cookie of cookiePairs) {
        const [key, value] = cookie.split('=');
        cookies[key] = decodeURIComponent(value);
    }
    return cookies;

}

function isLoggedIn(req, res, next) {

    const cookies = parseCookies(req);
    const token = cookies.authToken;

    if (!token) {
        res.status(401).redirect('/login');
        return;
    }
    try {
        const decoded = jwt.verify(token, process.env.TOKEN_SECRET);
        req.user = decoded;
        next();

    } catch (err) {
        console.log(err)
        res.render('auth/403-error.hbs', { errorMessage: err.message })
    }
}

function isLoggedOut(req, res, next) {

    const cookies = parseCookies(req);
    const token = cookies.authToken;

    if (token) {
        try {
            jwt.verify(token, process.env.TOKEN_SECRET);
            return res.redirect('/');
        } catch (err) {
            res.render('auth/403-error.hbs', { errorMessage: 'Invalid or expired token' })
        }
    }
    next() //continue processing if no token or invalid token
}

function isAdmin(req, res, next) {

    if (req.user && req.user.isAdmin) {
        return next();
    }
    res.status(403).render('admin/403-page.hbs');
}
module.exports = { isLoggedIn, isLoggedOut, isAdmin };