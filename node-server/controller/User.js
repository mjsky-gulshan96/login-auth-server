const router = require('express').Router();
const jwt = require('jsonwebtoken');
const profileModel = require('../model/profileModel');
require('dotenv').config();

router.get('/profile', async (req, res) => {
    let result = {
        error: false
    }
    if (!req.session.authToken) {
        return res.status(401).json('Unauthorised Request')
    }
    let cookies = req.header('Cookie');
    let authToken, authSubstr;
    if (cookies.includes('authToken')) {
        let start = cookies.indexOf('authToken')
        let end = cookies.indexOf(';', start);
        authSubstr = cookies.substring(start, end)
    }

    if (authSubstr.includes('authToken')) {
        authToken = authSubstr.split('=')[1];
    }

    if (!authToken) {
        result.errorMsg = "UnAuthorised Request"
        return res.status(403).json(result)
    }
    let useremail;
    try {
        useremail = jwt.verify(authToken, process.env.AUTHORISATION_SECRET).email;
    } catch (error) {
        res.status(204).json('Invalid user')
    }
    if (useremail) {
        result.user = await profileModel.findOne({ email: useremail })
    }
    res.status(200).json(result)
})

router.get('/profile/passport', async (req, res) => {
    let passportSession = req.session.passport;
    if (!passportSession) {
        return res.status(403).json('UnAuthorised Request')
    }
    useremail = passportSession.user.email
    const user = await profileModel.findOne({email: useremail})
    res.status(200).json(user)
})


module.exports = router