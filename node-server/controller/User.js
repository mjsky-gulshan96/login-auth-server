const router = require('express').Router();
const jwt = require('jsonwebtoken');
const profileModel = require('../model/profileModel');
require('dotenv').config();

router.get('/profile', async (req, res) => {
    let result = {
        error: false
    }
    let cookies = req.header('Cookie');
    let authToken;
    if (cookies && cookies.includes('rememberMe')) {
        let authTokenPair = cookies.split(';')[0]
        authToken = authTokenPair.split('=')[1]
    } else if (cookies) {
        authToken = cookies.split('=')[1]
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