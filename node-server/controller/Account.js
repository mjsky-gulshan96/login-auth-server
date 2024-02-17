const router = require('express').Router();
const jwt = require('jsonwebtoken');
const profileModel = require('../model/profileModel');
require('dotenv').config()

router.post('/register', async (req, res) => {
    const { name, email, password } = req.body

    const isExist = await profileModel.findOne({ email: email });
    if (isExist) {
        return res.status(208).json('user already exist');
    }
    let newProfile = new profileModel({ name, email, password });
    await newProfile.save()
    res.status(200).json(newProfile)
})

router.post('/login', async (req, res) => {
    let result = {
        error: false
    }
    const { email, password, rememberMe } = req.body;
    const user = await profileModel.findOne({ email: email });
    if (!user) {
        result.error = true,
            result.errorMsg = 'user not found'
        return res.status(204).json(result);
    } else if (user && user.password !== password) {
        result.error = true,
            result.errorMsg = 'incorrct password'
        return res.status(404).json(result);
    }

    // generate a authorization token
    let auth_token = jwt.sign({ email }, process.env.AUTHORISATION_SECRET, {
        expiresIn: '5m'
    })
    res.cookie('authToken', auth_token, {
        maxAge: 1000 * 60 * 5,
        path: '/',
        sameSite: 'none',
        httpOnly: true,
        secure: true
    })
    result.auth_token = auth_token

    // generate remember me token
    if (rememberMe) {
        let remeber_token = jwt.sign({ email, password }, process.env.REMEMBER_ME_SECRET, {
            expiresIn: '5m'
        })
        res.cookie('rememberMe', remeber_token, {
            maxAge: 1000 * 60 * 10,
            path: '/',
            sameSite: 'none',
            httpOnly: true,
            secure: true
        })
        // req.session.remeber_token = remeber_token
        result.remeber_token = remeber_token
    }
    result.user = user
    res.status(200).json(result)
})

router.get('/logout', (req, res) => {
    let authToken = req.header('authToken');
    let remeber_token = req.header('rememberMe');
    if (!authToken) {
        let cookies = req.header('Cookie');
        if (cookies && cookies.includes('rememberMe')) {
            let authTokenPair = cookies.split(';')[0]
            authToken = authTokenPair.split('=')[1]
        } else if (cookies) {
            authToken = cookies.split('=')[1]
        }
    }

    if (!authToken) {
        return res.status(404).json('UnAuthorised Request')
    }
    // clear auth token
    res.clearCookie('authToken', {
        domain: 'http://localhost:5173',
        path: '/'
    })
    res.clearCookie('rememberMe')

    res.status(200).json('you are logged out')

})

router.get('/logout/passport', (req, res) => {
    let passportSession = req.session.passport;
    let auth_token = req.header('auth_token');
    let remeber_token = req.header('remeber_token');

    if (!auth_token && !passportSession) {
        return res.status(404).json('UnAuthorised Request')
    }


    if (auth_token) {
        jwt.destroy(auth_token)
        res.status(200).json('user logged out');
    } else if (passportSession) {
        req.session.destroy(function (err) {
            if (!err) {
                res.clearCookie('connect.sid', { path: '/' }).json('user logged out');
            }
        });
    }
})


module.exports = router;