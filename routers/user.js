const express = require("express")

const User = require("../models/user")
const auth = require("../middleware/auth")

const router = express.Router()

router.post('/register', async (req, res) => {
    const user = new User(req.body)
    user.save()
    .then((user) => {res.status(200).send({user})})
    .catch((e) => {res.status(400).send(e)})
})

router.post('/login', async (req, res) => {
    try{
        const email = req.body.email
        const username = req.body.username
        let userChoice = ""
        if(email){
            userChoice = email
        }
        else{
            userChoice = username
        }
        const password = req.body.password
        const user = await User.findByCredentials(userChoice, password)
        const token = await user.generateToken()
        const userObject = user.toJSON()
        res.status(200).send({user, token})
    }catch(e){
        res.status(400).send(e.message)
    }
})

router.get('/profile', auth, async (req, res) => {
    res.status(200).send(req.user)
})

router.delete('/logout', auth, async (req, res) => {
    try{
        req.user.tokens = req.user.tokens.filter((el) => {
            return el !== req.token
        })
        await req.user.save()
        res.send()
    }
    catch(e){
        res.status(500).send(e)
    }
})

module.exports = router