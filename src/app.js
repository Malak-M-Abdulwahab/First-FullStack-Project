// npm i mongodb express mongoose bcryptjs jsonwebtoken nodemon

const jwt = require("jsonwebtoken")

const myToken = () => {
    const token = jwt.sign({_id: "69dbb1073cafe41c40f24a1a"}, "malokaloka")

    const tokenVerify = jwt.verify(token, "malokaloka")
}

const express = require("express")
const app = express()

const port = process.env.PORT || 3000

require("./db/mongoose")

app.use(express.json())

const userRouter = require("./routers/user")

app.use(userRouter)

app.listen(port, () => {
    console.log("Application is running on port: " + port)
})