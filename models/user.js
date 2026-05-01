const mongoose = require("mongoose")
const validator = require("validator")
const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");

const schema = new mongoose.Schema({
    username: {
        type: String,
        unique: true,
        required: true,
        trim: true
    },
    password: {
        type: String,
        required: true,
        trim: true,
        minlength: 8,
        validate(val){
            let password = new RegExp("^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])");
            if(!password.test(val)){
                throw new Error ("Password must be longer than 8 characters and have: Uppercase, Lowercase, Numbers, Special Characters")
            }
        }
    },
    email: {
        type: String,
        required: true,
        trim: true,
        lowercase: true,
        unique: true,
        validate(val){
            if(!validator.isEmail(val)){
                throw new Error ("Please Enter The Correct Email.")
            }
        }
    },
    age: {
        type: Number,
        required: true,
        validate(val){
            if(val <= 0){
                throw new Error ("Please Enter The Correct Age.")
            }
        }
    },
    country: {
        type: String,
        trim: true,
        required: true
    },
    city: {
        type: String,
        trim: true,
        required: true
    },
    tokens: {
        type: Array,
        required: true
    }
})

schema.pre("save", async function () {
    const newUser = this
    if(newUser.isModified("password")){
        newUser.password = await bcryptjs.hash(newUser.password, 8)
    }
})

schema.statics.findByCredentials = async function(userChoice, userPassword){
    if(validator.isEmail(userChoice)){
        const user = await this.findOne({email: userChoice})
        if(!(user)){
            throw new Error ("Account does not exist.")
        }
        else{
            const check = await bcryptjs.compare(userPassword, user.password)
            if(!check){
                throw new Error ("Password is incorrect.")
            }
            else{
                return user
            }
        }
        
    }
    else{
        const user = await this.findOne({username: userChoice})
        if(!(user)){
            throw new Error ("Account does not exist.")
        }
        else{
            const check = await bcryptjs.compare(userPassword, user.password)
            if(!check){
                throw new Error ("Password is incorrect.")
            }
            else{
                return user
            }
        }
    }
}

schema.methods.generateToken = async function(){
    const user = this
    const token = jwt.sign({_id: user._id.toString()}, user.password)
    if(!(user.tokens.includes(token)))
        user.tokens = user.tokens.concat(token)
    return token
}

const User = mongoose.model("User", schema)

module.exports = User