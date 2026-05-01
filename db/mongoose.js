const mongoose = require("mongoose")

mongoose.connect(process.env.MONGODB_URL + process.env.DATABASE_NAME)