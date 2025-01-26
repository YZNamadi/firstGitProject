const mongoose= require("mongoose");

const usersSchema= new mongoose.Schema({
    email:{
        type: String,
        required: [true, 'Email is required'],
        unique: true,
        trim: true,
        minLength: [5, 'Email must be at least 5 characters long'],
        maxLength: [50, 'Email must be at most 50 characters long'],
        lowercase: true
    },
    password:{
        type: String,
        required: [true, 'Password is required'],
        trim: true,
        select: false,
        minLength: [8, 'Password must be at least 8 characters long'],
        maxLength: [2000, 'Password must be at most 50 characters long']
    },
    verified:{
        type: Boolean,
        default: false
    },
    verificationCode:{
        type: String,
        select: false,
    },
    verificationCodeValidation:{
        type: String,
        select: false,
    },
    passwordResetCode:{
        type: String,
        select: false,
    },
    passwordResetCodeValidation:{
        type: Number,
        select: false,
    },
    
},{
    timestamps: true
});

module.exports= mongoose.model('Users', usersSchema);