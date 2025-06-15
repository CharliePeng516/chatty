import User from "../models/user.model.js";
import bcrypt from "bcryptjs";
import {generateToken} from "../lib/utils.js";


export const login = async(req, res) => {
    const {email, password} = req.body;
    try{
        const user = await User.findOne({ email});
        if(!user) {
            return res.status(400).json({message: 'Invalid credentials'});
        }
        
        const isPasswordCorrect = await bcrypt.compare(password, user.password);
        if(!isPasswordCorrect) {
            return res.status(400).json({message: 'Invalid credentials'});
        }
        generateToken(user._id, res); // Generate JWT token
        res.status(200).json({
            _id: user._id,
            fullName: user.fullName,
            email: user.email,
            profilePicture: user.profilePicture,
        });
    }catch (error) {
        console.error('Login error:', error.message);
        res.status(500).json({message: 'Internal server error'});
    }
};

export const signup = async  (req, res) => {
    const{fullName, email, password, profilePicture} = req.body;
    try {  
        // Handle signup logic here
        //Hash the password and save the user to the database
        if(!fullName || !email || !password) {
            return res.status(400).json({message: 'Please fill all the fields'});
        }
        if(password.length < 6) {
            return res.status(400).json({message:'Password must be at least 6 characters long'});
        }
        const user = await User.findOne({ email});
        if(user) {
            return res.status(400).send('User already exists with this email');
        }
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const newUser = new User({
            fullName,
            email,
            password: hashedPassword
        });

        if (newUser) {
            generateToken(newUser._id, res); // Generate JWT token
            await newUser.save();
            res.status(201).json({
                _id: newUser._id,
                fullName: newUser.fullName,
                email: newUser.email,
                profilePicture: newUser.profilePicture,
            });
        } else {
            res.status(400).json({message: 'invalid user data'});
        }
    }   catch (error) {
        console.error('Signup error:', error.message);
        res.status(500).json({message: 'Internal server error'});
    }
}
export const logout = (req, res) => {
    try{
        res.cookie('jwt',"", {maxAge:0});
        res.status(200).json({message: 'Logout successful'});

    }    catch (error) {
        console.error('Logout error:', error.message);
        res.status(500).json({message: 'Internal server error'});
    }
};

export const updateProfile = async (req, res) => {
    
}