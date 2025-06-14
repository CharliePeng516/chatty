import mongoose from "mongoose";
const userSchema = new mongoose.Schema
({
  fullName: {
    type: String,
    required: true,
    unique: true,
    trim: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
  },
  password: {
    type: String,
    required: true,
    minlength: 6,
  },
  profilePicture: {
    type: String,
    default: "", // Placeholder URL
  },
},
{ timestamps: true }
);

const User = mongoose.model("User", userSchema);
export default User;