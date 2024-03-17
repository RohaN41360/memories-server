const express = require('express');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const cors = require('cors');
const mongoose = require('mongoose')
require('dotenv').config();
const app = express();
const port = process.env.PORT || 5000;
app.use(cors());
app.use(express.json());
app.use(express.static('public'))
const fs = require('fs');
const uploadPath = 'uploads/';
const bcrypt = require('bcryptjs');
var jwt = require('jsonwebtoken');

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.CLOUD_API_KEY,
  api_secret:process.env.CLOUD_API_SECRET
});

// Configure multer for file upload

const URI = process.env.MONGODB_URL
mongoose.connect(URI)
.then(()=>{
    console.log("✔ connected to the database")
}).catch(()=>{
    console.log("❌ Could not Connect")
})

// Configure multer for file upload
const upload = multer({ dest: 'uploads/' });
// Create a Mongoose schema
const mediaSchema = new mongoose.Schema({
    name: String,
    description: String,
    url: String,
    likes:{
        type: Number,
        default: 0
    }
  },
  {
    timestamps: true //important
});
  
  // Create a Mongoose model
  const Media = mongoose.model('Media', mediaSchema);


// Define the User Schema
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true
  },
  email: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  },
  // Basic user details
  firstname: {
    type: String,
    required: true
  },
  lastname: {
    type: String,
    required: true
  },
   profilePicture: {
    type: String, // Store the URL of the profile picture
    default: 'default_profile_picture_url.jpg' // You can set a default image URL if none is provided
  },
  // Posts made by the user
  posts: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Media'
  }]
});

// Define and export the User model
const User = mongoose.model('User', userSchema);
module.exports = User;

  
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};
  // Define a route for file upload
  app.post('/upload',authenticateToken, upload.single('file'), async (req, res) => {
    try {
      // Upload file to Cloudinary
      const result = await cloudinary.uploader.upload(req.file.path,{folder: "memories"});
  
      // Create a new media object
      const media = new Media({
        name: req.body.name,
        description: req.body.description,
        url: result.secure_url
      });
  
      // Save the media object to MongoDB
      await media.save();
      clearUploadsFolder();
      // console.log({public_id: result.public_id, url: result.secure_url})
      res.status(200).json({ message: 'File uploaded successfully' });

    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'An error occurred' });
    }
  });

  
app.get('/getposts',(req,res)=>{
        Media.find()
        .then(media =>res.json(media))
        .catch(err =>res.status(400).json('error: '+err))
    })
  

//Update Like count 
app.patch('/getposts/:id',(req,res)=>{
    const likes = req.body.likes;
    
    
    Media.findByIdAndUpdate(req.params.id,{
        likes
    })
    .then(() => res.json('Post updated Successfully'))
           .catch(err => res.status(400).json('Error: ' + err));

})

app.delete('/delete/:id', async (req, res) => {
  try {
    const media = await Media.findByIdAndDelete(req.params.id);

    const publicId = extractPublicId(media.url);
  
    

    res.json({ msg: 'Deleted a Post', pid: publicId });
  } catch (err) {
    return res.status(500).json({ msg: err.message });
  }
});


app.get('/getusers',(req,res)=>{
  User.find()
  .then(user =>res.json(user))
  .catch(err =>res.status(400).json('error: '+err))
})

//register new user
app.post("/newuser",upload.single('file'),async (req,res)=>{
  try {

    const { username, email, password, firstname,lastname } = req.body;
    const existingEmail = await User.findOne({ email });
    const existingUsername = await User.findOne({ username });
    // Upload file to Cloudinary
    const result = await cloudinary.uploader.upload(req.file.path,{folder: "memories"});

    if(existingEmail)
    {
      return res.status(400).json({ message: 'User with the same email already exists' });
    }
    if(existingUsername)
    {
      return res.status(400).json({ message: 'User with the same Username already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10); 
    const user  = new User({
      username, email, password:hashedPassword, firstname,lastname,profilePicture:result.secure_url 
    });
  
    const userId = await user.save();
    clearUploadsFolder();
    const token = jwt.sign({ userId: userId._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    if(user)
    {
      return res.status(201).json({ message: 'User Created Profile Successfully with Userid '+userId._id });
    }
  } catch (error) {
    console.log(error)
    return res.status(500).json({ error: `An error occurred ${error}` });
  }

})

// POST route for user login
app.post('/userlogin', async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body;

    // Check if a user with the provided username or email exists
    const user = await User.findOne({ $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }] });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) { 
      return res.status(401).json({ message: 'Invalid password' });
    }

    // Generate JWT token
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.status(200).json({ token });
    
  } catch (error) {
    console.error('Error logging in:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


// Helper function to extract public ID from Cloudinary URL
function extractPublicId(url) {
  const startIndex = url.lastIndexOf('/') + 1;
  const endIndex = url.lastIndexOf('.');
  return url.substring(startIndex, endIndex);
}

// Function to clear the upload folder
const clearUploadsFolder = () => {
  fs.readdir(uploadPath, (err, files) => {
    if (err) {
      console.error(err);
      return;
    }

    // Delete each file in the upload folder
    files.forEach((file) => {
      fs.unlink(uploadPath + file, (err) => {
        if (err) {
          console.error(err);
        }
      });
    });
  });
};

// Call the function to clear the upload folder
clearUploadsFolder();
    
// Start the server
app.listen(port, () => {
    console.log(`Server is running at http://localhost:${port}`)
})