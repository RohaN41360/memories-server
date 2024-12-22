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
const cookieParser = require('cookie-parser');
app.use(cookieParser());

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
    default: 'https://res.cloudinary.com/dxw6gft9d/image/upload/v1717928295/memories/dummyImage_doe6xo.jpg' // You can set a default image URL if none is provided
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

// Create a Mongoose schema Media
const mediaSchema = new mongoose.Schema({
  name: String,
  description: String,
  url: String,
  public_id:String,
  likes:{
      type: Number,
      default: 0
  },
  user: userSchema
},
{
  timestamps: true //important
});

// Create a Mongoose model
const Media = mongoose.model('Media', mediaSchema);


const authMiddleware = async (req, res, next) => {
  // Retrieve token from Authorization header
  const authHeader = req.header("Authorization");

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    // Token is missing or improperly formatted
    return res.status(401).json({ error: 'Please Login' });
  }

  // Extract the token part
  const token = authHeader.split(" ")[1];

  try {
    const isValidToken = jwt.verify(token, process.env.JWT_SECRET);

    const userData = await User.findOne({ _id: isValidToken.userId }).select({ password: 0 });
    if (!userData) {
      return res.status(401).json({ error: 'Invalid token or user not found' });
    }

    req.user = userData;
    req.token = token;
    req.userId = userData._id;
    next();
  } catch (error) {
    console.error("Token verification error:", error);
    return res.status(401).json({ error: 'Invalid token' });
  }
};




  // Define a route for file upload
  app.post('/upload', authMiddleware, upload.single('file'), async (req, res) => {
    try {
        // Upload file to Cloudinary
        const result = await cloudinary.uploader.upload(req.file.path, { folder: "memories" });

        // Create a new media object with user details
        const media = new Media({
            name: req.body.name,
            description: req.body.description,
            url: result.secure_url,
            public_id: result.public_id
        });

        // Save the media object to MongoDB
        await media.save();

        // Find the user without selecting the password and posts
        const user = await User.findById(req.user._id);
        if (!user) {
            throw new Error("User not found");
        }

        // Add user details to the media object
        media.user = user;
        // Save the media object again to include user details
        await media.save();

      user.posts.push(media._id); // Assuming req.user._id contains the logged-in user's ID
      await user.save();

        clearUploadsFolder();
        res.status(200).json({ message: 'Post Upload successful' });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'An error occurred' });
    }
});


  
app.get('/getposts',authMiddleware,(req,res)=>{
        Media.find()
        .then(media =>res.json(media))
        .catch(err =>res.status(400).json('error: '+err))
    })
  

// Get user details by ID
app.get('/users/:id', (req, res) => {
  // Assuming you have a User model
  User.findById(req.params.id)
      .then(user => {
          if (!user) {
              return res.status(404).json({ message: 'User not found' });
          }
          // Return the user details
          res.json(user);
      })
      .catch(err => res.status(400).json({ message: 'Error fetching user details', error: err }));
});

    
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
app.post("/newuser", upload.single('file'), async (req, res) => {
  try {
    const { username, email, password, firstname, lastname } = req.body;
    const existingEmail = await User.findOne({ email });
    const existingUsername = await User.findOne({ username });

    if (existingEmail) {
      return res.status(400).json({ message: 'User with the same email already exists' });
    }
    if (existingUsername) {
      return res.status(400).json({ message: 'User with the same Username already exists' });
    }

    let profilePicture;
    if (req.file) {
      const result = await cloudinary.uploader.upload(req.file.path, { folder: "memories" });
      profilePicture = result.secure_url;
      clearUploadsFolder();
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      username, email, password: hashedPassword, firstname, lastname, profilePicture
    });

    const userId = await user.save();
    const token = jwt.sign({ userId: userId._id, userEmail: userId.email }, process.env.JWT_SECRET, { expiresIn: '24h' });

    return res.status(201).json({ message: 'User Created Profile Successfully', token: token });

  } catch (error) {
    console.log(error);
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
      return res.status(401).json({ message: 'Invalid Credentials' });
    }

    // Generate JWT token
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    // Store token in cookies
    // res.cookie('token', token, { httpOnly: true, maxAge: 3600000 }); // Expires in 1 hour (3600000 ms)

    // Respond with token
    res.status(200).json({ token });
    
    
  } catch (error) {
    console.error('Error logging in:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

//logout
app.post("/logout",(req, res) => {
  // Clear token cookie
  res.clearCookie('token');

  // Optionally, you may redirect the user to a login page or send a response indicating successful logout
  res.status(200).json({ message: 'Logout successful' });
});

//get User
app.get('/user',authMiddleware,(req,res)=>{
  try {
    const userData = req.user;
    res.status(200).json({msg:userData})
  } catch (error) {
    console.log(error)
  }
})


// Update user profile details
// Update existing user profile
app.patch("/updateuserprofile/:id", upload.single('file'), async (req, res) => {
  try {
    const { username, email, password, firstname, lastname } = req.body;
    const { id } = req.params;

    // Check if the user exists by ID
    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if the email or username already exists, but exclude the current user's email or username
    const existingEmail = await User.findOne({ email, _id: { $ne: id } });
    const existingUsername = await User.findOne({ username, _id: { $ne: id } });

    if (existingEmail) {
      return res.status(400).json({ message: 'User with the same email already exists' });
    }
    if (existingUsername) {
      return res.status(400).json({ message: 'User with the same username already exists' });
    }

    // If a new file (profile picture) is uploaded, handle it
    let profilePicture;
    if (req.file) {
      const result = await cloudinary.uploader.upload(req.file.path, { folder: "memories" });
      profilePicture = result.secure_url;
      clearUploadsFolder(); // Make sure you clean up uploaded files after processing
    }

    // Update user details
    if (username) user.username = username;
    if (email) user.email = email;
    if (firstname) user.firstname = firstname;
    if (lastname) user.lastname = lastname;
    if (password) {
      // Only update the password if provided, hash it before saving
      user.password = await bcrypt.hash(password, 10);
    }
    if (profilePicture) user.profilePicture = profilePicture;

    // Save the updated user
    await user.save();

    // Optionally, generate a new token if necessary (if you want the user to have a refreshed token after updating profile)
    const token = jwt.sign({ userId: user._id, userEmail: user.email }, process.env.JWT_SECRET, { expiresIn: '24h' });

    return res.status(200).json({ message: 'Profile updated successfully', token: token });

  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: `An error occurred: ${error.message}` });
  }
});


// GET method to retrieve all posts made by a particular user
app.get('/user/:username/posts', authMiddleware,async (req, res) => {
  try {
    // Find the user by username
    const user = await User.findOne({ username: req.params.username });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Extract post ids from the user's posts array
    const postIds = user.posts;

    // Find posts data from the Media collection using the post ids
    const postsData = await Media.find({ _id: { $in: postIds } });

    res.status(200).json({ posts: postsData });
  } catch (error) {
    console.error('Error fetching user posts:', error);
    res.status(500).json({ error: 'Internal server error' });
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