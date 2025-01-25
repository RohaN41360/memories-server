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
  bio: {
    type: String,
    default: ''
  },
  profilePicture: {
    type: String,
    default: 'https://res.cloudinary.com/dxw6gft9d/image/upload/v1717928295/memories/dummyImage_doe6xo.jpg'
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
    try {
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ message: 'Authorization header missing or invalid' });
        }

        const token = authHeader.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({ message: 'No token provided' });
        }

        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            const user = await User.findById(decoded.userId).select('-password');
            
            if (!user) {
                return res.status(401).json({ message: 'User not found' });
            }

            req.user = user;
            next();
        } catch (error) {
            if (error.name === 'TokenExpiredError') {
                return res.status(401).json({ message: 'Token expired' });
            }
            return res.status(401).json({ message: 'Invalid token' });
        }
    } catch (error) {
        console.error('Auth Middleware Error:', error);
        res.status(500).json({ message: 'Server error in authentication' });
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
app.get('/users/:id', async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select('-password');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json(user);
    } catch (err) {
        res.status(400).json({ message: 'Error fetching user details', error: err });
    }
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

app.delete('/posts/:id', authMiddleware, async (req, res) => {
  try {
    // Find the post first to get its details
    const post = await Media.findById(req.params.id);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    // Verify that the user owns this post
    if (post.user._id.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Not authorized to delete this post' });
    }

    // Delete the image from Cloudinary using the public_id
    if (post.public_id) {
      try {
        await cloudinary.uploader.destroy(post.public_id);
      } catch (cloudinaryError) {
        console.error('Error deleting from Cloudinary:', cloudinaryError);
        // Continue with post deletion even if Cloudinary deletion fails
      }
    }

    // Remove the post reference from the user's posts array
    await User.findByIdAndUpdate(
      req.user._id,
      { $pull: { posts: req.params.id } }
    );

    // Delete the post from Media collection
    await Media.findByIdAndDelete(req.params.id);

    res.status(200).json({ 
      message: 'Post deleted successfully',
      deletedPost: post
    });

  } catch (error) {
    console.error('Error deleting post:', error);
    res.status(500).json({ error: 'An error occurred while deleting the post' });
  }
});




app.get('/getusers', async (req, res) => {
    try {
        const users = await User.find().select('-password');
        res.json(users);
    } catch (err) {
        res.status(400).json({ error: err });
    }
});

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
        const user = await User.findOne({
            $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }]
        });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Verify password
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Generate JWT token
        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Send response with token and user data (excluding password)
        const userData = {
            _id: user._id,
            username: user.username,
            email: user.email,
            firstname: user.firstname,
            lastname: user.lastname,
            bio: user.bio,
            profilePicture: user.profilePicture
        };

        res.status(200).json({
            message: 'Login successful',
            token,
            user: userData
        });
    } catch (error) {
        console.error('Login error:', error);
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
app.get('/user', authMiddleware, (req, res) => {
    try {
        // req.user already has password excluded from authMiddleware
        res.status(200).json({ msg: req.user });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});


// Update user profile details
// Update existing user profile
app.patch("/updateuserprofile/:id", upload.single('file'), async (req, res) => {
  try {
    const { username, email, firstname, lastname, bio } = req.body;
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
      try {
        const result = await cloudinary.uploader.upload(req.file.path, { folder: "memories" });
        profilePicture = result.secure_url;
        clearUploadsFolder();
      } catch (cloudinaryError) {
        console.error('Cloudinary upload error:', cloudinaryError);
        return res.status(500).json({ message: 'Error uploading profile picture' });
      }
    }

    // Update user details
    if (username) user.username = username;
    if (email) user.email = email;
    if (firstname) user.firstname = firstname;
    if (lastname) user.lastname = lastname;
    if (bio !== undefined) user.bio = bio;
    if (profilePicture) user.profilePicture = profilePicture;

    // Save the updated user
    await user.save();

    // Generate new token
    const token = jwt.sign(
      { userId: user._id, userEmail: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Return success response with user data
    return res.status(200).json({ 
      message: 'Profile updated successfully', 
      token,
      user: {
        _id: user._id,
        username: user.username,
        email: user.email,
        firstname: user.firstname,
        lastname: user.lastname,
        bio: user.bio,
        profilePicture: user.profilePicture
      }
    });

  } catch (error) {
    console.error('Profile update error:', error);
    if (error.name === 'ValidationError') {
      return res.status(400).json({ message: 'Invalid input data' });
    }
    return res.status(500).json({ message: 'An error occurred while updating profile' });
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


app.get('/search',authMiddleware, async (req,res)=>{
  try {
    const { query } = req.query;

    if (!query || query.trim() === '') {
      return res.status(400).json({ message: 'Search query cannot be empty.' });
    }

    const searchRegex = new RegExp(query, 'i');

    // Search users with more fields and include profile information
    const users = await User.find({
      $or: [
        { username: searchRegex },
        { email: searchRegex },
        { firstname: searchRegex },
        { lastname: searchRegex },
      ],
    }).select('-password')  // Exclude password but include all other fields
      .populate({
        path: 'posts',
        select: '_id'  // Only get post IDs for counting
      });

    // Transform the response to include only necessary fields
    const transformedUsers = users.map(user => ({
      _id: user._id,
      username: user.username,
      firstname: user.firstname,
      lastname: user.lastname,
      bio: user.bio,
      profilePicture: user.profilePicture,
      posts: user.posts,
      createdAt: user.createdAt
    }));

    res.status(200).json(transformedUsers);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'An error occurred while searching for users.' });
  }
})

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

// Get user profile by username
app.get('/user/profile/:username', authMiddleware, async (req, res) => {
  try {
    const { username } = req.params;

    // Find user by username and exclude password
    const user = await User.findOne({ username })
      .select('-password')
      .populate({
        path: 'posts',
        select: '_id name description url likes createdAt',
        options: { sort: { 'createdAt': -1 } }
      });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Transform the response to include only necessary fields
    const userProfile = {
      _id: user._id,
      username: user.username,
      firstname: user.firstname,
      lastname: user.lastname,
      bio: user.bio,
      profilePicture: user.profilePicture,
      posts: user.posts,
      isOwnProfile: req.user._id.toString() === user._id.toString()
    };

    res.status(200).json(userProfile);
  } catch (error) {
    console.error('Error fetching user profile:', error);
    res.status(500).json({ message: 'Error fetching user profile' });
  }
});