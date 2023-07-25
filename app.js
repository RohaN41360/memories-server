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

  
  // Define a route for file upload
  app.post('/upload', upload.single('file'), async (req, res) => {
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