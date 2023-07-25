// const router = require('express').Router();
// const multer = require('multer');
// const path = require('path');
// const User = require('../modals/user.modal');

// const upload = multer({ dest: 'uploads/' });

// // Define a route for file upload
// app.post('http://localhost:5000/upload', upload.single('file'), async (req, res) => {
//     try {
//       // Upload file to Cloudinary
//       const result = await cloudinary.uploader.upload(req.file.path);
  
//       // Create a new user object
//       const user = new User({
//         name: req.body.name,
//         description: req.body.description,
//         photo: result.secure_url
//       });
  
//       // Save the user object to MongoDB
//       await user.save();
  
//       res.status(200).json({ message: 'File uploaded successfully' });
//     } catch (err) {
//       console.error(err);
//       res.status(500).json({ error: 'An error occurred' });
//     }
//   });


