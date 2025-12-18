const multer = require('multer');
const path = require('path');

// Configure storage (memory storage for Cloudinary)
const storage = multer.memoryStorage();

// File filter
const fileFilter = (req, file, cb) => {
  const allowedImageTypes = /jpeg|jpg|png|gif|webp/;
  const allowedVideoTypes = /mp4|webm|mov|avi|mkv/;
  
  // Check if it's an image
  if (file.fieldname.startsWith('image')) {
    const extname = allowedImageTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedImageTypes.test(file.mimetype);
    
    if (extname && mimetype) {
      return cb(null, true);
    }
  }
  
  // Check if it's a video
  if (file.fieldname.startsWith('video')) {
    const extname = allowedVideoTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedVideoTypes.test(file.mimetype);
    
    if (extname && mimetype) {
      return cb(null, true);
    }
  }
  
  cb(new Error('Unsupported file type'));
};

// Configure upload limits
const limits = {
  fileSize: 100 * 1024 * 1024, // 100MB max file size
  files: 10 // Max 10 files
};

// Create multer instance
const upload = multer({
  storage,
  fileFilter,
  limits
});

// Middleware for different upload scenarios
const uploadMiddleware = {
  // Single banner image upload
  singleBannerImage: upload.single('bannerImage'),
  
  // Single featured image upload
  singleFeaturedImage: upload.single('featuredImage'),
  
  // Multiple gallery images upload
  galleryImages: upload.array('galleryImages', 10),
  
  // Single video upload
  singleVideo: upload.single('video'),
  
  // Multiple fields upload
  eventMedia: upload.fields([
    { name: 'bannerImage', maxCount: 1 },
    { name: 'featuredImage', maxCount: 1 },
    { name: 'galleryImages', maxCount: 10 },
    { name: 'video', maxCount: 1 }
  ])
};

// Error handling middleware
const handleUploadError = (err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({
        success: false,
        message: 'File too large. Maximum size is 100MB'
      });
    }
    if (err.code === 'LIMIT_FILE_COUNT') {
      return res.status(400).json({
        success: false,
        message: 'Too many files. Maximum is 10'
      });
    }
  } else if (err) {
    return res.status(400).json({
      success: false,
      message: err.message || 'File upload error'
    });
  }
  next();
};

module.exports = {
  uploadMiddleware,
  handleUploadError
};