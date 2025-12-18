const cloudinary = require('cloudinary').v2;
const streamifier = require('streamifier');

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true
});

class CloudinaryService {
  // Upload file to Cloudinary
  static async uploadFile(file, options = {}) {
    try {
      const uploadOptions = {
        folder: options.folder || 'events',
        resource_type: options.resourceType || 'auto',
        overwrite: options.overwrite || true,
        transformation: options.transformation,
        public_id: options.publicId,
        ...options
      };

      let result;
      
      if (file.buffer) {
        // Upload from buffer (for Multer)
        result = await new Promise((resolve, reject) => {
          const uploadStream = cloudinary.uploader.upload_stream(
            uploadOptions,
            (error, result) => {
              if (error) reject(error);
              else resolve(result);
            }
          );
          
          streamifier.createReadStream(file.buffer).pipe(uploadStream);
        });
      } else if (file.path) {
        // Upload from file path
        result = await cloudinary.uploader.upload(file.path, uploadOptions);
      } else {
        throw new Error('Invalid file format');
      }

      return {
        url: result.secure_url,
        publicId: result.public_id,
        width: result.width,
        height: result.height,
        format: result.format,
        bytes: result.bytes,
        duration: result.duration,
        thumbnail: result.thumbnail_url,
        metadata: result
      };
    } catch (error) {
      console.error('Cloudinary upload error:', error);
      throw new Error(`Upload failed: ${error.message}`);
    }
  }

  // Upload video with specific optimizations
  static async uploadVideo(file, options = {}) {
    const videoOptions = {
      resource_type: 'video',
      chunk_size: 6000000, // 6MB chunks for large videos
      transformation: [
        { quality: 'auto', fetch_format: 'mp4' }
      ],
      ...options
    };

    return await this.uploadFile(file, videoOptions);
  }

  // Upload image with specific optimizations
  static async uploadImage(file, options = {}) {
    const imageOptions = {
      resource_type: 'image',
      transformation: [
        { quality: 'auto', fetch_format: 'auto' }
      ],
      ...options
    };

    if (options.resize) {
      imageOptions.transformation.push({
        width: options.resize.width,
        height: options.resize.height,
        crop: options.resize.crop || 'fill'
      });
    }

    return await this.uploadFile(file, imageOptions);
  }

  // Delete resources from Cloudinary
  static async deleteResources(publicIds, options = {}) {
    try {
      const result = await cloudinary.api.delete_resources(publicIds, {
        resource_type: options.resourceType || 'image',
        type: options.type || 'upload',
        invalidate: true
      });
      return result;
    } catch (error) {
      console.error('Cloudinary delete error:', error);
      throw new Error(`Delete failed: ${error.message}`);
    }
  }

  // Generate signed upload URL for client-side uploads
  static generateUploadSignature(folder = 'events') {
    const timestamp = Math.round(Date.now() / 1000);
    const params = {
      timestamp,
      folder
    };

    const signature = cloudinary.utils.api_sign_request(
      params,
      process.env.CLOUDINARY_API_SECRET
    );

    return {
      signature,
      timestamp,
      api_key: process.env.CLOUDINARY_API_KEY,
      cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
      folder
    };
  }
}

module.exports = CloudinaryService;