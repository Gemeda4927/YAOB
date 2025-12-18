// controllers/event.controller.js
const Event = require('../models/event.model');
const CloudinaryService = require('../utils/cloudinary');

// Response utility
const sendResponse = (res, statusCode, data = null, message = '') => {
  const response = {
    success: statusCode >= 200 && statusCode < 300,
    message: message || (statusCode >= 200 && statusCode < 300 ? 'Success' : 'Error'),
    timestamp: new Date().toISOString(),
  };

  if (data !== null) {
    response.data = data;
  }

  return res.status(statusCode).json(response);
};

// ==================== BASIC EVENT CONTROLLERS ====================

// GET ALL EVENTS
exports.getAllEvents = async (req, res) => {
  try {
    const { status, eventType, locationType, page = 1, limit = 10 } = req.query;
    
    const query = {};
    
    // Regular users can only see published events
    if (!req.user?.hasPermission('view_events')) {
      query.status = 'published';
    } else if (status) {
      query.status = status;
    }
    
    if (eventType) query.eventType = eventType;
    if (locationType) query.locationType = locationType;
    
    const skip = (page - 1) * limit;
    
    const events = await Event.find(query)
      .populate('organizer', 'name email')
      .sort({ startDate: 1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Event.countDocuments(query);
    
    return sendResponse(res, 200, {
      events,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit),
      },
    }, 'Events retrieved successfully');
  } catch (error) {
    console.error('Get all events error:', error);
    return sendResponse(res, 500, null, 'Failed to retrieve events');
  }
};

// GET SINGLE EVENT
exports.getEventById = async (req, res) => {
  try {
    const event = await Event.findById(req.params.id)
      .populate('organizer', 'name email')
      .populate('coOrganizers', 'name email');
    
    if (!event) {
      return sendResponse(res, 404, null, 'Event not found');
    }
    
    // Check permissions for draft events
    if (event.status === 'draft' && 
        !req.user?.hasPermission('view_events') && 
        event.organizer._id.toString() !== req.user?._id.toString()) {
      return sendResponse(res, 403, null, 'Access denied');
    }
    
    return sendResponse(res, 200, { event }, 'Event retrieved successfully');
  } catch (error) {
    console.error('Get event by ID error:', error);
    return sendResponse(res, 500, null, 'Failed to retrieve event');
  }
};

// GET UPCOMING EVENTS
exports.getUpcomingEvents = async (req, res) => {
  try {
    const events = await Event.find({
      status: 'published',
      startDate: { $gt: new Date() }
    })
    .sort({ startDate: 1 })
    .limit(10);
    
    return sendResponse(res, 200, { events }, 'Upcoming events retrieved');
  } catch (error) {
    console.error('Get upcoming events error:', error);
    return sendResponse(res, 500, null, 'Failed to retrieve upcoming events');
  }
};

// GET MY EVENTS
exports.getMyEvents = async (req, res) => {
  try {
    const events = await Event.find({ organizer: req.user._id })
      .sort({ createdAt: -1 });
    
    return sendResponse(res, 200, { events }, 'Your events retrieved');
  } catch (error) {
    console.error('Get my events error:', error);
    return sendResponse(res, 500, null, 'Failed to retrieve your events');
  }
};

// CREATE EVENT WITH MEDIA UPLOAD
exports.createEvent = async (req, res) => {
  try {
    const {
      title,
      description,
      eventType = 'meetup',
      startDate,
      endDate,
      locationType = 'physical',
      address,
      onlineLink,
      maxAttendees = 100,
      price = 0,
      categories = [],
      tags = [],
    } = req.body;

    // Required fields validation
    if (!title || !description || !startDate || !endDate) {
      return sendResponse(res, 400, null, 'Title, description, and dates are required');
    }

    // Date validation
    if (new Date(endDate) <= new Date(startDate)) {
      return sendResponse(res, 400, null, 'End date must be after start date');
    }

    // Create event object
    const eventData = {
      title,
      description,
      eventType,
      startDate: new Date(startDate),
      endDate: new Date(endDate),
      locationType,
      address: address ? JSON.parse(address) : undefined,
      onlineLink,
      maxAttendees,
      price,
      categories: Array.isArray(categories) ? categories : categories.split(','),
      tags: Array.isArray(tags) ? tags : tags.split(','),
      organizer: req.user._id,
      createdBy: req.user._id,
    };

    // Handle featured image upload if present
    if (req.file && req.file.fieldname === 'featuredImage') {
      try {
        const uploadResult = await CloudinaryService.uploadImage(req.file, {
          folder: `events/${req.user._id}`,
          public_id: `featured_${Date.now()}`
        });
        
        eventData.featuredImage = {
          url: uploadResult.url,
          publicId: uploadResult.publicId,
          width: uploadResult.width,
          height: uploadResult.height,
          format: uploadResult.format
        };
        
        eventData.cloudinaryAssets = [{
          publicId: uploadResult.publicId,
          resourceType: 'image',
          url: uploadResult.url,
          format: uploadResult.format,
          bytes: uploadResult.bytes,
          uploadedAt: new Date()
        }];
      } catch (uploadError) {
        console.error('Featured image upload failed:', uploadError);
      }
    }

    const event = await Event.create(eventData);
    return sendResponse(res, 201, { event }, 'Event created successfully');
  } catch (error) {
    console.error('Create event error:', error);
    return sendResponse(res, 500, null, 'Failed to create event');
  }
};

// UPDATE EVENT
exports.updateEvent = async (req, res) => {
  try {
    const event = await Event.findById(req.params.id);
    
    if (!event) {
      return sendResponse(res, 404, null, 'Event not found');
    }
    
    // Check permissions
    const isOrganizer = event.organizer.toString() === req.user._id.toString();
    const hasUpdatePermission = req.user.hasPermission('update_events');
    
    if (!isOrganizer && !hasUpdatePermission) {
      return sendResponse(res, 403, null, 'Permission denied');
    }
    
    // Update event
    Object.keys(req.body).forEach(key => {
      event[key] = req.body[key];
    });
    
    event.updatedBy = req.user._id;
    await event.save();
    
    return sendResponse(res, 200, { event }, 'Event updated successfully');
  } catch (error) {
    console.error('Update event error:', error);
    return sendResponse(res, 500, null, 'Failed to update event');
  }
};

// PUBLISH EVENT
exports.publishEvent = async (req, res) => {
  try {
    const event = await Event.findById(req.params.id);
    
    if (!event) {
      return sendResponse(res, 404, null, 'Event not found');
    }
    
    // Check permission
    if (!req.user.hasPermission('publish_events')) {
      return sendResponse(res, 403, null, 'Permission denied');
    }
    
    event.status = 'published';
    event.publishedAt = new Date();
    await event.save();
    
    return sendResponse(res, 200, { event }, 'Event published successfully');
  } catch (error) {
    console.error('Publish event error:', error);
    return sendResponse(res, 500, null, 'Failed to publish event');
  }
};

// UPLOAD BANNER IMAGE
exports.uploadBannerImage = async (req, res) => {
  try {
    const { id } = req.params;
    const event = await Event.findById(id);
    
    if (!event) {
      return sendResponse(res, 404, null, 'Event not found');
    }

    // Check permissions
    const isOrganizer = event.organizer.toString() === req.user._id.toString();
    const hasPermission = req.user.hasPermission('update_events');
    
    if (!isOrganizer && !hasPermission) {
      return sendResponse(res, 403, null, 'Permission denied');
    }

    if (!req.file) {
      return sendResponse(res, 400, null, 'No banner image provided');
    }

    // Delete old banner if exists
    if (event.bannerImage?.publicId) {
      try {
        await CloudinaryService.deleteResources([event.bannerImage.publicId]);
        
        // Remove from cloudinaryAssets array
        event.cloudinaryAssets = event.cloudinaryAssets.filter(
          asset => asset.publicId !== event.bannerImage.publicId
        );
      } catch (deleteError) {
        console.error('Failed to delete old banner:', deleteError);
      }
    }

    // Upload new banner image
    const uploadResult = await CloudinaryService.uploadImage(req.file, {
      folder: `events/${event._id}/banners`,
      public_id: `banner_${Date.now()}`,
      resize: { width: 1920, height: 1080, crop: 'fill' }
    });

    // Update event with new banner
    event.bannerImage = {
      url: uploadResult.url,
      publicId: uploadResult.publicId,
      width: uploadResult.width,
      height: uploadResult.height,
      format: uploadResult.format
    };

    // Add to cloudinaryAssets tracking
    event.cloudinaryAssets.push({
      publicId: uploadResult.publicId,
      resourceType: 'image',
      url: uploadResult.url,
      format: uploadResult.format,
      bytes: uploadResult.bytes,
      uploadedAt: new Date()
    });

    event.updatedBy = req.user._id;
    await event.save();

    return sendResponse(res, 200, { 
      bannerImage: event.bannerImage,
      uploadResult
    }, 'Banner image uploaded successfully');
  } catch (error) {
    console.error('Upload banner error:', error);
    return sendResponse(res, 500, null, 'Failed to upload banner image');
  }
};

// UPLOAD POST-EVENT VIDEO
exports.uploadPostEventVideo = async (req, res) => {
  try {
    const { id } = req.params;
    const { title, description } = req.body;
    
    const event = await Event.findById(id);
    
    if (!event) {
      return sendResponse(res, 404, null, 'Event not found');
    }

    // Check if event is completed or past end date
    if (event.status !== 'completed' && new Date(event.endDate) > new Date()) {
      return sendResponse(res, 400, null, 'Video can only be uploaded after event completion');
    }

    // Check permissions
    const isOrganizer = event.organizer.toString() === req.user._id.toString();
    const hasPermission = req.user.hasPermission('update_events');
    
    if (!isOrganizer && !hasPermission) {
      return sendResponse(res, 403, null, 'Permission denied');
    }

    if (!req.file) {
      return sendResponse(res, 400, null, 'No video file provided');
    }

    // Delete old video if exists
    if (event.postEventVideo?.publicId) {
      try {
        await CloudinaryService.deleteResources([event.postEventVideo.publicId], {
          resourceType: 'video'
        });
        
        // Remove from cloudinaryAssets array
        event.cloudinaryAssets = event.cloudinaryAssets.filter(
          asset => asset.publicId !== event.postEventVideo.publicId
        );
      } catch (deleteError) {
        console.error('Failed to delete old video:', deleteError);
      }
    }

    // Upload new video
    const uploadResult = await CloudinaryService.uploadVideo(req.file, {
      folder: `events/${event._id}/videos`,
      public_id: `video_${Date.now()}`,
      resource_type: 'video'
    });

    // Update event with new video
    event.postEventVideo = {
      url: uploadResult.url,
      publicId: uploadResult.publicId,
      thumbnail: uploadResult.thumbnail,
      duration: uploadResult.duration,
      format: uploadResult.format,
      size: uploadResult.bytes,
      uploadedAt: new Date(),
      title: title || `Video from ${event.title}`,
      description: description || '',
      metadata: {
        width: uploadResult.width,
        height: uploadResult.height,
        bitrate: uploadResult.metadata.bit_rate,
        codec: uploadResult.metadata.video_codec
      }
    };

    // Add to cloudinaryAssets tracking
    event.cloudinaryAssets.push({
      publicId: uploadResult.publicId,
      resourceType: 'video',
      url: uploadResult.url,
      format: uploadResult.format,
      bytes: uploadResult.bytes,
      uploadedAt: new Date()
    });

    event.updatedBy = req.user._id;
    await event.save();

    return sendResponse(res, 200, { 
      postEventVideo: event.postEventVideo,
      uploadResult
    }, 'Post-event video uploaded successfully');
  } catch (error) {
    console.error('Upload video error:', error);
    return sendResponse(res, 500, null, 'Failed to upload video');
  }
};

// UPLOAD GALLERY IMAGES
exports.uploadGalleryImages = async (req, res) => {
  try {
    const { id } = req.params;
    const event = await Event.findById(id);
    
    if (!event) {
      return sendResponse(res, 404, null, 'Event not found');
    }

    // Check permissions
    const isOrganizer = event.organizer.toString() === req.user._id.toString();
    const hasPermission = req.user.hasPermission('update_events');
    
    if (!isOrganizer && !hasPermission) {
      return sendResponse(res, 403, null, 'Permission denied');
    }

    if (!req.files || req.files.length === 0) {
      return sendResponse(res, 400, null, 'No gallery images provided');
    }

    const uploadPromises = req.files.map((file, index) => 
      CloudinaryService.uploadImage(file, {
        folder: `events/${event._id}/gallery`,
        public_id: `gallery_${Date.now()}_${index}`,
        resize: { width: 1200, height: 800, crop: 'fill' }
      })
    );

    const uploadResults = await Promise.all(uploadPromises);

    // Add new images to gallery
    const newGalleryItems = uploadResults.map(result => ({
      url: result.url,
      publicId: result.publicId,
      width: result.width,
      height: result.height,
      format: result.format,
      uploadedAt: new Date()
    }));

    event.gallery.push(...newGalleryItems);

    // Add to cloudinaryAssets tracking
    uploadResults.forEach(result => {
      event.cloudinaryAssets.push({
        publicId: result.publicId,
        resourceType: 'image',
        url: result.url,
        format: result.format,
        bytes: result.bytes,
        uploadedAt: new Date()
      });
    });

    event.updatedBy = req.user._id;
    await event.save();

    return sendResponse(res, 200, { 
      gallery: newGalleryItems,
      totalGalleryImages: event.gallery.length
    }, 'Gallery images uploaded successfully');
  } catch (error) {
    console.error('Upload gallery error:', error);
    return sendResponse(res, 500, null, 'Failed to upload gallery images');
  }
};

// DELETE GALLERY IMAGE
exports.deleteGalleryImage = async (req, res) => {
  try {
    const { id, imageId } = req.params;
    const event = await Event.findById(id);
    
    if (!event) {
      return sendResponse(res, 404, null, 'Event not found');
    }

    // Check permissions
    const isOrganizer = event.organizer.toString() === req.user._id.toString();
    const hasPermission = req.user.hasPermission('update_events');
    
    if (!isOrganizer && !hasPermission) {
      return sendResponse(res, 403, null, 'Permission denied');
    }

    // Find the image in gallery
    const imageIndex = event.gallery.findIndex(img => img._id.toString() === imageId);
    if (imageIndex === -1) {
      return sendResponse(res, 404, null, 'Image not found in gallery');
    }

    const imageToDelete = event.gallery[imageIndex];

    // Delete from Cloudinary
    if (imageToDelete.publicId) {
      try {
        await CloudinaryService.deleteResources([imageToDelete.publicId]);
        
        // Remove from cloudinaryAssets tracking
        event.cloudinaryAssets = event.cloudinaryAssets.filter(
          asset => asset.publicId !== imageToDelete.publicId
        );
      } catch (deleteError) {
        console.error('Failed to delete from Cloudinary:', deleteError);
      }
    }

    // Remove from gallery array
    event.gallery.splice(imageIndex, 1);
    event.updatedBy = req.user._id;
    await event.save();

    return sendResponse(res, 200, null, 'Gallery image deleted successfully');
  } catch (error) {
    console.error('Delete gallery image error:', error);
    return sendResponse(res, 500, null, 'Failed to delete gallery image');
  }
};

// GET CLOUDINARY UPLOAD SIGNATURE (for client-side uploads)
exports.getUploadSignature = async (req, res) => {
  try {
    const { folder = 'events' } = req.query;
    
    const signature = CloudinaryService.generateUploadSignature(folder);
    
    return sendResponse(res, 200, { 
      signature,
      cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
      api_key: process.env.CLOUDINARY_API_KEY,
      upload_url: `https://api.cloudinary.com/v1_1/${process.env.CLOUDINARY_CLOUD_NAME}/auto/upload`
    }, 'Upload signature generated');
  } catch (error) {
    console.error('Generate signature error:', error);
    return sendResponse(res, 500, null, 'Failed to generate upload signature');
  }
};

// DELETE EVENT (updated to clean Cloudinary assets)
exports.deleteEvent = async (req, res) => {
  try {
    const event = await Event.findById(req.params.id);
    
    if (!event) {
      return sendResponse(res, 404, null, 'Event not found');
    }
    
    // Check permissions
    const isOrganizer = event.organizer.toString() === req.user._id.toString();
    const hasDeletePermission = req.user.hasPermission('delete_events');
    
    if (!isOrganizer && !hasDeletePermission) {
      return sendResponse(res, 403, null, 'Permission denied');
    }
    
    // Clean up Cloudinary assets
    await Event.cleanupCloudinaryAssets(event._id);
    
    // Soft delete
    event.isDeleted = true;
    event.isActive = false;
    event.updatedBy = req.user._id;
    await event.save();
    
    return sendResponse(res, 200, null, 'Event deleted successfully');
  } catch (error) {
    console.error('Delete event error:', error);
    return sendResponse(res, 500, null, 'Failed to delete event');
  }
};

// COMPLETE EVENT
exports.completeEvent = async (req, res) => {
  try {
    const event = await Event.findById(req.params.id);
    
    if (!event) {
      return sendResponse(res, 404, null, 'Event not found');
    }
    
    // Check permissions
    const isOrganizer = event.organizer.toString() === req.user._id.toString();
    const hasPermission = req.user.hasPermission('update_events');
    
    if (!isOrganizer && !hasPermission) {
      return sendResponse(res, 403, null, 'Permission denied');
    }
    
    // Update event status
    event.status = 'completed';
    event.updatedBy = req.user._id;
    await event.save();
    
    return sendResponse(res, 200, { event }, 'Event marked as completed');
  } catch (error) {
    console.error('Complete event error:', error);
    return sendResponse(res, 500, null, 'Failed to complete event');
  }
};