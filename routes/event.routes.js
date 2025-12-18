
const express = require('express');
const router = express.Router();
const eventController = require('../controllers/event.controller');
const { protect, hasPermission } = require('../middleware/auth');
const { uploadMiddleware, handleUploadError } = require('../middleware/upload');

// ==================== PROTECTED ROUTES ====================
router.use(protect);

// ==================== PUBLIC ROUTES ====================
// Specific routes first
router.get('/upcoming/events', eventController.getUpcomingEvents);
router.get('/my/events', eventController.getMyEvents); // organizer-specific
router.get('/', eventController.getAllEvents);
router.get('/:id', eventController.getEventById);

// ==================== ORGANIZER ROUTES ====================

// Create event
router.post(
  '/',
  hasPermission('create_events'),
  uploadMiddleware.singleFeaturedImage,
  handleUploadError,
  eventController.createEvent
);

// Update event
router.patch(
  '/:id',
  async (req, res, next) => {
    const Event = require('../models/event.model');
    const event = await Event.findById(req.params.id);

    if (!event) {
      return res
        .status(404)
        .json({ success: false, message: 'Event not found' });
    }

    const isOrganizer = event.organizer.toString() === req.user._id.toString();
    const hasUpdatePermission = req.user.hasPermission('update_events');

    if (!isOrganizer && !hasUpdatePermission) {
      return res
        .status(403)
        .json({ success: false, message: 'Permission denied' });
    }

    next();
  },
  eventController.updateEvent
);

// Upload banner image
router.post(
  '/:id/banner',
  uploadMiddleware.singleBannerImage,
  handleUploadError,
  eventController.uploadBannerImage
);

// Upload gallery images
router.post(
  '/:id/gallery',
  uploadMiddleware.galleryImages,
  handleUploadError,
  eventController.uploadGalleryImages
);

// Delete gallery image
router.delete('/:id/gallery/:imageId', eventController.deleteGalleryImage);

// Upload post-event video
router.post(
  '/:id/video',
  uploadMiddleware.singleVideo,
  handleUploadError,
  eventController.uploadPostEventVideo
);

// Complete event
router.patch('/:id/complete', eventController.completeEvent);

// Get Cloudinary upload signature
router.get(
  '/upload/signature',
  hasPermission('create_events'),
  eventController.getUploadSignature
);

// Delete event
router.delete(
  '/:id',
  async (req, res, next) => {
    const Event = require('../models/event.model');
    const event = await Event.findById(req.params.id);

    if (!event) {
      return res
        .status(404)
        .json({ success: false, message: 'Event not found' });
    }

    const isOrganizer = event.organizer.toString() === req.user._id.toString();
    const hasDeletePermission = req.user.hasPermission('delete_events');

    if (!isOrganizer && !hasDeletePermission) {
      return res
        .status(403)
        .json({ success: false, message: 'Permission denied' });
    }

    next();
  },
  eventController.deleteEvent
);

// ==================== ADMIN ROUTES ====================

// Publish event
router.patch(
  '/:id/publish',
  hasPermission('publish_events'),
  eventController.publishEvent
);

module.exports = router;