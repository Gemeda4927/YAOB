const express = require('express');
const router = express.Router();
const eventController = require('../controllers/event.controller');
const { protect, hasPermission } = require('../middleware/auth');

// All routes require authentication
router.use(protect);

// ==================== PUBLIC ROUTES ====================

// Get all events (published only for regular users)
router.get('/', eventController.getAllEvents);

// Get single event
router.get('/:id', eventController.getEventById);

// Get upcoming events
router.get('/upcoming/events', eventController.getUpcomingEvents);

// ==================== ORGANIZER ROUTES ====================

// Get my events
router.get('/my/events', eventController.getMyEvents);

// Create event (requires permission)
router.post('/', 
  hasPermission('create_events'),
  eventController.createEvent
);

// Update my event
router.patch('/:id',
  async (req, res, next) => {
    const Event = require('../models/event.model');
    const event = await Event.findById(req.params.id);
    
    if (!event) {
      return res.status(404).json({
        success: false,
        message: 'Event not found'
      });
    }
    
    // Check if user is organizer OR has update permission
    const isOrganizer = event.organizer.toString() === req.user._id.toString();
    const hasUpdatePermission = req.user.hasPermission('update_events');
    
    if (!isOrganizer && !hasUpdatePermission) {
      return res.status(403).json({
        success: false,
        message: 'Permission denied'
      });
    }
    
    next();
  },
  eventController.updateEvent
);

// Delete my event
router.delete('/:id',
  async (req, res, next) => {
    const Event = require('../models/event.model');
    const event = await Event.findById(req.params.id);
    
    if (!event) {
      return res.status(404).json({
        success: false,
        message: 'Event not found'
      });
    }
    
    // Check if user is organizer OR has delete permission
    const isOrganizer = event.organizer.toString() === req.user._id.toString();
    const hasDeletePermission = req.user.hasPermission('delete_events');
    
    if (!isOrganizer && !hasDeletePermission) {
      return res.status(403).json({
        success: false,
        message: 'Permission denied'
      });
    }
    
    next();
  },
  eventController.deleteEvent
);

// ==================== ADMIN ROUTES ====================

// Publish event
router.patch('/:id/publish',
  hasPermission('publish_events'),
  eventController.publishEvent
);

module.exports = router;