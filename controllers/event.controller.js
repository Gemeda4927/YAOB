const Event = require('../models/event.model');

// Reuse your response utilities
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

// ==================== EVENT CONTROLLERS ====================

// CREATE EVENT
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

    const event = await Event.create({
      title,
      description,
      eventType,
      startDate: new Date(startDate),
      endDate: new Date(endDate),
      locationType,
      address,
      onlineLink,
      maxAttendees,
      price,
      categories,
      tags,
      organizer: req.user._id,
      createdBy: req.user._id,
    });

    return sendResponse(res, 201, { event }, 'Event created successfully');
  } catch (error) {
    console.error(error);
    return sendResponse(res, 500, null, 'Failed to create event');
  }
};

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
    return sendResponse(res, 500, null, 'Failed to retrieve event');
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
    return sendResponse(res, 500, null, 'Failed to update event');
  }
};

// DELETE EVENT
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
    
    // Soft delete
    event.isDeleted = true;
    event.isActive = false;
    await event.save();
    
    return sendResponse(res, 200, null, 'Event deleted successfully');
  } catch (error) {
    return sendResponse(res, 500, null, 'Failed to delete event');
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
    return sendResponse(res, 500, null, 'Failed to publish event');
  }
};

// GET MY EVENTS
exports.getMyEvents = async (req, res) => {
  try {
    const events = await Event.find({ organizer: req.user._id })
      .sort({ createdAt: -1 });
    
    return sendResponse(res, 200, { events }, 'Your events retrieved');
  } catch (error) {
    return sendResponse(res, 500, null, 'Failed to retrieve your events');
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
    return sendResponse(res, 500, null, 'Failed to retrieve upcoming events');
  }
};