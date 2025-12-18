const mongoose = require('mongoose');
const validator = require('validator');

const eventSchema = new mongoose.Schema(
  {
    // =========================
    // BASIC INFORMATION
    // =========================
    title: {
      type: String,
      required: [true, 'Event title is required'],
      trim: true,
      minlength: [5, 'Title must be at least 5 characters'],
      maxlength: [200, 'Title cannot exceed 200 characters'],
    },

    description: {
      type: String,
      required: [true, 'Event description is required'],
      trim: true,
      minlength: [20, 'Description must be at least 20 characters'],
      maxlength: [5000, 'Description cannot exceed 5000 characters'],
    },

    // =========================
    // EVENT DETAILS
    // =========================
    eventType: {
      type: String,
      enum: [
        'conference',
        'workshop',
        'meetup',
        'seminar',
        'webinar',
        'social',
        'other',
      ],
      default: 'meetup',
    },

    status: {
      type: String,
      enum: ['draft', 'published', 'cancelled', 'completed'],
      default: 'draft',
    },

    // =========================
    // DATE & TIME
    // =========================
    startDate: {
      type: Date,
      required: [true, 'Start date is required'],
    },

    endDate: {
      type: Date,
      required: [true, 'End date is required'],
    },

    timezone: {
      type: String,
      default: 'UTC',
    },

    // =========================
    // LOCATION
    // =========================
    locationType: {
      type: String,
      enum: ['physical', 'virtual', 'hybrid'],
      default: 'physical',
    },

    address: {
      street: String,
      city: String,
      state: String,
      country: String,
      zipCode: String,
    },

    onlineLink: {
      type: String,
      validate: {
        validator(value) {
          if (!value) return true;
          return validator.isURL(value, {
            protocols: ['http', 'https'],
            require_protocol: true,
          });
        },
        message: 'Please provide a valid URL',
      },
    },

    // =========================
    // CAPACITY & PRICING
    // =========================
    maxAttendees: {
      type: Number,
      min: [1, 'Maximum attendees must be at least 1'],
      default: 100,
    },

    currentAttendees: {
      type: Number,
      default: 0,
      min: [0, 'Current attendees cannot be negative'],
    },

    price: {
      type: Number,
      min: [0, 'Price cannot be negative'],
      default: 0,
    },

    currency: {
      type: String,
      default: 'USD',
      uppercase: true,
    },

    // =========================
    // ORGANIZATION
    // =========================
    organizer: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },

    coOrganizers: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
      },
    ],

    // =========================
    // CATEGORIES & TAGS
    // =========================
    categories: [String],
    tags: [String],

    // =========================
    // MEDIA
    // =========================
    featuredImage: String,
    gallery: [String],

    // =========================
    // SETTINGS
    // =========================
    isFeatured: {
      type: Boolean,
      default: false,
    },

    requiresApproval: {
      type: Boolean,
      default: false,
    },

    registrationDeadline: Date,

    publishedAt: Date,

    // =========================
    // SOFT DELETE
    // =========================
    isActive: {
      type: Boolean,
      default: true,
    },

    isDeleted: {
      type: Boolean,
      default: false,
    },

    // =========================
    // AUDIT
    // =========================
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },

    updatedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

//
// =========================
// VIRTUALS
// =========================
//
eventSchema.virtual('durationHours').get(function () {
  if (!this.startDate || !this.endDate) return 0;
  return (this.endDate - this.startDate) / (1000 * 60 * 60);
});

eventSchema.virtual('availableSeats').get(function () {
  return this.maxAttendees - this.currentAttendees;
});

eventSchema.virtual('isFull').get(function () {
  return this.currentAttendees >= this.maxAttendees;
});

eventSchema.virtual('registrationOpen').get(function () {
  const now = new Date();
  return (
    now < this.startDate &&
    (!this.registrationDeadline || now < this.registrationDeadline)
  );
});

//
// =========================
// INDEXES
// =========================
//
eventSchema.index({ status: 1 });
eventSchema.index({ organizer: 1 });
eventSchema.index({ startDate: 1 });
eventSchema.index({ locationType: 1 });

//
// =========================
// MIDDLEWARE (FIXED)
// =========================
//

// Auto set publishedAt
eventSchema.pre('save', function () {
  if (
    this.isModified('status') &&
    this.status === 'published' &&
    !this.publishedAt
  ) {
    this.publishedAt = new Date();
  }
});

// Exclude soft-deleted docs
eventSchema.pre(/^find/, function () {
  this.find({ isDeleted: { $ne: true } });
});

//
// =========================
// MODEL
// =========================
//
const Event = mongoose.model('Event', eventSchema);

module.exports = Event;
