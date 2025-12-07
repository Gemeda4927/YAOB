const express = require('express');
const authController = require('../controllers/auth.controller');

const router = express.Router();

router.post('/signup', authController.signup);
router.post('/login', authController.login);
router.post('/forgotPassword', authController.forgotPassword);
router.patch('/resetPassword/:resetToken', authController.resetPassword);

router.use(authController.protect);

router.get('/me', (req, res) => res.status(200).json({ success: true, user: req.user }));
router.get('/adminOnly', authController.restrictTo('admin'), (req, res) => res.status(200).json({ message: 'Admin route' }));

module.exports = router;
