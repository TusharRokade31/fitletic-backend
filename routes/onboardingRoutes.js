const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/authMiddleware');
const ctrl = require('../controllers/onboardingController');

router.get('/',    requireAuth, ctrl.getOnboarding);
router.patch('/',  requireAuth, ctrl.updateOnboarding);

module.exports = router;