const User = require('../models/User');
const { sendSuccess, sendError } = require('../utils/response');

exports.updateOnboarding = async (req, res) => {
  try {
    const allowedFields = [
      'sex', 'age', 'weight', 'height', 'goal',
      'activityLevel', 'targetWeight', 'medicalConditions',
      'foodPreference', 'referralCode', 'isComplete'
    ];

    const update = {};
    for (const field of allowedFields) {
      if (req.body[field] !== undefined) {
        update[`onboarding.${field}`] = req.body[field];
      }
    }

    // Also update top-level name if sent
    if (req.body.name) update.name = req.body.name;

    const user = await User.findByIdAndUpdate(
      req.user._id,
      { $set: update },
      { new: true, runValidators: true }
    );

    return sendSuccess(res, { user: user.toPublicJSON() }, 'Onboarding updated');
  } catch (err) {
    // Default error status code is 500, so we just pass the message
    return sendError(res, err.message);
  }
};

/**
 * GET /api/onboarding
 */
exports.getOnboarding = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    
    // Optional: adding a check in case the user isn't found
    if (!user) {
      return sendError(res, 'User not found', 404);
    }

    return sendSuccess(res, { onboarding: user.onboarding }, 'Onboarding data');
  } catch (err) {
    return sendError(res, err.message);
  }
};