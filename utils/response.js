/**
 * Standardised API response helpers
 */

const sendSuccess = (res, data = {}, message = 'Success', statusCode = 200) => {
  return res.status(statusCode).json({
    success: true,
    message,
    data
  });
};

const sendError = (res, message = 'Something went wrong', statusCode = 500, errors = null) => {
  const response = { success: false, message };
  if (errors) response.errors = errors;
  return res.status(statusCode).json(response);
};

const sendCreated = (res, data = {}, message = 'Created successfully') => {
  return sendSuccess(res, data, message, 201);
};

const sendUnauthorized = (res, message = 'Unauthorized') => {
  return sendError(res, message, 401);
};

const sendForbidden = (res, message = 'Forbidden') => {
  return sendError(res, message, 403);
};

const sendNotFound = (res, message = 'Not found') => {
  return sendError(res, message, 404);
};

const sendValidationError = (res, errors) => {
  return sendError(res, 'Validation failed', 422, errors);
};

module.exports = {
  sendSuccess,
  sendError,
  sendCreated,
  sendUnauthorized,
  sendForbidden,
  sendNotFound,
  sendValidationError
};