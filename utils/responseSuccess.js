function successResponse(message, data = null) {
  return {
    statusCode: 200,
    error: null,
    message,
    data,
  };
}

module.exports = successResponse;
