function successResponse(message_title, detail_message, data = null) {
  return {
    statusCode: 200,
    error: null,
    message_title,
    detail_message,
    data,
  };
}

module.exports = successResponse;
