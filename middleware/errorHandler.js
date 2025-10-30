module.exports = function errorHandler(err, req, res, next) {
  const status = err.status || 500;
  const msg = err.publicMessage || 'Internal Server Error';
  if (process.env.NODE_ENV !== 'production') {
    console.error(err);
    return res.status(status).json({ error: msg, details: err.message, stack: err.stack });
  }
  return res.status(status).json({ error: msg });
};
