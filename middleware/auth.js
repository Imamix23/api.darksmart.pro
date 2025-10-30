const { verifyToken } = require('../utils/jwt');

module.exports = function auth(required = true) {
  return (req, res, next) => {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) {
      if (!required) return next();
      return res.status(401).json({ error: 'Missing token' });
    }
    try {
      const payload = verifyToken(token);
      req.user = payload;
      return next();
    } catch (e) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
  };
};
