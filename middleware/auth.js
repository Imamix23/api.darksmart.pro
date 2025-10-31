const { verifyToken } = require('../utils/jwt');

function requireAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'unauthorized',
        message: 'Missing or invalid authorization header'
      });
    }

    const token = authHeader.substring(7);
    const decoded = verifyToken(token);

    if (!decoded) {
      return res.status(401).json({
        error: 'unauthorized',
        message: 'Invalid or expired token'
      });
    }

    // Attach user info to request
    req.userId = decoded.sub;
    req.userEmail = decoded.email;
    req.agentUserId = decoded.agentUserId;
    
    next();
  } catch (err) {
    console.error('Auth middleware error:', err);
    res.status(401).json({
      error: 'unauthorized',
      message: 'Authentication failed'
    });
  }
}

function optionalAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      const decoded = verifyToken(token);
      
      if (decoded) {
        req.userId = decoded.sub;
        req.userEmail = decoded.email;
        req.agentUserId = decoded.agentUserId;
      }
    }
    
    next();
  } catch (err) {
    // Continue without auth
    next();
  }
}

module.exports = {
  requireAuth,
  optionalAuth
};