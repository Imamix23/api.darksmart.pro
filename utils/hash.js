const bcrypt = require('bcryptjs');

const SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS || '12', 10);

const hashPassword = async (password) => bcrypt.hash(password, SALT_ROUNDS);
const comparePassword = async (password, hash) => bcrypt.compare(password, hash);

module.exports = { hashPassword, comparePassword, SALT_ROUNDS };
