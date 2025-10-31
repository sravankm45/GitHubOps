const winston = require('winston');
const { combine, timestamp, printf, colorize } = winston.format;
const myFormat = printf(({ level, message, timestamp }) => `${timestamp} [${level}] ${message}`);
const logger = winston.createLogger({
  level: 'debug',
  format: combine(timestamp(), myFormat),
  transports: [
    new winston.transports.Console({ format: combine(colorize(), timestamp(), myFormat) }),
    new winston.transports.File({ filename: 'gitsafeops.log' })
  ]
});
module.exports = logger;
