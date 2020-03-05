'use strict';

/**
 * Module dependencies.
 */

var crypto = require('crypto');
var randomBytes = require('bluebird').promisify(require('crypto').randomBytes);
var jwt = require('jsonwebtoken');

/**
 * Export `TokenUtil`.
 */

module.exports = {

  /**
   * Generate random token.
   */

  generateRandomToken: function() {
    return randomBytes(256).then(function(buffer) {
      return crypto
        .createHash('sha1')
        .update(buffer)
        .digest('hex');
    });
  },

  /**
   * jwt sign
   */
  generateIdToken: function (user, privateKey, options) {
    return jwt.sign(user, privateKey, options);
  }

};
