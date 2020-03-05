'use strict';

/**
 * Module dependencies.
 */

// var ServerError = require('../errors/server-error');
var InvalidArgumentError = require('../errors/invalid-argument-error');
var ServerError = require('../errors/server-error');
var url = require('url');
var tokenUtil = require('../utils/token-util');

/**
 * Constructor.
 */

function IdTokenResponseType(code, client, user, scope, options) {
  if (!code) {
    throw new InvalidArgumentError('Missing parameter: `code`');
  }

  let id_token = this.signIdToken(client, user, scope, options);

  // this.code = code;
  this.id_token = id_token;
}

/**
 * Build redirect uri.
 */

IdTokenResponseType.prototype.buildRedirectUri = function(redirectUri) {
  if (!redirectUri) {
    throw new InvalidArgumentError('Missing parameter: `redirectUri`');
  }

  var uri = url.parse(redirectUri, true);

  // uri.hash = 'id_token='+this.id_token;
  uri.query.id_token = this.id_token;
  uri.search = null;

  return uri;
};

IdTokenResponseType.prototype.signIdToken = function (client, user, scope, options) {
  let {
    openidAlgorithm: alg,
    openidIssuer: iss,
    openidPrivateKey: key,
  } = options;

  /* Arguments Checking */
  if (scope && !scope.includes('openid')) {
    return null;
  }

  if (!user) {
    throw new ServerError('Server error: `user` must be a User instance');
  }

  if (!client.id) {
    throw new InvalidArgumentError('Missing parameter: `client.id`');
  }

  if (!alg) {
    throw new InvalidArgumentError('Missing parameter: `openidAlgorithm`');
  }

  if (!iss) {
    throw new InvalidArgumentError('Missing parameter: `openidIssuer`');
  }

  let _options = {
    algorithm: alg, //alg
    expiresIn: '7d', //exp
    audience: client.id, //aud
    issuer: iss, //iss
    subject: '' + user.uid, //sub
  };

  return tokenUtil.generateIdToken(user, key, _options);
};

/**
 * Export constructor.
 */

module.exports = IdTokenResponseType;
