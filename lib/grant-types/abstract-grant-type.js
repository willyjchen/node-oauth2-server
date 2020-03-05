'use strict';

/**
 * Module dependencies.
 */

var InvalidArgumentError = require('../errors/invalid-argument-error');
var InvalidScopeError = require('../errors/invalid-scope-error');
var ServerError = require('../errors/server-error');
var Promise = require('bluebird');
var promisify = require('promisify-any').use(Promise);
var is = require('../validator/is');
var tokenUtil = require('../utils/token-util');

/**
 * Constructor.
 */

function AbstractGrantType(options) {
  options = options || {};
  if (!options.accessTokenLifetime) {
    throw new InvalidArgumentError('Missing parameter: `accessTokenLifetime`');
  }

  if (!options.model) {
    throw new InvalidArgumentError('Missing parameter: `model`');
  }

  this.accessTokenLifetime = options.accessTokenLifetime;
  this.model = options.model;
  this.refreshTokenLifetime = options.refreshTokenLifetime;
  this.alwaysIssueNewRefreshToken = options.alwaysIssueNewRefreshToken;

  this.options = options;
}

/**
 * Generate access token.
 */

AbstractGrantType.prototype.generateAccessToken = function(client, user, scope) {
  if (this.model.generateAccessToken) {
    return promisify(this.model.generateAccessToken, 3).call(this.model, client, user, scope)
      .then(function(accessToken) {
        return accessToken || tokenUtil.generateRandomToken();
      });
  }

  return tokenUtil.generateRandomToken();
};

/**
 * Generate id token.
 */

AbstractGrantType.prototype.generateIdToken = function (client, user, scope) {
  /* Scope Chain */
  let {
    openidAlgorithm: alg,
    openidIssuer: iss,
    openidPrivateKey: key,
  } = this.options;

  /* Arguments Checking */
  if (!scope || (scope && !scope.includes('openid'))) {
    return undefined;
  }

  if (!user) {
    throw new ServerError('Server error: `user` must be a User instance');
  }

  if (!client.id) {
    throw new InvalidArgumentError('Missing parameter: `client.id`');
  }

  /* Class Function Overwriting: Call Child Function*/
  if (this.model.generateIdToken) {
    return promisify(this.model.generateIdToken, 3).call(this.model, client, user, scope)
      .then(function (idToken) {
        return idToken;
      });
  }

  /* Call class function if there is no child function */
  if (!alg) {
    throw new InvalidArgumentError('Missing parameter: `openidAlgorithm`');
  }

  if (!iss) {
    throw new InvalidArgumentError('Missing parameter: `openidIssuer`');
  }

  /* for JWT */
  /** TODO: user.uid is hard-coded. A dependency injection way is needed. */
  let options = {
    algorithm: alg, //alg
    expiresIn: '7d', //exp
    audience: client.id, //aud
    issuer: iss, //iss
    subject: '' + user.uid, //sub
  };

  return tokenUtil.generateIdToken(user, key, options);
};

/**
 * Generate refresh token.
 */

AbstractGrantType.prototype.generateRefreshToken = function(client, user, scope) {
  if (this.model.generateRefreshToken) {
    return promisify(this.model.generateRefreshToken, 3).call(this.model, client, user, scope)
      .then(function(refreshToken) {
        return refreshToken || tokenUtil.generateRandomToken();
      });
  }

  return tokenUtil.generateRandomToken();
};

/**
 * Get access token expiration date.
 */

AbstractGrantType.prototype.getAccessTokenExpiresAt = function() {
  var expires = new Date();

  expires.setSeconds(expires.getSeconds() + this.accessTokenLifetime);

  return expires;
};

/**
 * Get refresh token expiration date.
 */

AbstractGrantType.prototype.getRefreshTokenExpiresAt = function() {
  var expires = new Date();

  expires.setSeconds(expires.getSeconds() + this.refreshTokenLifetime);

  return expires;
};

/**
 * Get scope from the request body.
 */

AbstractGrantType.prototype.getScope = function(request) {
  if (!is.nqschar(request.body.scope)) {
    throw new InvalidArgumentError('Invalid parameter: `scope`');
  }

  return request.body.scope;
};

/**
 * Validate requested scope.
 */
AbstractGrantType.prototype.validateScope = function(user, client, scope) {
  if (this.model.validateScope) {
    return promisify(this.model.validateScope, 3).call(this.model, user, client, scope)
      .then(function (scope) {
        if (!scope) {
          throw new InvalidScopeError('Invalid scope: Requested scope is invalid');
        }

        return scope;
      });
  } else {
    return scope;
  }
};

/**
 * Export constructor.
 */

module.exports = AbstractGrantType;
