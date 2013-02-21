/**
 * Module dependencies.
 */

var util = require('util');
var OAuth2Strategy = require('passport-oauth').OAuth2Strategy;
var InternalOAuthError = require('passport-oauth').InternalOAuthError;
var HOST_URL = 'http://defaultdynamics.com';

/**
 * `Strategy` constructor.
 *
 * The Default Dynamics authentication strategy authenticates requests by delegating to
 * Default Dynamics using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Default Dynamics application's App ID
 *   - `clientSecret`  your Default Dynamics application's App Secret
 *   - `callbackURL`   URL to which Default Ddynamics will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new DDStrategy({
 *         clientID: 'ABC123',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/oauth/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */

function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = HOST_URL + '/Authorize.asp';
  options.tokenURL = HOST_URL + '/CLServicesDev/oAuth2.ashx/token';
  options.scopeSeparator = options.scopeSeparator || ',';
  
  OAuth2Strategy.call(this, options, verify);
  this.name = 'dd';
  this.hostURL = options.hostURL;
}

/**
 * Inherit from `OAuth2Strategy`.
 */

util.inherits(Strategy, OAuth2Strategy);

/**
 * Retrieve user profile from Default Dynamics.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`           always set to `dd`
 *   - `id`                 the user's DefaultDynamics ID
 *   - `username`           the user's DefaultDynamics username
 *   - `displayName`        the user's full name
 *   - `name.firstName`     the user's last name
 *   - `name.lastName`      the user's first name
 *   - `profileUrl`         the URL of the profile for the user on Default Dynamics
 *   - `organization`       the user organization name
 *   - `organizationType`   the user organiaation type
 *   - `organizationTypeId` the user organiazarion type id
 *   - `email`              the contact email address granted by the user
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */

Strategy.prototype.userProfile = function (accessToken, done) {
  
  // We have to set token as custom name instead of access_token
  this._oauth2.setAccessTokenName('token');

  /**
   * Here we request for the user information
   */
  
  this._oauth2.get(HOST_URL + '/CLServicesDev/Mobileapp.ashx?action=GetCurrentUserInfo', accessToken, function (err, body, res) {
    if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }
    
    try {
      var json = JSON.parse(body);
     
      var profile                 = { provider: 'dd' };
      profile.username            = json.userId.toLowerCase();
      profile.displayName         = json.firstName + ' ' + json.lastName;
      profile.name                = { first: json.firstName, last: json.lastName };
      profile.email               = json.email.toLowerCase();
      profile.organization        = json.organization;
      profile.organizationType    = json.organizationType;
      profile.organizationTypeId  = json.organizationTypeId;

      profile._raw                = body;
      profile._json               = json;

      done(null, profile);
    } catch(e) {
      done(e);
    }
  });
};


/**
 * Expose `Strategy`.
 */

module.exports = Strategy;
