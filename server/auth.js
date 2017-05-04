/* eslint-disable no-param-reassign */

import {Passport} from 'passport';
import HelsinkiStrategy from 'passport-helsinki';
import openidClient from 'openid-client';
import jwt from 'jsonwebtoken';
import merge from 'lodash/merge';
import _debug from 'debug';

const debug = _debug('auth');

function generateToken(profile, options) {
  return jwt.sign(merge({}, profile), options.key, {
    subject: profile.id,
    audience: options.audience
  });
}

function MockStrategy(options) {
  this.name = 'mock';
  this.options = options;
}

MockStrategy.prototype.authenticate = function mockAuthenticate() {
  const profile = {
    id: '5ca1ab1e-cafe-babe-beef-deadbea70000',
    displayName: 'Mock von User',
    firstName: 'Mock',
    lastName: 'von User',
    username: 'mock.von.user',
    provider: 'helsinki'
  };
  profile.token = generateToken(profile, this.options);
  debug('mock strategy success:', profile);
  this.success(profile);
};


export function getHelsinkiStrategy(settings) {
  const getTokenFromAPI = true;
  const jwtOptions = {key: settings.jwtKey, audience: 'kerrokantasi'};

  const helsinkiStrategy = new HelsinkiStrategy({
    clientID: settings.helsinkiAuthId,
    clientSecret: settings.helsinkiAuthSecret,
    callbackURL: settings.publicUrl + '/login/helsinki/return'
  }, (accessToken, refreshToken, profile, done) => {
    debug('access token:', accessToken);
    debug('refresh token:', refreshToken);
    if (getTokenFromAPI) {
      debug('acquiring token from api...');
      helsinkiStrategy.getAPIToken(accessToken, settings.helsinkiTargetApp, (token) => {
        profile.token = token;
        return done(null, profile);
      });
    } else {
      if (profile._json) delete profile._json;
      if (profile._raw) delete profile._raw;
      profile.token = generateToken(profile, jwtOptions);
      debug('token generated with options:', jwtOptions);
      debug('profile:', profile);
      done(null, profile);
    }
  });
  return helsinkiStrategy;
}


export function getOIDCStrategy(settings) {
  const helssoUrl = 'http://localhost:8000';
  const issuer = new openidClient.Issuer({
    issuer: helssoUrl + '/openid',
    authorization_endpoint: helssoUrl + '/openid/authorize',
    token_endpoint: helssoUrl + '/openid/token',
    userinfo_endpoint: helssoUrl + '/openid/userinfo',
    jwks_uri: helssoUrl + '/openid/jwks',
    id_token_signing_alg_values_supported: ['HS256', 'RS256'],
    end_session_endpoint: helssoUrl + '/openid/end-session',
    token_endpoint_auth_methods_supported: [
      'client_secret_post',
      'client_secret_basic'
    ],
    response_types_supported: [
      'code',
      'id_token',
      'id_token token',
      'code token',
      'code id_token',
      'code id_token token'
    ],
    subject_types_supported: ['public']
  });
  // TODO: Construct issuer with discover!
  // Issuer.discover(helssoUrl + '/openid')
  //   .then((issuer) => (
  //     console.log('Discovered issuer %s', issuer);
  //   ));
  const client = new issuer.Client({
    client_id: '358712',
    redirect_uris: [settings.publicUrl + '/login/helsinki/return'],
    response_types: ['code']
  });

  const strategy = new openidClient.Strategy(
    {
      client,
      params: {
        scope: 'openid profile https://api.hel.fi/auth/kerrokantasi',
      },
    },
    (tokenset, userinfo, done) => {
      debug('tokenset', tokenset);
      debug('access_token', tokenset.access_token);
      debug('id_token', tokenset.id_token);
      debug('claims', tokenset.claims);
      debug('userinfo', userinfo);
      // User.findOne({ id: tokenset.claims.sub }, function (err, user) {
      //  if (err) return done(err);
      const profile = {
        id: userinfo.sub,
        displayName: userinfo.name,
        name: {
          familyName: userinfo.family_name,
          givenName: userinfo.given_name
        },
        // department: userinfo.department_name,
        /* emails: [
          {value: userinfo.email}
        ], */
        username: userinfo.preferred_username,
        token: tokenset.id_token
      };
      return done(null, profile);
    }
  );
  debug('strategy._params:', strategy._params);
  return strategy;
}


export function getPassport(settings) {
  const jwtOptions = {key: settings.jwtKey, audience: 'kerrokantasi'};
  const passport = new Passport();

  passport.use(getHelsinkiStrategy(settings));
  passport.use('oidc', getOIDCStrategy(settings));
  passport.use(new MockStrategy(jwtOptions));

  passport.serializeUser((user, done) => {
    debug('serializing user:', user);
    done(null, user);
  });
  passport.deserializeUser((user, done) => {
    debug('deserializing user:', user);
    done(null, user);
  });
  return passport;
}

function successfulLoginHandler(req, res) {
  const js = 'setTimeout(function() {if(window.opener) { window.close(); } else { location.href = "/"; } }, 300);';
  res.send('<html><body>Login successful.<script>' + js + '</script>');
}

export function addAuth(server, settings) {
  const passport = getPassport(settings);
  server.use(passport.initialize());
  server.use(passport.session());

  switch (settings.authStrategy) {
    case 'helsinki-oidc':
      server.get('/login/helsinki', passport.authenticate('oidc'));
      server.get('/login/helsinki/return', passport.authenticate('oidc'), successfulLoginHandler);
      break;
    case 'mock':
      server.get('/login/mock', passport.authenticate('mock'), successfulLoginHandler);
      break;
    default:
      server.get('/login/helsinki', passport.authenticate('helsinki'));
      server.get('/login/helsinki/return', passport.authenticate('helsinki'), successfulLoginHandler);
  }

  server.get('/logout', (req, res) => {
    res.send('<html><body><form method="post"></form><script>document.forms[0].submit()</script>');
  });
  server.post('/logout', (req, res) => {
    req.logout();
    const redirectUrl = req.query.next || '/';
    res.redirect(`${settings.helssoUrl}/logout/?next=${redirectUrl}`);
  });
  server.get('/me', (req, res) => {
    res.json(req.user || {});
  });
}
