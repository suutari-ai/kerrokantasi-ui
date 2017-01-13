/* eslint-disable no-param-reassign */

import {Passport} from 'passport';
import HelsinkiStrategy from 'passport-helsinki';
//import Strategy from 'passport-oidc-client';
import {Strategy} from 'passport-openidconnect';
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


export function getPassport(settings) {
  const getTokenFromAPI = true;
  const jwtOptions = {key: settings.jwtKey, audience: 'kerrokantasi'};
  const passport = new Passport();
  /*
  const helsinkiStrategy = new HelsinkiStrategy({
    appTokenURL: 'http://localhost:8000/jwt-token/',
    authorizationURL: 'http://localhost:8000/oauth2/authorize/',
    tokenURL: 'http://localhost:8000/oauth2/token/',
    userProfileURL: 'http://localhost:8000/user/',
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
  passport.use(helsinkiStrategy);
   */

  /*
  const strategy = new Strategy(
    {
      clientId: '332114', //settings.helsinkiAuthId,
      authority: 'http://localhost:8000/openid',
      callbackURL: settings.publicUrl + '/login/helsinki/return',
      verbose_logging: true
    },
    (results, error) => {
      debug("dippadappa");
      debug("results:", results);
      debug("error:", error);
    });
  debug('oidc strategy config:', strategy._config);
   */
  const strategy = new Strategy(
    {
      scope: 'profile email github api-kerrokantasi',
      issuer: 'http://localhost:8000/openid',
      clientID: '358712',
      clientSecret: '510d049135d9cce96e54a67fa1f09fa8cfa9ce774cb88aa445b630c4',
      authorizationURL: 'http://localhost:8000/openid/authorize',
      tokenURL: 'http://localhost:8000/openid/token',
      userInfoURL: 'http://localhost:8000/openid/userinfo',
      callbackURL: settings.publicUrl + '/login/helsinki/return'
    },
    (token, tokenSecret, profile, cb) => {
      debug("dippadappa");
      debug("token:", token);
      debug("tokenSecret:", tokenSecret);
      debug("profile:", profile);
      cb(null, profile);
    });

  passport.use(strategy);
  if (settings.dev && false) { // preferably develop using SSO
    passport.use(new MockStrategy(jwtOptions));
  }
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
  server.get('/login/helsinki', passport.authenticate('openidconnect'));
  
  //server.get('/login/helsinki', passport.authenticate('helsinki'));
  if (settings.dev && false) {  // preferably develop using SSO
    server.get('/login/mock', passport.authenticate('mock'), successfulLoginHandler);
  }
  server.get('/login/helsinki/return', passport.authenticate('openidconnect'), successfulLoginHandler);
  server.get('/logout', (req, res) => {
    res.send('<html><body><form method="post"></form><script>document.forms[0].submit()</script>');
  });
  server.post('/logout', (req, res) => {
    req.logout();
    const redirectUrl = req.query.next || '/';
    res.redirect(`http://localhost:8000/logout/?next=${redirectUrl}`);
  });
  server.get('/me', (req, res) => {
    res.json(req.user || {});
  });
}
