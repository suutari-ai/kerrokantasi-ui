/* eslint-disable no-param-reassign */

import {Passport} from 'passport';
import HelsinkiStrategy from 'passport-helsinki';
//import Strategy from 'passport-oidc-client';
//import {Strategy} from 'passport-openidconnect';
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

  const Issuer = require('openid-client').Issuer;
  const Strategy = require('openid-client').Strategy;
  const issuer = new Issuer({
    issuer: "http://localhost:8000/openid",
    authorization_endpoint: "http://localhost:8000/openid/authorize",
    token_endpoint: "http://localhost:8000/openid/token",
    userinfo_endpoint: "http://localhost:8000/openid/userinfo",
    jwks_uri: "http://localhost:8000/openid/jwks",
    id_token_signing_alg_values_supported: ["HS256", "RS256"],
    end_session_endpoint: "http://localhost:8000/openid/end-session",
    token_endpoint_auth_methods_supported: [
      "client_secret_post",
      "client_secret_basic"
    ],
    "response_types_supported": [
      "code",
      "id_token",
      "id_token token",
      "code token",
      "code id_token",
      "code id_token token"
    ],
    "subject_types_supported": ["public"]
  });
  // TODO: Construct issuer with discover!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  // Issuer.discover('http://localhost:8000/openid')
  //   .then(function (issuer) {
  //     console.log('Discovered issuer %s', issuer);
  //   });
  const client = new issuer.Client({
    client_id: '358712',
    redirect_uris: [settings.publicUrl + '/login/helsinki/return'],
    response_types: ['code']
  });

  const strategy = new Strategy(
    {client: client, params: {scope: 'openid profile https://api.hel.fi/auth/kerrokantasi'}},
    // {
    //   client: client,
    //   scope: 'openid https://api.hel.fi/auth/kerrokantasi'
    // },
    (tokenset, userinfo, done) => {
      debug('tokenset', tokenset);
      debug('access_token', tokenset.access_token);
      debug('id_token', tokenset.id_token);
      debug('claims', tokenset.claims);
      debug('userinfo', userinfo);

      //User.findOne({ id: tokenset.claims.sub }, function (err, user) {
      //  if (err) return done(err);
      userinfo.displayName = userinfo.name;
      userinfo.token = tokenset.id_token;
      return done(null, userinfo);
    }
  );
  debug('strategy._params:', strategy._params);
  passport.use('oidc', strategy);

  // const strategy = new Strategy(
  //   {
  //     scope: 'https://api.hel.fi/auth/kerrokantasi',
  //     issuer: 'http://localhost:8000/openid',
  //     clientID: '358712',
  //     clientSecret: '510d049135d9cce96e54a67fa1f09fa8cfa9ce774cb88aa445b630c4',
  //     authorizationURL: 'http://localhost:8000/openid/authorize',
  //     tokenURL: 'http://localhost:8000/openid/token',
  //     userInfoURL: 'http://localhost:8000/openid/userinfo',
  //     callbackURL: settings.publicUrl + '/login/helsinki/return',
  //     passReqToCallback: true
  //   },
  //   (req, iss, sub, profile, verified) => {
  //     debug("dippadappa");
  //     debug("iss:", iss);
  //     debug("sub:", sub);
  //     debug("profile:", profile);
  //     verified(null, profile, profile);
  //   });

  // passport.use(strategy);

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
  server.get('/login/helsinki', passport.authenticate('oidc'));
  
  //server.get('/login/helsinki', passport.authenticate('helsinki'));
  if (settings.dev && false) {  // preferably develop using SSO
    server.get('/login/mock', passport.authenticate('mock'), successfulLoginHandler);
  }
  server.get('/login/helsinki/return', passport.authenticate('oidc'), successfulLoginHandler);
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
