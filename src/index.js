import { request } from "graphql-request";
const session = require("express-session");
const RedisStore = require("connect-redis")(session);
const LocalStrategy = require("passport-local").Strategy;
const passport = require("passport");
const redis = require("redis");

const ACCOUNT_GET = `query AccountGet($username: String!) {
  viewer {
    id
    accounts {
      get(username: $username) {
        id
        username
        status
        email
      }
    }
  }
}`;

const ACCOUNT_CHECK = `query AccountCheck($username: String!, $password: String!) {
  viewer {
    id
    accounts {
      check(username: $username, password: $password) {
        id
        username
        status
        email
      }
    }
  }
}`;

export const check = async (url, username, password, cxt) => {
  const {
    viewer: {
      accounts: { check: user }
    }
  } = await request(url, ACCOUNT_CHECK, { username, password });

  cxt.logger.debug("account.check", { user, username, password });

  return user;
};

export function init(
  { app, cache: { host, port, secret }, accounts: { url: AccountServiceUrl } },
  cxt
) {
  passport.serializeUser(function(user, cb) {
    cb(null, user.username);
  });

  passport.deserializeUser(function(username, cb) {
    request(AccountServiceUrl, ACCOUNT_GET, { username }).then(
      ({
        viewer: {
          accounts: { get: user }
        }
      }) => {
        cxt.logger.debug("account.deserialize", { user, username });

        return cb(null, user);
      }
    );
  });
  const RETRY_TIME = 1000 * 60 * 60;
  const RETRY_ATTEMPT = 10;

  const client = redis.createClient({
    host,
    port,
    auth_pass: secret,
    retry_strategy: function(options) {
      if (options.error && options.error.code === "ECONNREFUSED") {
        cxt.logger.error("auth.accounts.error", { error: options.error.code });
        process.exit(17);
      }
      if (options.total_retry_time > RETRY_TIME) {
        console.log("Retry time exhausted");
        cxt.logger.error("auth.accounts.retry", { time: RETRY_TIME });
        process.exit(18);
      }
      if (options.attempt > RETRY_ATTEMPT) {
        cxt.logger.error("auth.accounts.attempt", { attempt: RETRY_ATTEMP });
        process.exit(19);
      }

      return Math.min(options.attempt * 100, 3000);
    }
  });

  client.on("connect", function() {
    cxt.logger.debug("auth.accounts.cache.connected");
  });

  client.on("reconnecting", function() {
    cxt.logger.debug("auth.accounts.cache.reconnecting");
  });

  client.on("error", function(err) {
    cxt.logger.debug("auth.accounts.cache.error", { error: e.toString() });
  });

  passport.use(
    new LocalStrategy((username, password, done) => {
      check(AccountServiceUrl, username, password, cxt).then((user, err) => {
        if (!user || err) {
          done(null, false);
        } else {
          done(null, user);
        }
      });
    })
  );

  app.use(
    session({
      cookie: { maxAge: 3600000 },
      store: new RedisStore({
        host,
        port: parseInt(port),
        client,
        ttl: 260
      }),
      secret,
      resave: false,
      saveUninitialized: false
    })
  );
  app.use(passport.initialize());
  app.use(passport.session());

  return {
    client,
    passport
  };
}
