import { request } from "graphql-request";
const session = require("express-session");
const RedisStore = require("connect-redis")(session);
const LocalStrategy = require("passport-local").Strategy;
const passport = require("passport");
const redis = require("redis");

const ACCOUNT_GET = `query AccountGet($username: String!) {
  viewer {
    id
    account {
      get(username: $username) {
        id
        username
        email
      }
    }
  }
}`;

const ACCOUNT_CHECK = `query AccountCheck($username: String!, $password: String!) {
  viewer {
    id
    account {
      check(username: $username, password: $password) {
        id
        username
        email
      }
    }
  }
}`;

function init({
  app,
  cache: { host, port, secret },
  accounts: { url: AccountServiceUrl }
}) {
  passport.serializeUser(function(user, cb) {
    cb(null, user.username);
  });

  passport.deserializeUser(function(username, cb) {
    request(AccountServiceUrl, ACCOUNT_GET, { username }).then(
      ({
        viewer: {
          account: { get: user }
        }
      }) => {
        return cb(null, user);
      }
    );
  });

  const client = redis.createClient({
    host,
    port,
    auth_pass: secret,
    retry_strategy: function(options) {
      if (options.error && options.error.code === "ECONNREFUSED") {
        console.log("The server refused the connection");
        process.exit(17);
      }
      if (options.total_retry_time > 1000 * 60 * 60) {
        console.log("Retry time exhausted");
        process.exit(17);
      }
      if (options.attempt > 10) {
        console.log("Retry time exhausted");
        process.exit(17);
      }

      return Math.min(options.attempt * 100, 3000);
    }
  });

  client.on("connect", function() {
    console.log(" -> Cache connected");
  });

  client.on("reconnecting", function() {
    console.log(" -> Cache reconnecting");
  });

  client.on("error", function(err) {
    console.log(" -> Cache error: " + err.toString());
  });

  passport.use(
    new LocalStrategy((username, password, done) => {
      request(AccountServiceUrl, ACCOUNT_CHECK, { username, password }).then(
        (
          {
            viewer: {
              account: { check: user }
            }
          },
          err
        ) => {
          if (!user || err) {
            done(null, false);
          } else {
            done(null, user);
          }
        }
      );
    })
  );

  app.use(
    session({
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

export { init };
