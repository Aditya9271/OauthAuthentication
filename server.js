var express   = require('express');
var app         = express();
var bodyParser  = require('body-parser');
var morgan      = require('morgan');
var mongoose    = require('mongoose');
var passport = require('passport');

var FacebookStrategy = require('passport-facebook').Strategy;
var TwitterStrategy = require('passport-twitter').Strategy;
var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;

var jwt    = require('jsonwebtoken'); // used to create, sign, and verify tokens
var config = require('./config'); // get our config file
var User   = require('./app/models/user'); // get our mongoose model
var configAuth = require('./auth'); // get our authorization file

// configuration 

var port = process.env.PORT || 3000; 
mongoose.connect(config.database); // connect to database
app.set('superSecret', config.secret); // secret variable

// use body parser so we can get info from POST and/or URL parameters
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// use morgan to log requests to the console
app.use(morgan('dev'));

// routes 
app.post('/signup', function(req, res) {

  // create a sample user by taking input from front end
  var newUser = new User();
  
  User.findOne({
    userId : req.body.userId
  },function(err,user){

    // if error throw error;
    if(err) throw err;

    // if user exists 
    if(user){
      res.json({success : false, message:'UserId already taken!'});
    }else{
          // save user details in database
            newUser.name = req.body.name;
            newUser.email = req.body.email;
            newUser.userId = req.body.userId;
            newUser.password = newUser.generateHash(req.body.password);  
            admin : true;

            newUser.save(function(err) {
                  if (err) throw err;
              console.log("User saved successfully");
              res.json({ success: true });
            });

    }}); 
});

// basic route (http://localhost:3000)
app.get('/', function(req, res) {
  res.send('Hello!');
});

// get an instance of the router for api routes

var apiRoutes = express.Router(); 

// authentication (no middleware necessary since this isnt authenticated)

// http://localhost:8080/api/authenticate
apiRoutes.post('/authenticate', function(req, res) {

  // find the user
  User.findOne({
    userId: req.body.userId
  }, function(err, user) {

    if (err) throw err;
    if (!user) {
      res.json({ success: false, message: 'Authentication failed. User not found.' });
    } else if (user) {

      // check if password matches
      if (!user.validPassword(req.body.password)) {
        res.json({ success: false, message: 'Authentication failed. Wrong password.' });
      } else {

        // if user is found and password is right
        // create a token
        var token = jwt.sign(user, app.get('superSecret'), {
          expiresIn: 86400 // expires in 24 hours
        });
        res.json({
            user : user,
          success: true,
          message: 'Enjoy your token!',
          token: token
        });

      }   

    }

  });
});

// Facebook strategy

  passport.use(new FacebookStrategy({
     // pull in our app id and secret from our auth.js file
        clientID        : configAuth.facebookAuth.clientID,
        clientSecret    : configAuth.facebookAuth.clientSecret,
        callbackURL     : configAuth.facebookAuth.callbackURL,
        passReqToCallback : true // allows us to pass in the req from our route (lets us check if a user is logged in or not)
  },
    // facebook will send back the token and profile
    function(req, token, refreshToken, profile, res) {

        // asynchronous
        process.nextTick(function() {

            // check if the user is already logged in
            if (!req.user) {

                // find the user in the database based on their facebook id
                User.findOne({ 'facebook_id' : profile.id }, function(err, user) {

                    // if there is an error, stop everything and return that
                    // ie an error connecting to the database
                    if (err)
                        throw err;

                    // if the user is found, then log them in
                    if (user) {
                        if(!user.facebook_token){
                            user.facebook_token = token;
                            user.facebook_name =  profile.name.givenName + ' ' + profile.name.familyName;
                            user.facebook_email = profile.emails[0].value;
                        }
                        user.save(function(err){
                            if(err)
                                throw err;
                            res.json(user);
                        });
                         // if user is found and password is right
                        // create a token
                        var token = jwt.sign(user, app.get('superSecret'), {
                          expiresIn: 86400 // expires in 24 hours
                        });

                        // user found, return that user

                        res.json({
                            user : user,
                          success: true,
                          message: 'Enjoy your token!',
                          token: token
                        });

                    } else {
                        // if there is no user found with that facebook id, create them
                        var newUser            = new User();

                        // set all of the facebook information in our user model
                        newUser.facebook_id    = profile.id; // set the users facebook id                   
                        newUser.facebook_token = token; // we will save the token that facebook provides to the user                    
                        newUser.facebook_name  = profile.name.givenName + ' ' + profile.name.familyName; // look at the passport user profile to see how names are returned
                        newUser.facebook_email = profile.emails[0].value; // facebook can return multiple emails so we'll take the first

                        // save our user to the database
                        newUser.save(function(err) {
                            if (err)
                                throw err;

                            // if successful, return the new user with the token
                             // create a token
                            var token = jwt.sign(newUser, app.get('superSecret'), {
                              expiresIn: 86400 // expires in 24 hours
                            });

                            // user found, return that user

                            res.json({
                              user : newUser,
                              success: true,
                              message: 'Enjoy your token!',
                              token: token
                            });
                        });
                    }

                });

            } else {
                // user already exists and is logged in, we have to link accounts
                var user            = req.user; // pull the user out of the session

                // update the current users facebook credentials
                user.facebook_id    = profile.id;
                user.facebook_token = token;
                user.facebook_name  = profile.name.givenName + ' ' + profile.name.familyName;
                user.facebook_email = profile.emails[0].value;

                // save the user
                user.save(function(err) {
                    if (err)
                        throw err;
                     // create a token
                     var token = jwt.sign(user, app.get('superSecret'), {
                        expiresIn: 86400 // expires in 24 hours
                        });
                        // after creating the token assign it to user and return
                        res.json({
                          user : user,
                          success: true,
                          message: 'Enjoy your token!',
                          token: token
                        });
                });
            }

        });

  }));

// google strategy

passport.use(new GoogleStrategy({

        // pull in our app id and secret from our auth.js file
        clientID        : configAuth.googleAuth.clientID,
        clientSecret    : configAuth.googleAuth.clientSecret,
        callbackURL     : configAuth.googleAuth.callbackURL,
        passReqToCallback : true // allows us to pass in the req from our route (lets us check if a user is logged in or not)

    },

    // facebook will send back the token and profile
    function(req, token, refreshToken, profile, res) {

        // asynchronous
        process.nextTick(function() {

            // check if the user is already logged in
            if (!req.user) {

                // find the user in the database based on their google id
                User.findOne({ 'google_id' : profile.id }, function(err, user) {

                    // if there is an error, stop everything and return that
                    // ie an error connecting to the database
                    if (err)
                        throw err;

                    // if the user is found, then log them in
                    if (user) {
                         // if there is a user id already but no token (user was linked at one point and then removed)
                        // just add our token and profile information
                        if(!user.google_token)
                        {
                            user.google_token = token;
                            user.google_name = profile.displayName;
                            user.google_email = profile.emails[0].value;
                        }
                        user.save(function(err) {
                                if (err)
                                    throw err;
                                res.json(user);
                            });

                       // create a token and return user
                     var token = jwt.sign(user, app.get('superSecret'), {
                        expiresIn: 86400 // expires in 24 hours
                        });
                        // after creating the token assign it to user and return
                        res.json({
                          user : user,
                          success: true,
                          message: 'Enjoy your token!',
                          token: token
                        }); 
                    } else {
                        // if there is no user found with that google id, create them
                        var newUser            = new User();
                    
                    //set all of the relevant information
                    newUser.google_id    = profile.id;  //save the profile id in a new variable in newUser.google.id
                    newUser.google_token = token;   //save the token value in a new variable
                    newUser.google_name  = profile.displayName; // save the display name in a new variable
                    newUser.google_email = profile.emails[0].value; // pull the first email

                        // save our user to the database
                        newUser.save(function(err) {
                            if (err)
                                throw err;

                             // create a token and return user
                            var token = jwt.sign(newUser, app.get('superSecret'), {
                                expiresIn: 86400 // expires in 24 hours
                            });
                            // after creating the token assign it to user and return
                            res.json({
                                 user : newUser,
                                 success: true,
                                 message: 'Enjoy your token!',
                                 token: token
                            }); 

                        });
                    }

                });

            } else {
                // user already exists and is logged in, we have to link accounts
                var user            = req.user; // pull the user out of the session

                // update the current users google credentials
                user.google_id    = profile.id;
                user.google_token = token;
                user.google_name  = profile.name.givenName + ' ' + profile.name.familyName;
                user.google_email = profile.emails[0].value;

                // save the user
                user.save(function(err) {
                    if (err)
                        throw err;
                     // create a token and return user
                            var token = jwt.sign(user, app.get('superSecret'), {
                                expiresIn: 86400 // expires in 24 hours
                            });
                            // after creating the token assign it to user and return
                            res.json({
                                 user : user,
                                 success: true,
                                 message: 'Enjoy your token!',
                                 token: token
                            }); 
                });
            }

        });

    }));


// twitter strategy

 passport.use(new TwitterStrategy({

        consumerKey     : configAuth.twitterAuth.consumerKey,
        consumerSecret  : configAuth.twitterAuth.consumerSecret,
        callbackURL     : configAuth.twitterAuth.callbackURL,
        passReqToCallback : true // allows us to pass in the req from our route (lets us check if a user is logged in or not)

    },
    function(req, token, tokenSecret, profile, res) {

        // asynchronous
        process.nextTick(function() {

            // check if the user is already logged in
            if (!req.user) {

                User.findOne({ 'twitter_id' : profile.id }, function(err, user) {
                    if (err)
                        throw err;

                    if (user) {
                        // if there is a user id already but no token (user was linked at one point and then removed)
                        if (!user.twitter_token) {
                            user.twitter_token       = token;
                            user.twitter_username    = profile.username;
                            user.twitter_displayName = profile.displayName;

                            user.save(function(err) {
                                if (err)
                                    throw err;
                                // create a token and return user
                            var token = jwt.sign(user, app.get('superSecret'), {
                                expiresIn: 86400 // expires in 24 hours
                            });
                            // after creating the token assign it to user and return
                            res.json({
                                 user : user,
                                 success: true,
                                 message: 'Enjoy your token!',
                                 token: token
                            }); 
                            });
                        }

                        res.json(user); // user found, return that user
                    } else {
                        // if there is no user, create them
                        var newUser                 = new User();

                        newUser.twitter_id          = profile.id;
                        newUser.twitter_token       = token;
                        newUser.twitter_username    = profile.username;
                        newUser.twitter_displayName = profile.displayName;

                        newUser.save(function(err) {
                            if (err)
                                throw err;
                            // create a token and return user
                            var token = jwt.sign(newUser, app.get('superSecret'), {
                                expiresIn: 86400 // expires in 24 hours
                            });
                            // after creating the token assign it to user and return
                            res.json({
                                 user : newUser,
                                 success: true,
                                 message: 'Enjoy your token!',
                                 token: token
                            }); 
                        });
                    }
                });

            } else {
                // user already exists and is logged in, we have to link accounts
                var user                 = req.user; // pull the user out of the session

                user.twitter_id          = profile.id;
                user.twitter_token       = token;
                user.twitter_username    = profile.username;
                user.twitter_displayName = profile.displayName;

                user.save(function(err) {
                    if (err)
                        throw err;
                    // create a token and return user
                            var token = jwt.sign(user, app.get('superSecret'), {
                                expiresIn: 86400 // expires in 24 hours
                            });
                            // after creating the token assign it to user and return
                            res.json({
                                 user : user,
                                 success: true,
                                 message: 'Enjoy your token!',
                                 token: token
                            }); 
                });
            }

        });

    }));

// route middleware to authenticate and check token
//var apiRoutes = api
apiRoutes.use(function(req, res, next) {

  // check header or url parameters or post parameters for token
  var token = req.body.token || req.param('token') || req.headers['x-access-token'];

  // decode token
  if (token) {

    // verifies secret and checks exp
    jwt.verify(token, app.get('superSecret'), function(err, decoded) {      
      if (err) {
        return res.json({ success: false, message: 'Failed to authenticate token.' });    
      } else {
        // if everything is good, save to request for use in other routes
        req.decoded = decoded;  
        next();
      }
    });

  } else {

    // if there is no token
    // return an error
    return res.status(403).send({ 
      success: false, 
      message: 'No token provided.'
    });
    
  }
  
});


// authenticated routes

apiRoutes.get('/', function(req, res) {
  res.json({ message: 'Welcome to the coolest API on earth!' });
});

apiRoutes.get('/users', function(req, res) {
  User.find({}, function(err, users) {
    res.json(users);
  });
});

apiRoutes.get('/check', function(req, res) {
  res.json(req.decoded);
});

app.use('/api', apiRoutes);

// start the server 

app.listen(port);
console.log('Magic happens at http://localhost:' + port);