var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var bcrypt = require('bcrypt-nodejs');

// user schema for database
var userSchema = mongoose.Schema({
	email : String,
	password : String,
	name : String,
	userId : String,
	facebook_id : String,
	facebook_token : String,
	facebook_email : String,
	facebook_name : String,
	twitter_id : String,
	twitter_token : String,
	twitter_displayName : String,
	twitter_username : String,
	google_id : String,
	google_token : String,
	google_email : String,
	google_name : String
}); 

// generating a hash 
userSchema.methods.generateHash = function(password){
	return bcrypt.hashSync(password, bcrypt.genSaltSync(8), null);
};

// for comparing password
userSchema.methods.validPassword = function(password){
	return bcrypt.compareSync(password,this.password);
};

// create the model for users and expose this model for our server
module.exports = mongoose.model('User',userSchema);