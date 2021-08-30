const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const alert = require('alert');

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, 'Username cannot be blank!'],
        unique: [true, 'This username already exists']
    },
    password: {
        type: String,
        required: [true, 'Password cannot be blank!']
    }
})

const isValidArgs = (username, password) => !!(password && username && password.length && username.length)

userSchema.statics.isLoggedIn = async function (username, password) {
    if (!isValidArgs(username, password)) {
        alert("Invalid username or password.");
        return false
    }
    const foundUsername = await this.findOne({ username });
    if (!foundUsername || !password.length) {
        alert("Invalid username or password.");
        return false;
    }
    const isValidPassword = await bcrypt.compare(password, foundUsername.password);
    if (isValidPassword) {
        return foundUsername;
    }
    alert("Invalid username or password.");
    return false;
}

userSchema.statics.isValidUserCredentials = async function (username, password) {
    if (!isValidArgs(username, password)) {
        alert("Invalid username or password.")
        return false
    }
    const hasUser = await this.findOne({ username });
    if(hasUser){
        alert("Username has already been taken.");
        return false;
    }
    return true;
}

module.exports = mongoose.model('User', userSchema);