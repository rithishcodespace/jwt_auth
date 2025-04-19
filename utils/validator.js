const validator = require("validator");

const validate = (emailId,password) =>{
    try{
      if(!validator.isEmail(emailId))
      {
        throw new Error("Not a valid emailId");
      }
      if(!validator.isStrongPassword(password))
      {
        throw new Error("Not a strong password");
      }
    }
    catch(error){
        throw new Error(error);
    }
}

module.exports = validate;