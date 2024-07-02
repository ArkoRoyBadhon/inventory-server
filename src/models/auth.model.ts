import mongoose from "mongoose";

const AuthenticationSchema = new mongoose.Schema({
  role: {
    type: String,
    enum: ["owner", "staff", "customer"],
    required: true,
  },

  email: {
    type: String,
    required: true,
  },

  passwprd: {
    type: String,
    required: true,
  },
});

const Authentication = mongoose.model("Authentication", AuthenticationSchema);
AuthenticationSchema.pre("save",function(){
  
})
export default Authentication;
