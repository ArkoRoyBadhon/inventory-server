import mongoose from "mongoose";

const staffScheam = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
});

const Staff = mongoose.model("Staff", staffScheam);
export default Staff;
