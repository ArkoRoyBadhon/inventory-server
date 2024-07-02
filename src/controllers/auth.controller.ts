import catchAsyncError from "../middlewares/catchAsyncErrors";

export const createCustomer = catchAsyncError(async (req, res) => {
  const { body } = req.body;
});
