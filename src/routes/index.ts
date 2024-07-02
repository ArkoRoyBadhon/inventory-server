import express from "express";
const router = express.Router();
import reviewsController from "./review.route";

router.use("/r", reviewsController);

export default router;
