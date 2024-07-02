import express from "express";
const router = express.Router();

import products from "./product.route";
import category from "./category.route";

router.use("/product", products);
router.use("/category", category);

export default router;
