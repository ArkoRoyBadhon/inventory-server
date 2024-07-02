import { Request, Response, NextFunction } from "express";
import catchAsyncError from "../middlewares/catchAsyncErrors";
import Product from "../models/product.model";
import { validationResult } from "express-validator";

export const createProductController = catchAsyncError(
  async (req: Request, res: Response, next: NextFunction) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      const firstError = errors
        .array()
        .map((error: { msg: any }) => error.msg)[0];
      return res.status(422).json({
        errors: firstError,
      });
    }

    const {
      name,
      category,
      stock,
      price,
      discountPrice,
      brand,
      cell,
      service,
    } = req.body;

    try {
      const newProduct = await Product.create({
        name,
        category,
        stock,
        price,
        discountPrice,
        brand,
        cell,
        service,
      });

      return 
    //   res.status(201).json(newProduct);
    } catch (error) {
      res.status(500).json({ message: "Error creating product", error });
    }
  }
);
