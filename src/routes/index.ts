import express from "express";
import authRoute from "./auth.route";
const router = express.Router();

const moduleRoute = [
  {
    path: "/auth",
    route: authRoute,
  },
];

moduleRoute.forEach((route) => router.use(route.path, route.route));

export default router;
