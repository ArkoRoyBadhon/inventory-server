import { Router } from "express";
const router = Router();
router.post("/create/customer");
router.post("/create/staff");
const authRoute = router;
export default authRoute;
