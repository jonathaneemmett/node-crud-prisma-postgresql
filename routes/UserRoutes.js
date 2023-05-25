import { Router } from 'express';
import { login, register } from '../controllers/UserController.js';
import { tokenHandler } from '../middleware/AuthMiddleware.js';

const router = Router();

router.post('/register', register);
router.post('/login', login);

// TODO: Add a route to logout

export default router;
