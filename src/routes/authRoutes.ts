import { Router } from 'express';
import { register, login, logout, getProfile } from '../controllers/authController';
import { isAuthenticated } from '../middlewares/authMiddleware';

const router = Router();

router.post('/register', register);
router.post('/login', login);
router.get('/logout', isAuthenticated, logout);
router.get('/profile', isAuthenticated, getProfile);

export default router;
