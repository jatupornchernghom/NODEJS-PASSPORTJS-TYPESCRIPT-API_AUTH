import { Request, Response} from 'express'
import bcrypt from 'bcryptjs';
import db from '../config/database';
import passport from 'passport';

export const register = async (req: Request, res: Response) => {
  try {
    const { username, password } = req.body;

    // เช็คว่าชื่อผู้ใช้มีอยู่แล้วหรือไม่มี
    const [existingUsers]: any = await db.execute(
      'SELECT * FROM users WHERE username = ?',
      [username]
    );

    if (existingUsers.length) {
      return res.status(400).json({ message: 'Username already exists' });
    }

    // เข้ารหัส ใช้ salt 10 digit
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Save user to database
    await db.execute(
      'INSERT INTO users (username, password) VALUES (?, ?)',
      [username, hashedPassword]
    );

    res.status(201).json({ message: 'User registered successfully' });
    
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

export const login = (req: Request, res: Response, next: any) => {
  passport.authenticate('local', (err: Error, user: any, info: any) => {
    if (err) {
      return next(err);
    }
    
    if (!user) {
      return res.status(401).json({ message: info.message || 'Authentication failed' });
    }
    
    req.logIn(user, (err) => {
      if (err) {
        return next(err);
      }
      
      return res.json({ message: 'Login successful', user: { id: user.id, username: user.username } });
    });
  })(req, res, next);
};

export const logout = (req: Request, res: Response) => {
  req.logout(function(err) {
    if (err) { return res.status(500).json({ message: 'Error during logout' }); }
    res.json({ message: 'Logged out successfully' });
  });
};

export const getProfile = (req: Request, res: Response) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ message: 'Not authenticated' });
  }
  res.json({ user: req.user });
};



