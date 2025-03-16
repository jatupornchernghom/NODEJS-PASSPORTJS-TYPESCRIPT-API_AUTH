import express from 'express';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import passport from './config/passport';
import authRoutes from './routes/authRoutes';
import dotenv from 'dotenv';
import cors from "cors";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(cors({
  origin: "http://localhost:3000", // Allow only the frontend domain
  credentials: true, // Allow cookies/session credentials
})
); 
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
  secret: process.env.SESSION_SECRET || 'secret',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

app.use(passport.initialize());
app.use(passport.session());

app.use('/api/auth', authRoutes);

app.get('/', (req, res) => {
  res.send('Express + TypeScript + Passport.js + MySQL Auth API');
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

