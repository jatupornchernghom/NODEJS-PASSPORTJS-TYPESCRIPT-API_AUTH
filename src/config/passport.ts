import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import bcrypt from 'bcryptjs';
import db from './database';



passport.use(new LocalStrategy(
  async (username, password, done) => { // Defines a new LocalStrategy, which authenticates users based on username and password
    try {
      const [rows]: any = await db.execute( // Fetches ข้อมูลจาก database โดยใช้ db.execute().
        'SELECT * FROM users WHERE username = ?',
        [username]
      );

      if (!rows.length) { //ถ้าไม่เจอ username
        return done(null, false, { message: 'Incorrect username.' });
      }

      const user = rows[0];
      const isMatch = await bcrypt.compare(password, user.password); //เช็ค password ที่กับ uncrypt password จาก database 

      if (!isMatch) {//uncrypt password ไม่ตรงกันกับ password ที่ส่งมา
        return done(null, false, { message: 'Incorrect password.' });
      }

      return done(null, user); // the user object is passed to done(). (null = no err, user)
    } catch (error) {
      return done(error); // if get any err throw err done = (err)
    }
  }
));

passport.serializeUser((user: any, done) => {
  done(null, user.id); //Stores the user ID in the session 
});


//If a user is logged in, Passport automatically calls deserializeUser on each request
//This attaches the user object to req.user, so you can access it in routes
// This allows session-based authentication in Passport.js

passport.deserializeUser(async (id: number, done) => {
  try {
    const [rows]: any = await db.execute(
      'SELECT id, username FROM users WHERE id = ?', //Fetches user details from the database based on the stored ID
      [id]
    );
    
    if (!rows.length) {
      return done(null, false); // Authentication failed (invalid username or password)
    }
    
    done(null, rows[0]); // If the user exists, it restores the session user
  } catch (error) {
    done(error, null);
  }
});




export default passport;
