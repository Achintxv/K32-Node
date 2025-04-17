import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import bcrypt from 'bcryptjs';
import userModel from '../models/user.model.js';

// Local Strategy
passport.use(
    new LocalStrategy(
        {
            emailField: 'email',
            passwordField: 'password',
        },
        async (email, password, done) => {
            try {
                const user = await userModel.findOne({ email }).select('+password');
                
                if (!user || !user.password) {
                    return done(null, false, { message: 'Incorrect email or password' });
                }

                const isMatch = await bcrypt.compare(password, user.password);
                
                if (isMatch) {
                    return done(null, user);
                } else {
                    return done(null, false, { message: 'Incorrect email or password' });
                }
            } catch (error) {
                return done(error);
            }
        }
    )
);

// JWT Strategy
const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET,
};

passport.use(
    new JwtStrategy(jwtOptions, async (jwtPayload, done) => {
        try {
            const user = await userModel.findById(jwtPayload.id);
            if (user) {
                return done(null, user);
            } else {
                return done(null, false);
            }
        } catch (error) {
            return done(error, false);
        }
    })
);

// Google OAuth Strategy
passport.use(
    new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL: '/api/auth/google/callback',
            scope: ['profile', 'email']
        },
        async (accessToken, refreshToken, profile, done) => {
            try {
                // Check if user already exists
                let user = await userModel.findOne({ googleId: profile.id });
                
                if (!user) {
                    // Check if email exists but Google ID is missing (merge accounts)
                    user = await userModel.findOne({ email: profile.emails[0].value });
                    
                    if (user) {
                        // Add Google ID to existing account
                        user.googleId = profile.id;
                        await user.save();
                    } else {
                        // Create new user
                        user = await userModel.create({
                            googleId: profile.id,
                            email: profile.emails[0].value,
                            name: profile.displayName
                        });
                    }
                }
                
                return done(null, user);
            } catch (error) {
                return done(error, null);
            }
        }
    )
);

// Serialize/Deserialize User
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await userModel.findById(id);
        done(null, user);
    } catch (error) {
        done(error);
    }
});

export default passport;