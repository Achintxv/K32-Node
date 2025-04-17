// route.js file
import express from 'express';
import passport from 'passport';
import jwt from 'jsonwebtoken';

const router = express.Router();

// Local login
router.post('/login',
    passport.authenticate('local', { session: false }),
    (req, res) => {
        const token = jwt.sign(
            { id: req.user._id },
            process.env.JWT_SECRET,
            { expiresIn: '1d' }
        );
        res.json({ token, user: req.user });
    }
);

// Google OAuth routes
router.get('/auth/google', passport.authenticate('google', { 
    session: false, 
    scope: ['profile', 'email'] 
}));

router.get('/auth/google/callback',
    passport.authenticate('google', { 
        session: false, 
        failureRedirect: '/login' 
    }),
    (req, res) => {
        const token = jwt.sign(
            { id: req.user._id },
            process.env.JWT_SECRET,
            { expiresIn: '1d' }
        );
        // Redirect with token or send JSON response
        res.redirect(`${process.env.FRONTEND_URL}/auth-success?token=${token}`);
    }
);

// Protected route 
router.get('/profile',
    passport.authenticate('jwt', { session: false }),
    (req, res) => {
        res.json(req.user);
    }
);

export default router;