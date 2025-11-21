console.log('🔵 SERVER.JS FILE LOADING - TOP OF FILE');

require('dotenv').config();
const dns = require('dns');
// Set DNS resolution order to prioritize IPv4 (Windows fix for MongoDB Atlas)
dns.setDefaultResultOrder('ipv4first');

console.log('🔵 DNS and dotenv configured');

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const config = require('./src/config/config') ;

// Student Schema
const studentSchema = new mongoose.Schema({
    name: { type: String, required: true },
    idNumber: { type: String, required: true, unique: true },
    kcseGrade: { type: String, required: true },
    admissionNumber: { type: String, required: true, unique: true },
    course: { type: String, required: true },
    department: { type: String, required: true },
    year: { type: Number, required: true },
    intake: { 
        type: String, 
        required: true, 
        enum: ['january', 'september'],
        lowercase: true 
    },
    intakeYear: { type: Number, required: true },
    phoneNumber: { type: String, required: true },
    email: { 
        type: String, 
        trim: true,
        lowercase: true,
        validate: {
            validator: function(v) {
                return !v || /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
            },
            message: 'Invalid email format'
        }
    },
    admissionType: { 
        type: String, 
        required: true, 
        enum: ['walk-in', 'KUCCPS'],
        default: 'walk-in'
    },
    password: { type: String, required: true },
    role: { type: String, default: 'student' },
    createdAt: { type: Date, default: Date.now }
});

// Hash password before saving
studentSchema.pre('save', async function(next) {
    if (this.isModified('password')) {
        this.password = await bcrypt.hash(this.password, 10);
    }
    next();
});

// Method to compare passwords
studentSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

// Register Student model (check if already exists for serverless compatibility)
const Student = mongoose.models.Student || mongoose.model('Student', studentSchema);

// Import models
const Unit = require('./src/models/Unit');
const Trainer = require('./src/models/Trainer');
const TrainerAssignment = require('./src/models/TrainerAssignment');
const HOD = require('./src/models/HOD');
const CommonUnit = require('./src/models/CommonUnit');
const CommonUnitAssignment = require('./src/models/CommonUnitAssignment');
const SystemSettings = require('./src/models/SystemSettings');
const StudentUnitRegistration = require('./src/models/StudentUnitRegistration');
const ToolsOfTrade = require('./src/models/ToolsOfTrade');
const Notification = require('./src/models/Notification');
const GraduationApplication = require('./src/models/GraduationApplication');
const AttachmentApplication = require('./src/models/AttachmentApplication');
const PasswordReset = require('./src/models/PasswordReset');
const StudentUpload = require('./src/models/StudentUpload');
const AuditLog = require('./src/models/AuditLog');
const StudentNote = require('./src/models/StudentNote');
const Payslip = require('./src/models/Payslip');
const AdminStaff = require('./src/models/AdminStaff');
const LoginOTP = require('./src/models/LoginOTP');

// Import services
const EmailService = require('./src/utils/emailService');
const { uploadToS3, getPresignedUrl, deleteFromS3, isS3Configured } = require('./src/utils/s3Service');

// Initialize email service
const emailService = new EmailService();

// Import data parsers
const { getAllTrainers, parseTrainersFile } = require('./src/data/trainerData');

// Utility function to format course names
function formatCourseNameServer(courseCode) {
    if (!courseCode) return 'Unknown Course';
    
    // Course name mappings
    const courseNames = {
        'analytical_chemistry_6': 'Analytical Chemistry',
        'sustainable_agriculture_5': 'Sustainable Agriculture',
        'building_technology_6': 'Building Technology',
        'electrical_installation_6': 'Electrical Installation',
        'food_beverage_6': 'Food & Beverage Service',
        'business_management_6': 'Business Management',
        'computer_science_6': 'Computer Science',
        'fashion_design_4': 'Fashion & Design',
        'science_laboratory_technology_6': 'Science Laboratory Technology',
        'crop_production_6': 'Crop Production',
        'civil_engineering_6': 'Civil Engineering',
        'mechanical_engineering_6': 'Mechanical Engineering',
        'hospitality_management_6': 'Hospitality Management',
        'accounting_6': 'Accounting',
        'information_technology_6': 'Information Technology',
        'interior_design_4': 'Interior Design'
    };
    
    return courseNames[courseCode] || courseCode.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
}

// Import routes (conditionally) and database initializer
let studentRoutes;
try {
    studentRoutes = require('./src/server/routes/student');
} catch (err) {
    console.warn('Student routes file not found, using inline student endpoints.');
}

const adminAuthRoutes = require('./src/routes/adminAuth');

console.log('🔵 All imports loaded successfully');

const app = express();

console.log('🔵 Express app created');

// Create uploads directory if it doesn't exist (skip in serverless/Vercel environment)
const uploadsDir = path.join(__dirname, 'uploads');
if (!process.env.VERCEL && !fs.existsSync(uploadsDir)) {
    try {
        fs.mkdirSync(uploadsDir, { recursive: true });
        console.log('✅ Created uploads directory');
    } catch (err) {
        console.warn('⚠️  Could not create uploads directory (using S3):', err.message);
    }
} else if (process.env.VERCEL) {
    console.log('🌐 Running on Vercel - using S3 for file storage');
}

// Multer configuration for file uploads
// Use memory storage for S3 uploads, or disk storage as fallback
const storage = isS3Configured() 
    ? multer.memoryStorage() // Store in memory for S3 upload
    : multer.diskStorage({
        destination: function (req, file, cb) {
            // Fallback: local storage if S3 not configured
            const uploadPath = path.join(uploadsDir, 'tools-of-trade', 'general');
            if (!fs.existsSync(uploadPath)) {
                fs.mkdirSync(uploadPath, { recursive: true });
            }
            cb(null, uploadPath);
        },
        filename: function (req, file, cb) {
            const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
            const extension = path.extname(file.originalname);
            cb(null, file.fieldname + '-' + uniqueSuffix + extension);
        }
    });

const fileFilter = (req, file, cb) => {
    const allowedTypes = [
        'application/pdf', 
        'application/msword', 
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'image/jpeg',
        'image/jpg', 
        'image/png',
        'video/mp4',
        'video/mpeg',
        'video/quicktime'
    ];
    if (allowedTypes.includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error('Invalid file type. Allowed: PDF, DOC, DOCX, JPG, PNG, MP4'), false);
    }
};

const upload = multer({
    storage: storage,
    fileFilter: fileFilter,
    limits: {
        fileSize: 10 * 1024 * 1024 // 10MB limit (increased for images and videos)
    }
});

// ===============================
// DATABASE CONNECTION
// ===============================

// Connect to MongoDB  
const connectDB = async () => {
    try {
        console.log('🔄 Connecting to MongoDB...');
        console.log(`📍 MongoDB URI: ${config.mongodbUri.replace(/\/\/.*@/, '//***@')}`);
        
        await mongoose.connect(config.mongodbUri, {
            serverSelectionTimeoutMS: 30000, // 30 seconds timeout
            socketTimeoutMS: 45000,
            family: 4, // Force IPv4 (Windows DNS resolution fix)
        });
        
        console.log('✅ Connected to MongoDB successfully!');
        console.log(`📊 Database: ${mongoose.connection.name}`);
        
        // Initialize default data
        await initializeSystemSettings();
        await initializeCommonUnits();
        await initializeTrainers();
        await initializeAdminStaff();
        
    } catch (error) {
        console.error('❌ MongoDB connection error:', error.message);
        console.error('Full error:', error);
        
        // In production, try to reconnect after 5 seconds
        if (config.nodeEnv === 'production') {
            console.log('🔄 Attempting to reconnect in 5 seconds...');
            setTimeout(connectDB, 5000);
        } else {
            // In development, just log and continue
            console.warn('⚠️  Running without database connection (development mode)');
        }
    }
};

// Handle MongoDB connection events
mongoose.connection.on('disconnected', () => {
    console.log('⚠️  MongoDB disconnected');
});

mongoose.connection.on('error', (err) => {
    console.error('❌ MongoDB error:', err);
});

mongoose.connection.on('reconnected', () => {
    console.log('✅ MongoDB reconnected');
});

// Connect to database
connectDB();

console.log('✅ Past connectDB() call, loading middleware and routes...');

// Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

// Serve static files from src directory (for HTML, CSS, JS)
app.use('/src', express.static(path.join(__dirname, 'src')));
app.use(express.static(path.join(__dirname, 'src')));

// Helper function to serve HTML files (Vercel-compatible)
const serveHTML = (res, filePath) => {
    if (process.env.VERCEL) {
        // In Vercel, read file and send content directly
        try {
            const content = fs.readFileSync(filePath, 'utf8');
            res.setHeader('Content-Type', 'text/html');
            res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
            res.send(content);
        } catch (err) {
            console.error('Error reading file:', err);
            res.status(404).send('Page not found');
        }
    } else {
        // Local development: use sendFile
        res.sendFile(filePath);
    }
};

// Request logger middleware
app.use((req, res, next) => {
    console.log(` ${req.method} ${req.url} - ${new Date().toISOString()}`);
    if (req.url.includes('/api/auth/')) {
        console.log(' AUTH REQUEST:', req.method, req.url);
    }
    next();
});

// ===============================
// FORGOT PASSWORD API ENDPOINTS  
// ===============================

// Forgot password endpoint - Initiate password reset (OTP or Token)
app.post('/api/auth/forgot-password', async (req, res) => {
    console.log('🔐 FORGOT PASSWORD ENDPOINT HIT!');
    console.log('Request body:', req.body);
    console.log('Request headers:', req.headers);
    console.log('Request method:', req.method);
    console.log('Request URL:', req.url);
    
    try {
        const { email, resetMethod, userType } = req.body;
        
        if (!email || !resetMethod || !userType) {
            return res.status(400).json({ 
                success: false, 
                message: 'Email, reset method, and user type are required' 
            });
        }

        if (!['otp', 'token'].includes(resetMethod)) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid reset method. Use "otp" or "token"' 
            });
        }

        if (!['student', 'trainer', 'hod'].includes(userType)) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid user type' 
            });
        }

        // Find user based on type
        let user = null;
        let userData = null;

        if (userType === 'hod') {
            user = await HOD.findOne({ email: email.toLowerCase(), isActive: true });
            if (user) {
                userData = {
                    userId: user._id,
                    name: user.name,
                    email: user.email,
                    department: user.department
                };
            }
        } else if (userType === 'trainer') {
            user = await Trainer.findOne({ email: email.toLowerCase(), isActive: true });
            if (user) {
                userData = {
                    userId: user._id,
                    name: user.name,
                    email: user.email,
                    department: user.department
                };
            }
        } else if (userType === 'student') {
            user = await Student.findOne({ email: email.toLowerCase() });
            if (user) {
                userData = {
                    userId: user._id,
                    name: user.name,
                    email: user.email,
                    admissionNumber: user.admissionNumber
                };
            }
        }

        // Always return the same response to prevent email enumeration
        const standardResponse = {
            success: true,
            message: `If an account with that email exists, you will receive a ${resetMethod === 'otp' ? 'verification code' : 'reset link'} shortly.`
        };

        // If user not found, still return success but don't send email
        if (!user) {
            return res.json(standardResponse);
        }

        // Check rate limiting - max 3 attempts per 15 minutes
        const recentAttempts = await PasswordReset.countDocuments({
            email: email.toLowerCase(),
            userType: userType,
            createdAt: { $gt: new Date(Date.now() - 15 * 60 * 1000) }
        });

        if (recentAttempts >= 3) {
            return res.json(standardResponse); // Don't reveal rate limiting
        }

        // Invalidate any existing reset requests for this user
        await PasswordReset.invalidateUserResets(userData.userId, userType);

        // Create new reset request
        const resetData = {
            userId: userData.userId,
            userType: userType,
            email: email.toLowerCase(),
            resetType: resetMethod,
            ipAddress: req.ip || req.connection.remoteAddress || 'unknown',
            userAgent: req.get('User-Agent') || 'unknown'
        };

        if (resetMethod === 'otp') {
            resetData.otp = PasswordReset.generateOTP();
        } else {
            resetData.resetToken = PasswordReset.generateResetToken();
        }

        const passwordReset = new PasswordReset(resetData);
        await passwordReset.save();

        // Send email
        try {
            if (resetMethod === 'otp') {
                await emailService.sendOTPEmail(
                    userData.email, 
                    resetData.otp, 
                    userData.name, 
                    userType
                );
            } else {
                await emailService.sendResetLinkEmail(
                    userData.email, 
                    resetData.resetToken, 
                    userData.name, 
                    userType
                );
            }
        } catch (emailError) {
            console.error('Email sending failed:', emailError);
            // Don't reveal email failure to user
        }

        res.json(standardResponse);

    } catch (error) {
        console.error('Error in forgot password:', error);
        res.status(500).json({ 
            success: false, 
            message: 'An error occurred. Please try again later.' 
        });
    }
});

// Verify OTP endpoint
app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { email, otp, userType } = req.body;
        
        if (!email || !otp || !userType) {
            return res.status(400).json({ 
                success: false, 
                message: 'Email, OTP, and user type are required' 
            });
        }

        // Find valid OTP reset request
        const resetRequest = await PasswordReset.findValidReset({
            email: email.toLowerCase(),
            userType: userType,
            resetType: 'otp',
            otp: otp
        });

        if (!resetRequest) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid or expired OTP' 
            });
        }

        if (!resetRequest.canAttempt()) {
            return res.status(400).json({ 
                success: false, 
                message: 'Maximum OTP attempts exceeded or OTP expired' 
            });
        }

        // Generate session token for password reset
        const sessionToken = PasswordReset.generateResetToken();
        
        // Create a session token entry (reuse the same document)
        resetRequest.resetToken = sessionToken;
        resetRequest.isUsed = true; // Mark OTP as used
        resetRequest.usedAt = new Date();
        await resetRequest.save();

        // Create new session for password reset
        const sessionReset = new PasswordReset({
            userId: resetRequest.userId,
            userType: userType,
            email: email.toLowerCase(),
            resetType: 'token',
            resetToken: sessionToken,
            ipAddress: req.ip || req.connection.remoteAddress || 'unknown',
            userAgent: req.get('User-Agent') || 'unknown',
            expiresAt: new Date(Date.now() + 30 * 60 * 1000) // 30 minutes for password reset
        });
        
        await sessionReset.save();

        res.json({
            success: true,
            message: 'OTP verified successfully',
            sessionToken: sessionToken
        });

    } catch (error) {
        console.error('Error verifying OTP:', error);
        res.status(500).json({ 
            success: false, 
            message: 'An error occurred. Please try again later.' 
        });
    }
});

// Reset password endpoint
app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { token, newPassword, userType, sessionToken } = req.body;
        
        // Check if it's a session token (from OTP flow) or reset token (from email link)
        const resetToken = sessionToken || token;
        
        if (!resetToken || !newPassword || !userType) {
            return res.status(400).json({ 
                success: false, 
                message: 'Token, new password, and user type are required' 
            });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({ 
                success: false, 
                message: 'Password must be at least 6 characters long' 
            });
        }

        // Find valid reset request
        const resetRequest = await PasswordReset.findValidReset({
            resetToken: resetToken,
            userType: userType,
            resetType: 'token'
        });

        if (!resetRequest) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid or expired reset token' 
            });
        }

        // Find and update user password
        let user = null;
        if (userType === 'hod') {
            user = await HOD.findById(resetRequest.userId);
        } else if (userType === 'trainer') {
            user = await Trainer.findById(resetRequest.userId);
        } else if (userType === 'student') {
            user = await Student.findById(resetRequest.userId);
        }

        if (!user) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }

        // Update password
        if (userType === 'student') {
            // For students, password is stored as plain text (phone number)
            user.password = newPassword;
        } else {
            // For HOD and trainers, set the plain password - the model's pre-save hook will hash it
            user.password = newPassword;
        }
        
        await user.save();

        // Mark reset request as used
        await resetRequest.markAsUsed();

        // Invalidate all other reset requests for this user
        await PasswordReset.invalidateUserResets(resetRequest.userId, userType);

        res.json({
            success: true,
            message: 'Password reset successfully'
        });

    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).json({ 
            success: false, 
            message: 'An error occurred. Please try again later.' 
        });
    }
});

// Validate reset token endpoint (for email links)
app.get('/api/auth/validate-reset-token/:token', async (req, res) => {
    try {
        const { token } = req.params;
        const { type } = req.query;
        
        if (!token || !type) {
            return res.status(400).json({ 
                success: false, 
                message: 'Token and user type are required' 
            });
        }

        const resetRequest = await PasswordReset.findValidReset({
            resetToken: token,
            userType: type,
            resetType: 'token'
        });

        if (!resetRequest) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid or expired reset token' 
            });
        }

        res.json({
            success: true,
            message: 'Token is valid',
            email: resetRequest.email,
            userType: resetRequest.userType
        });

    } catch (error) {
        console.error('Error validating reset token:', error);
        res.status(500).json({ 
            success: false, 
            message: 'An error occurred. Please try again later.' 
        });
    }
});

// Reset password page route
app.get('/reset-password', (req, res) => {
    res.sendFile(path.join(__dirname, 'src', 'components', 'auth', 'ResetPassword.html'));
});

// Debug page route
app.get('/debug', (req, res) => {
    res.sendFile(path.join(__dirname, 'debug.html'));
});


// Admin staff authentication routes
app.use('/api/admin/auth', adminAuthRoutes);

// Admin portal pages (MUST BE BEFORE GENERIC ROUTES)
app.get('/admin/login', (req, res) => {
    const filePath = path.join(__dirname, 'src', 'components', 'admin', 'AdminLogin.html');
    console.log('🔐 Admin login requested');
    console.log('📂 File path:', filePath);
    console.log('📁 File exists:', fs.existsSync(filePath));
    
    serveHTML(res, filePath);
});

app.get('/admin/first-login', (req, res) => {
    console.log('📝 First login page requested');
    serveHTML(res, path.join(__dirname, 'src', 'components', 'admin', 'FirstLogin.html'));
});

app.get('/admin/dashboard', (req, res) => {
    console.log('📊 Admin dashboard requested');
    res.set({
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
    });
    serveHTML(res, path.join(__dirname, 'src', 'components', 'admin', 'AdminDashboard.html'));
});

// Serve main login page (Student/Trainer combined)
app.get('/login', (req, res) => {
    serveHTML(res, path.join(__dirname, 'src', 'login.html'));
});

// Serve HOD pages
app.get('/hod/login', (req, res) => {
    serveHTML(res, path.join(__dirname, 'src', 'components', 'hod', 'HODLogin.html'));
});

app.get('/hod/dashboard', (req, res) => {
    serveHTML(res, path.join(__dirname, 'src', 'components', 'hod', 'HODDashboard.html'));
});

// Serve trainer pages
app.get('/trainer/login', (req, res) => {
    serveHTML(res, path.join(__dirname, 'src', 'components', 'trainer', 'TrainerLogin.html'));
});

app.get('/trainer/dashboard', (req, res) => {
    serveHTML(res, path.join(__dirname, 'src', 'components', 'trainer', 'TrainerDashboard.html'));
});

// Serve student pages
app.get('/student/dashboard', (req, res) => {
    serveHTML(res, path.join(__dirname, 'src', 'components', 'student', 'StudentPortalTailwind.html'));
});

// Serve admission letter template
app.get('/src/components/registrar/AdmissionLetter.html', (req, res) => {
    serveHTML(res, path.join(__dirname, 'src', 'components', 'registrar', 'AdmissionLetter.html'));
});

// Function to initialize programs in database
async function initializePrograms() {
    try {
        const programs = [
            // Applied Science Department
            { programName: 'Applied Biology Level 6', programCost: 67189, department: 'applied_science' },
            { programName: 'Analytical Chemistry Level 6', programCost: 67189, department: 'applied_science' },
            { programName: 'Science Lab Technology Level 5', programCost: 67189, department: 'applied_science' },
            
            // Agriculture Department
            { programName: 'General Agriculture Level 4', programCost: 67189, department: 'agriculture' },
            { programName: 'Sustainable Agriculture Level 5', programCost: 67189, department: 'agriculture' },
            { programName: 'Agricultural Extension Level 6', programCost: 67189, department: 'agriculture' },
            
            // Building and Civil Department
            { programName: 'Building Technician Level 4', programCost: 67189, department: 'building_civil' },
            { programName: 'Building Technician Level 6', programCost: 67189, department: 'building_civil' },
            { programName: 'Civil Engineering Level 6', programCost: 67189, department: 'building_civil' },
            { programName: 'Plumbing Level 4', programCost: 67189, department: 'building_civil' },
            { programName: 'Plumbing Level 5', programCost: 67189, department: 'building_civil' },
            
            // Electromechanical Department
            { programName: 'Electrical Engineering Level 4', programCost: 67189, department: 'electromechanical' },
            { programName: 'Electrical Engineering Level 5', programCost: 67189, department: 'electromechanical' },
            { programName: 'Electrical Engineering Level 6', programCost: 67189, department: 'electromechanical' },
            { programName: 'Automotive Engineering Level 5', programCost: 67189, department: 'electromechanical' },
            { programName: 'Automotive Engineering Level 6', programCost: 67189, department: 'electromechanical' },
            
            // Hospitality Department
            { programName: 'Food and Beverage Level 4', programCost: 67189, department: 'hospitality' },
            { programName: 'Food & Beverage Level 5', programCost: 67189, department: 'hospitality' },
            { programName: 'Food & Beverage Level 6', programCost: 67189, department: 'hospitality' },
            { programName: 'Fashion & Design Level 4', programCost: 67189, department: 'hospitality' },
            { programName: 'Fashion and Design Level 5', programCost: 67189, department: 'hospitality' },
            { programName: 'Fashion and Design Level 6', programCost: 67189, department: 'hospitality' },
            { programName: 'Hairdressing Level 4', programCost: 67189, department: 'hospitality' },
            { programName: 'Hairdressing Level 5', programCost: 67189, department: 'hospitality' },
            { programName: 'Hairdressing Level 6', programCost: 67189, department: 'hospitality' },
            { programName: 'Tourism Management Level 5', programCost: 67189, department: 'hospitality' },
            { programName: 'Tourism Management Level 6', programCost: 67189, department: 'hospitality' },
            
            // Business and Liberal Studies Department
            { programName: 'Social Work Level 5', programCost: 67189, department: 'business_liberal' },
            { programName: 'Social Work Level 6', programCost: 67189, department: 'business_liberal' },
            { programName: 'Office Administration Level 5', programCost: 67189, department: 'business_liberal' },
            { programName: 'Office Administration Level 6', programCost: 67189, department: 'business_liberal' },
            
            // Computing and Informatics Department
            { programName: 'ICT Level 5', programCost: 67189, department: 'computing_informatics' },
            { programName: 'ICT Level 6', programCost: 67189, department: 'computing_informatics' },
            { programName: 'Information Science Level 5', programCost: 67189, department: 'computing_informatics' },
            { programName: 'Information Science Level 6', programCost: 67189, department: 'computing_informatics' }
        ];

        for (const programData of programs) {
            const existingProgram = await Program.findOne({ programName: programData.programName });
            if (!existingProgram) {
                const program = new Program(programData);
                await program.save();
                console.log(`Program created: ${programData.programName}`);
            }
        }

        console.log('Programs initialization completed!');
    } catch (error) {
        console.error('Error initializing programs:', error);
    }
}

// Function to filter out common units from course units
function filterCommonUnits(units) {
    // Define common unit names that should be excluded from department units
    const commonUnitNames = [
        'Demonstrate Communication Skills',
        'Communication Skills',
        'Demonstrate Numeracy Skills', 
        'Numeracy Skills',
        'Demonstrate Digital Literacy',
        'Digital Literacy',
        'Demonstrate Understanding of Entrepreneurship',
        'Demonstrate Entrepreneural Skills',
        'Demonstrate Entrepreneurial Skills',
        'Entrepreneurial Skills',
        'Entrepreneural Skills',
        'Demonstrate Employability Skills',
        'Employability Skills',
        'Demonstrate Environmental Literacy',
        'Environmental Literacy',
        'Demonstrate Occupational Safety and Health Practices',
        'Occupational Safety and Health Practices',
        'OSH Practices'
    ];
    
    return units.filter(unit => {
        const isCommonUnit = commonUnitNames.some(commonName => 
            unit.unitName.toLowerCase().includes(commonName.toLowerCase()) ||
            commonName.toLowerCase().includes(unit.unitName.toLowerCase())
        );
        return !isCommonUnit;
    });
}

// Function to initialize units in database
async function initializeUnits() {
    try {
        // Import course units data
        const { courseUnits } = require('./src/data/courseUnits');
        
        // Check if units already exist
        const existingUnitsCount = await Unit.countDocuments();
        if (existingUnitsCount > 0) {
            console.log(`Units already initialized (${existingUnitsCount} units found)`);
            // Check if we have all the course codes from courseUnits
            const courseCodesInDb = await Unit.distinct('courseCode');
            const courseCodesInMapping = Object.keys(courseUnits);
            const missingCourses = courseCodesInMapping.filter(code => !courseCodesInDb.includes(code));
            
            if (missingCourses.length > 0) {
                console.log(`Found ${missingCourses.length} missing course codes: ${missingCourses.join(', ')}`);
                console.log('Adding missing units...');
                
                // Add units for missing courses
                let unitsAdded = 0;
                for (const courseCode of missingCourses) {
                    const courseData = courseUnits[courseCode];
                    const { department, level, units } = courseData;

                    // Filter out common units
                    const departmentUnits = filterCommonUnits(units);

                    for (const unitData of departmentUnits) {
                        const unit = new Unit({
                            unitName: unitData.unitName,
                            unitCode: unitData.unitCode,
                            courseCode: courseCode,
                            department: department,
                            level: level,
                            description: `${unitData.unitName} - Part of ${courseCode.replace(/_/g, ' ').toUpperCase()} program`,
                            isActive: true
                        });

                        await unit.save();
                        unitsAdded++;
                    }
                }
                console.log(`Successfully added ${unitsAdded} units for ${missingCourses.length} missing courses`);
            }
            return;
        }

        console.log('Initializing units...');
        let totalUnitsAdded = 0;

        // Process each course and its units
        for (const [courseCode, courseData] of Object.entries(courseUnits)) {
            const { department, level, units } = courseData;
            
            // Filter out common units
            const departmentUnits = filterCommonUnits(units);
            const filteredCount = units.length - departmentUnits.length;
            if (filteredCount > 0) {
                console.log(`  📋 ${courseCode}: Filtered out ${filteredCount} common units, keeping ${departmentUnits.length} department-specific units`);
            }

            // Create units for this course
            for (const unitData of departmentUnits) {
                const unit = new Unit({
                    unitName: unitData.unitName,
                    unitCode: unitData.unitCode,
                    courseCode: courseCode,
                    department: department,
                    level: level,
                    description: `${unitData.unitName} - Part of ${courseCode.replace(/_/g, ' ').toUpperCase()} program`,
                    isActive: true
                });

                await unit.save();
                totalUnitsAdded++;
            }
        }

        console.log(`Successfully initialized ${totalUnitsAdded} units across ${Object.keys(courseUnits).length} courses`);
    } catch (error) {
        console.error('Error initializing units:', error);
    }
}

// Function to initialize trainers in database
async function initializeTrainers() {
    try {
        console.log('🔄 Initializing trainers (preserving existing ones)...');

        const trainersByDepartment = parseTrainersFile();
        console.log('📋 Departments found in trainers.txt:', Object.keys(trainersByDepartment));
        
        let newTrainersAdded = 0;
        let existingTrainersFound = 0;
        
        for (const [department, trainers] of Object.entries(trainersByDepartment)) {
            console.log(`🔍 Checking ${trainers.length} trainers for department: ${department}`);
            
            for (const trainerData of trainers) {
                // Check if trainer already exists by email (unique identifier)
                const existingTrainer = await Trainer.findOne({ email: trainerData.email });
                
                if (existingTrainer) {
                    // Update existing trainer if needed
                    let updated = false;
                    if (existingTrainer.department !== trainerData.department) {
                        existingTrainer.department = trainerData.department;
                        updated = true;
                    }
                    if (existingTrainer.name !== trainerData.name) {
                        existingTrainer.name = trainerData.name;
                        updated = true;
                    }
                    
                    if (updated) {
                        await existingTrainer.save();
                        console.log(`  ✏️ Updated trainer: ${trainerData.name}`);
                    } else {
                        console.log(`  ✅ Existing trainer: ${trainerData.name}`);
                    }
                    existingTrainersFound++;
                } else {
                    // Create new trainer
                    console.log(`  ➕ Adding new trainer: ${trainerData.name} to department: ${trainerData.department}`);
                const trainer = new Trainer(trainerData);
                await trainer.save();
                    newTrainersAdded++;
                }
            }
        }

        console.log(`✅ Trainer initialization complete!`);
        console.log(`📊 Summary: ${existingTrainersFound} existing, ${newTrainersAdded} new trainers`);
        
        // Only fix references if we have broken ones
        const allAssignments = await TrainerAssignment.find({ status: 'active' });
        const allTrainers = await Trainer.find({});
        const currentTrainerIds = allTrainers.map(t => t._id.toString());
        
        const brokenAssignments = allAssignments.filter(assignment => 
            !assignment.trainerId || !currentTrainerIds.includes(assignment.trainerId.toString())
        );
        
        if (brokenAssignments.length > 0) {
            console.log(`🔧 Found ${brokenAssignments.length} broken trainer references, fixing...`);
            await fixBrokenTrainerReferences();
        } else {
            console.log('✅ All trainer references are valid');
        }
        
        // Check unit references
        const allUnits = await Unit.find({ isActive: true });
        const currentUnitIds = allUnits.map(u => u._id.toString());
        
        const brokenUnitAssignments = allAssignments.filter(assignment => 
            !assignment.unitId || !currentUnitIds.includes(assignment.unitId.toString())
        );
        
        if (brokenUnitAssignments.length > 0) {
            console.log(`🔧 Found ${brokenUnitAssignments.length} broken unit references, fixing...`);
            await fixBrokenUnitReferences();
        } else {
            console.log('✅ All unit references are valid');
        }
        
    } catch (error) {
        console.error('❌ Error initializing trainers:', error);
    }
}

// Function to fix broken trainer references in assignments
async function fixBrokenTrainerReferences() {
    try {
        console.log('Fixing broken trainer references in assignments...');
        
        // Get all assignments with null or invalid trainer references
        const brokenAssignments = await TrainerAssignment.find({
            $or: [
                { trainerId: null },
                { trainerId: { $exists: false } }
            ],
            status: 'active'
        });
        
        console.log(`Found ${brokenAssignments.length} assignments with broken trainer references`);
        
        if (brokenAssignments.length === 0) {
            return;
        }
        
        // Get all current trainers
        const allTrainers = await Trainer.find({});
        console.log(`Available trainers: ${allTrainers.map(t => t.name).join(', ')}`);
        
        let fixedCount = 0;
        
        // For now, we'll assign all broken assignments to the first trainer in each department
        // This is a temporary fix - in production you'd want a more sophisticated matching
        for (const assignment of brokenAssignments) {
            const departmentTrainers = allTrainers.filter(t => t.department === assignment.department);
            
            if (departmentTrainers.length > 0) {
                // Assign to first trainer in the department (you could implement better logic here)
                const trainer = departmentTrainers[0];
                assignment.trainerId = trainer._id;
                await assignment.save();
                
                console.log(`Fixed assignment for unit ${assignment.courseCode} - assigned to ${trainer.name}`);
                fixedCount++;
            } else {
                console.warn(`No trainers found for department ${assignment.department}`);
            }
        }
        
        console.log(`Successfully fixed ${fixedCount} broken trainer references`);
        
    } catch (error) {
        console.error('Error fixing broken trainer references:', error);
    }
}

// Function to fix broken unit references in assignments
async function fixBrokenUnitReferences() {
    try {
        console.log('🔧 Fixing broken unit references in assignments...');
        
        // Get all active assignments
        const allAssignments = await TrainerAssignment.find({ status: 'active' });
        console.log(`📋 Found ${allAssignments.length} total active assignments`);
        
        // Get all current units
        const currentUnits = await Unit.find({ isActive: true });
        const currentUnitIds = currentUnits.map(u => u._id.toString());
        
        console.log(`📚 Found ${currentUnits.length} active units in database`);
        
        // Find assignments with invalid unit references
        const brokenAssignments = [];
        for (const assignment of allAssignments) {
            if (!assignment.unitId || !currentUnitIds.includes(assignment.unitId.toString())) {
                brokenAssignments.push(assignment);
            }
        }
        
        console.log(`🔍 Found ${brokenAssignments.length} assignments with broken/invalid unit references`);
        
        if (brokenAssignments.length === 0) {
            console.log('✅ No broken unit references found');
            return;
        }
        
        let fixedCount = 0;
        
        for (const assignment of brokenAssignments) {
            // Try to find a unit by course code and department
            const matchingUnits = currentUnits.filter(u => 
                u.courseCode === assignment.courseCode && u.department === assignment.department
            );
            
            if (matchingUnits.length > 0) {
                // Assign to first matching unit
                const unit = matchingUnits[0];
                assignment.unitId = unit._id;
                await assignment.save();
                
                console.log(`✅ Fixed unit reference for assignment ${assignment.courseCode} - assigned to unit ${unit.unitCode}`);
                fixedCount++;
            } else {
                console.warn(`⚠️ No matching units found for assignment ${assignment.courseCode} in department ${assignment.department}`);
                
                // Try to find any unit with the same course code (ignore department)
                const anyMatchingUnit = currentUnits.find(u => u.courseCode === assignment.courseCode);
                if (anyMatchingUnit) {
                    assignment.unitId = anyMatchingUnit._id;
                    await assignment.save();
                    console.log(`✅ Fixed unit reference for assignment ${assignment.courseCode} - assigned to unit ${anyMatchingUnit.unitCode} (cross-department)`);
                    fixedCount++;
                }
            }
        }
        
        console.log(`✅ Successfully fixed ${fixedCount} broken unit references`);
        
    } catch (error) {
        console.error('❌ Error fixing broken unit references:', error);
    }
}

// Function to initialize HODs in database
async function initializeHODs() {
    try {
        const existingHODsCount = await HOD.countDocuments();
        if (existingHODsCount > 0) {
            console.log(`HODs already initialized (${existingHODsCount} HODs found)`);
            return;
        }

        const departments = HOD.getAllDepartments();
        console.log(`Initializing ${departments.length} HODs...`);

        for (const dept of departments) {
            const hod = new HOD({
                department: dept.code,
                name: `HOD ${dept.name}`,
                email: `hod.${dept.code}@ace.ac.ke`,
                password: 'HOD' // Will be hashed automatically
            });
            await hod.save();
        }

        console.log(`Successfully initialized ${departments.length} HODs!`);
    } catch (error) {
        console.error('Error initializing HODs:', error);
    }
}

// Initialize Common Units
async function initializeCommonUnits() {
    try {
        console.log('🔄 Initializing common units...');
        
        // Common units data from the requirements
        const commonUnits = [
            {
                unitCode: 'COM001',
                unitName: 'Communication Skills',
                courseCode: 'COMMON',
                courseName: 'Common Units',
                level: 'certificate',
                description: 'Essential communication skills for all students'
            },
            {
                unitCode: 'COM002',
                unitName: 'Numeracy Skills',
                courseCode: 'COMMON',
                courseName: 'Common Units',
                level: 'certificate',
                description: 'Basic mathematical and numerical skills'
            },
            {
                unitCode: 'COM003',
                unitName: 'Digital Literacy',
                courseCode: 'COMMON',
                courseName: 'Common Units',
                level: 'certificate',
                description: 'Essential digital and computer literacy skills'
            },
            {
                unitCode: 'COM004',
                unitName: 'Entrepreneurial Skills',
                courseCode: 'COMMON',
                courseName: 'Common Units',
                level: 'certificate',
                description: 'Basic entrepreneurship and business skills'
            },
            {
                unitCode: 'COM005',
                unitName: 'Employability Skills',
                courseCode: 'COMMON',
                courseName: 'Common Units',
                level: 'certificate',
                description: 'Skills for employment readiness and workplace success'
            },
            {
                unitCode: 'COM006',
                unitName: 'Environmental Literacy',
                courseCode: 'COMMON',
                courseName: 'Common Units',
                level: 'certificate',
                description: 'Environmental awareness and sustainability practices'
            },
            {
                unitCode: 'COM007',
                unitName: 'Occupational Safety and Health (OSH) Practices',
                courseCode: 'COMMON',
                courseName: 'Common Units',
                level: 'certificate',
                description: 'Workplace safety and health practices'
            }
        ];

        let existingCount = 0;
        let newCount = 0;

        for (const unitData of commonUnits) {
            const existingUnit = await CommonUnit.findOne({ unitCode: unitData.unitCode });
            
            if (existingUnit) {
                // Update existing unit if needed
                Object.assign(existingUnit, unitData);
                await existingUnit.save();
                existingCount++;
                console.log(`  ✅ Updated common unit: ${unitData.unitName}`);
            } else {
                // Create new common unit
                const commonUnit = new CommonUnit(unitData);
                await commonUnit.save();
                newCount++;
                console.log(`  ➕ Created common unit: ${unitData.unitName}`);
            }
        }

        console.log(`✅ Common units initialization complete!`);
        console.log(`📊 Summary: ${existingCount} existing, ${newCount} new common units`);
        
    } catch (error) {
        console.error('❌ Error initializing common units:', error);
    }
}

// Initialize admin staff with default accounts
async function initializeAdminStaff() {
    try {
        console.log('🔄 Initializing admin staff...');
        
        const existingStaffCount = await AdminStaff.countDocuments();
        if (existingStaffCount > 0) {
            console.log(`✅ Admin staff already initialized (${existingStaffCount} accounts found)`);
            return;
        }
        
        // Default admin staff accounts
        const defaultStaff = [
            {
                role: 'admin',
                staffId: 'ADMIN001',
                name: 'System Administrator',
                email: 'admin@edtti.ac.ke',
                password: 'Admin@2024', // Will be hashed by the model
                department: 'Administration',
                isActive: true,
                isFirstLogin: true,
                mustUpdateEmail: true,
                mustUpdatePassword: true
            },
            {
                role: 'deputy',
                staffId: 'DEPUTY001',
                name: 'Deputy Principal',
                email: 'deputy@edtti.ac.ke',
                password: 'Admin@2024',
                department: 'Administration',
                isActive: true,
                isFirstLogin: true,
                mustUpdateEmail: true,
                mustUpdatePassword: true
            },
            {
                role: 'finance',
                staffId: 'FINANCE001',
                name: 'Finance Officer',
                email: 'finance@edtti.ac.ke',
                password: 'Admin@2024',
                department: 'Finance',
                isActive: true,
                isFirstLogin: true,
                mustUpdateEmail: true,
                mustUpdatePassword: true
            },
            {
                role: 'dean',
                staffId: 'DEAN001',
                name: 'Dean of Students',
                email: 'dean@edtti.ac.ke',
                password: 'Admin@2024',
                department: 'Student Affairs',
                isActive: true,
                isFirstLogin: true,
                mustUpdateEmail: true,
                mustUpdatePassword: true
            },
            {
                role: 'ilo',
                staffId: 'ILO001',
                name: 'Industry Liaison Officer',
                email: 'ilo@edtti.ac.ke',
                password: 'Admin@2024',
                department: 'Industry Liaison',
                isActive: true,
                isFirstLogin: true,
                mustUpdateEmail: true,
                mustUpdatePassword: true
            },
            {
                role: 'registrar',
                staffId: 'REGISTRAR001',
                name: 'Registrar',
                email: 'registrar@edtti.ac.ke',
                password: 'Admin@2024',
                department: 'Registry',
                isActive: true,
                isFirstLogin: true,
                mustUpdateEmail: true,
                mustUpdatePassword: true
            }
        ];
        
        // Create staff accounts
        for (const staffData of defaultStaff) {
            const staff = new AdminStaff(staffData);
            await staff.save();
            console.log(`✅ Created ${AdminStaff.getRoleDisplayName(staffData.role)} account: ${staffData.email}`);
        }
        
        console.log('✅ Admin staff initialization completed!');
        console.log('📧 Default credentials:');
        console.log('   Email: [role]@edtti.ac.ke (e.g., admin@edtti.ac.ke)');
        console.log('   Password: Admin@2024');
        console.log('   ⚠️  Users must update their email and password on first login');
        
    } catch (error) {
        console.error('❌ Error initializing admin staff:', error);
    }
}

// Initialize system settings with default values
async function initializeSystemSettings() {
    try {
        console.log('🔄 Initializing system settings...');
        
        // Default settings
        const defaultSettings = [
            {
                key: 'fee_threshold',
                value: 50000,
                description: 'Minimum fee balance required for unit registration',
                category: 'finance'
            },
            {
                key: 'current_academic_year',
                value: '2024/2025',
                description: 'Current academic year',
                category: 'academic'
            },
            {
                key: 'current_semester',
                value: '1',
                description: 'Current semester (1 or 2)',
                category: 'academic'
            },
            {
                key: 'registration_enabled',
                value: true,
                description: 'Whether unit registration is currently enabled',
                category: 'academic'
            }
        ];

        let existingCount = 0;
        let newCount = 0;

        for (const settingData of defaultSettings) {
            const existingSetting = await SystemSettings.findOne({ key: settingData.key });
            
            if (existingSetting) {
                existingCount++;
                console.log(`  ✓ Setting exists: ${settingData.key} = ${existingSetting.value}`);
            } else {
                await SystemSettings.create(settingData);
                newCount++;
                console.log(`  ➕ Created setting: ${settingData.key} = ${settingData.value}`);
            }
        }

        console.log(`✅ System settings initialization complete!`);
        console.log(`📊 Summary: ${existingCount} existing, ${newCount} new settings`);
        
    } catch (error) {
        console.error('❌ Error initializing system settings:', error);
    }
}

// Load environment variables
require('dotenv').config();

// Email Configuration
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_APP_PASSWORD
    },
    debug: true, // Enable debug logs
    logger: true, // Enable logging
    pool: true, // Use pooled connections
    maxConnections: 5, // Maximum number of simultaneous connections
    rateDelta: 1000, // How many messages to send in rateDelta time
    rateLimit: 5 // How many messages in rateDelta time
});

// Verify email configuration
transporter.verify((error, success) => {
    if (error) {
        console.error('Email configuration error:', error);
        if (error.code === 'EAUTH') {
            console.error('Please check your EMAIL_USER and EMAIL_APP_PASSWORD in .env file');
            console.error('Make sure to use an App Password from your Google Account settings');
        }
    } else {
        console.log('Email server is ready to send messages');
    }
});

// Tool Request Schema
const toolRequestSchema = new mongoose.Schema({
    toolType: { type: String, required: true },
    course: { type: String, required: true },
    dueDate: { type: Date, required: true },
    instructions: String,
    status: { type: String, default: 'pending' },
    createdAt: { type: Date, default: Date.now }
});

const ToolRequest = mongoose.models.ToolRequest || mongoose.model('ToolRequest', toolRequestSchema);

// Program Schema
const programSchema = new mongoose.Schema({
    programName: { 
        type: String, 
        required: [true, 'Program name is required'],
        trim: true,
        unique: true
    },
    programCost: { 
        type: Number, 
        required: [true, 'Program cost is required'],
        min: [0, 'Program cost cannot be negative']
    },
    department: {
        type: String,
        required: [true, 'Department is required'],
        enum: ['applied_science', 'agriculture', 'building_civil', 'electromechanical', 'hospitality', 'business_liberal', 'computing_informatics']
    },
    createdAt: { 
        type: Date, 
        default: Date.now 
    },
    updatedAt: { 
        type: Date, 
        default: Date.now 
    }
});

programSchema.pre('save', function(next) {
    this.updatedAt = new Date();
    next();
});

const Program = mongoose.models.Program || mongoose.model('Program', programSchema);

// Payment Schema
const paymentSchema = new mongoose.Schema({
    studentId: { 
        type: String, 
        required: [true, 'Student ID is required'],
        trim: true
    },
    amount: { 
        type: Number, 
        required: [true, 'Payment amount is required'],
        min: [1, 'Payment amount must be positive']
    },
    paymentMode: {
        type: String,
        required: [true, 'Payment mode is required'],
        enum: ['mpesa', 'bank', 'bursary']
    },
    bankName: {
        type: String,
        required: function() { return this.paymentMode === 'bank'; }
    },
    receiptNumber: {
        type: String,
        required: function() { return this.paymentMode === 'bank'; }
    },
    mpesaTransactionId: {
        type: String,
        required: function() { return this.paymentMode === 'mpesa'; }
    },
    bursaryReference: {
        type: String,
        required: function() { return this.paymentMode === 'bursary'; }
    },
    reference: {
        type: String,
        required: true
    },
    paymentDate: { 
        type: Date, 
        default: Date.now 
    },
    createdAt: { 
        type: Date, 
        default: Date.now 
    }
});

const Payment = mongoose.models.Payment || mongoose.model('Payment', paymentSchema);





// Tool Request Routes

// Get all tool requests
app.get('/api/tool-requests', async (req, res) => {
    try {
        const requests = await ToolRequest.find().sort({ createdAt: -1 });
        res.json(requests);
    } catch (error) {
        console.error('Error fetching tool requests:', error);
        res.status(500).json({ message: 'Failed to fetch tool requests' });
    }
});

// Get tool requests for a specific trainer
app.get('/api/tool-requests/trainer/:email', async (req, res) => {
    try {
        const requests = await ToolRequest.find({
            $or: [
                { trainer: req.params.email },
                { trainer: 'all_trainers' }
            ]
        }).sort({ createdAt: -1 });
        res.json(requests);
    } catch (error) {
        console.error('Error fetching trainer requests:', error);
        res.status(500).json({ message: 'Failed to fetch trainer requests' });
    }
});

// Submit a new tool request
app.post('/api/tool-requests', async (req, res) => {
    try {
        const { toolType, course, trainer, dueDate, instructions } = req.body;

        if (!toolType || !course || !trainer || !dueDate) {
            return res.status(400).json({
                message: 'Missing required fields: toolType, course, trainer, and dueDate are required'
            });
        }

        const newRequest = new ToolRequest({
            toolType,
            course,
            trainer,
            dueDate,
            instructions
        });

        await newRequest.save();

        try {
            // Map trainers based on course
            let emailList = [];
            if (trainer === 'all_trainers') {
                // Course-specific trainer email mappings
                // Each course can have multiple trainers assigned
                // The system will notify all trainers associated with the course
                switch(course) {
                    case 'software_engineering':
                    case 'computer science':
                        emailList.push(
                            'maxxymaxxy04@gmail.com',
                            'software.lead@example.com',
                            'cs.coordinator@example.com'
                        );
                        break;
                    case 'data_science':
                        emailList.push(
                            'gatewaytimer@gmail.com',
                            'data.analytics@example.com',
                            'ml.specialist@example.com'
                        );
                        break;
                    case 'cybersecurity':
                        emailList.push(
                            'severinawanjiku2022@gmail.com',
                            'network.security@example.com',
                            'security.analyst@example.com'
                        );
                        break;
                    case 'artificial_intelligence':
                        emailList.push(
                            'ai.director@example.com',
                            'ml.research@example.com',
                            'ai.applications@example.com'
                        );
                        break;
                    default:
                        console.warn('No specific trainers mapped for course:', course);
                }
            } else {
                emailList.push(trainer);
            }

            if (emailList.length === 0) {
                console.warn('No trainers found for the course:', course);
                emailList.push(process.env.EMAIL_USER); // Fallback to admin email
            }

            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: emailList.join(','),
                subject: `New Tool Request: ${toolType}`,
                html: `
                    <h2>New Tool Request</h2>
                    <p>Dear Trainer,</p>
                    <p>I trust this email finds you well. A new tool request has been submitted with the following details:</p>
                    <p><strong>Tool Type:</strong> ${toolType}</p>
                    <p><strong>Course:</strong> ${course}</p>
                    <p><strong>Due Date:</strong> ${new Date(dueDate).toLocaleDateString()}</p>
                    ${instructions ? `<p><strong>Special Instructions:</strong> ${instructions}</p>` : ''}
                    <p>Please log in to the Staff Portal to view and process this request at your earliest convenience.</p>
                    <p>Best regards,</p>
                    <p><strong>Dr. James Kiprop</strong><br>
                    Deputy Principal (Academics)<br>
                    EMURUA DIKIRR TTI<br>
                    <em>Excellence in Technical Education</em></p>
                `,
                // Enable delivery status notifications
                dsn: {
                    id: newRequest._id.toString(),
                    return: 'headers',
                    notify: ['success', 'failure', 'delay'],
                    recipient: process.env.EMAIL_USER
                }
            };

            const info = await transporter.sendMail(mailOptions);
            console.log('Email notification details:');
            console.log('Message ID:', info.messageId);
            console.log('Accepted recipients:', info.accepted);
            console.log('Rejected recipients:', info.rejected);
            console.log('Pending recipients:', info.pending);
            console.log('Response:', info.response);
            
            if (info.accepted.length > 0) {
                console.log('Email notification sent successfully to:', info.accepted.join(', '));
            }
            if (info.rejected.length > 0) {
                console.error('Failed to send to some recipients:', info.rejected.join(', '));
            }
        } catch (emailError) {
            console.error('Failed to send email notification:');
            console.error('Error code:', emailError.code);
            console.error('Error message:', emailError.message);
            if (emailError.response) {
                console.error('SMTP response:', emailError.response);
            }
            if (Array.isArray(emailError.rejected)) {
                console.error('Rejected recipients:', emailError.rejected.join(', '));
            }
        }

        res.status(201).json({
            message: 'Tool request submitted successfully',
            request: newRequest
        });
    } catch (error) {
        console.error('Error submitting tool request:', error);
        res.status(500).json({
            message: 'Failed to submit tool request',
            error: error.message
        });
    }
});

// Student Routes

// Registration Endpoint
app.post('/api/students/register', async (req, res) => {
    try {
        const { name, idNumber, kcseGrade, admissionNumber, course, department, phoneNumber, year, intake, intakeYear, admissionType } = req.body;

        const normalizedPhone = phoneNumber.replace(/\D/g, '');

        if (!/^(?:254|\+254|0)?([17](?:(?:[0-9][0-9])|(?:0[0-8])|(4[0-1]))[0-9]{6})$/.test(normalizedPhone)) {
            return res.status(400).json({
                message: 'Invalid phone number format. Please enter a valid Kenyan phone number'
            });
        }

        const formattedPhone = normalizedPhone.length === 12 ? '0' + normalizedPhone.slice(-9) : 
                              normalizedPhone.length === 13 ? '0' + normalizedPhone.slice(-9) : 
                              normalizedPhone;

        const existingIdNumber = await Student.findOne({ idNumber });
        const existingPhone = await Student.findOne({ phoneNumber: formattedPhone });
        const existingAdmission = await Student.findOne({ admissionNumber });

        if (existingIdNumber) {
            return res.status(400).json({
                message: 'A student with this ID number already exists'
            });
        }
        if (existingPhone) {
            return res.status(400).json({
                message: 'A student with this phone number already exists'
            });
        }
        if (existingAdmission) {
            return res.status(400).json({
                message: 'A student with this admission number already exists'
            });
        }

        const student = new Student({
            name,
            idNumber,
            kcseGrade,
            admissionNumber,
            course,
            department,
            year: year || 1,
            intake: intake || 'september',
            intakeYear: intakeYear || new Date().getFullYear(),
            phoneNumber: formattedPhone,
            admissionType: admissionType || 'walk-in',  // Default to walk-in if not provided
            password: formattedPhone,  // Let the pre-save hook hash this
            role: 'student'
        });

        await student.save();

        // Prepare admission letter data
        const admissionLetterData = {
            name: student.name,
            admissionNumber: student.admissionNumber,
            course: student.course,
            department: student.department,
            intakeYear: student.intakeYear,
            phoneNumber: student.phoneNumber,
            intake: student.intake
        };

        res.status(201).json({
            message: 'Student registered successfully',
            student: {
                name: student.name,
                admissionNumber: student.admissionNumber,
                course: student.course
            },
            admissionLetter: admissionLetterData,
            showAdmissionLetter: true
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Error registering student' });
    }
});

// Generate intake code based on intake and year
function generateIntakeCode(intake, intakeYear) {
    const yearSuffix = intakeYear.toString().slice(-2); // Get last 2 digits of year
    const intakePrefix = intake === 'january' ? 'J' : 'S';
    return `${intakePrefix}${yearSuffix}`;
}

// Units API Routes

// Get units by course code (for student portal)
app.get('/api/units/course/:courseCode', async (req, res) => {
    try {
        const { courseCode } = req.params;
        const { studentId } = req.query; // Optional parameter for registration status
        
        // Validate course code
        if (!courseCode || courseCode.trim() === '') {
            return res.status(400).json({ message: 'Course code is required' });
        }

        // Find department units for the course
        const departmentUnits = await Unit.getUnitsByCourse(courseCode.toLowerCase());
        
        // Get all common units
        const commonUnits = await CommonUnit.getActiveUnits();
        
        // Get current academic settings
        const currentAcademicYear = await SystemSettings.getSetting('current_academic_year', '2024/2025');
        const currentSemester = await SystemSettings.getSetting('current_semester', '1');
        
        // Get student's registrations if studentId is provided
        let studentRegistrations = [];
        if (studentId) {
            studentRegistrations = await StudentUnitRegistration.find({
                studentId: studentId,
                academicYear: currentAcademicYear,
                semester: currentSemester,
                status: 'registered',
                isActive: true
            });
        }
        
        // Create a map for quick lookup of registered units
        const registrationMap = new Map();
        studentRegistrations.forEach(reg => {
            registrationMap.set(reg.unitCode, reg);
        });
        
        // Format common units to match the department units structure
        const formattedCommonUnits = commonUnits.map(unit => ({
            _id: unit._id,
            unitName: unit.unitName,
            unitCode: unit.unitCode,
            courseCode: unit.courseCode,
            department: 'common',
            level: unit.level,
            description: unit.description,
            isActive: unit.isActive,
            type: 'common',
            isRegistered: registrationMap.has(unit.unitCode),
            registrationId: registrationMap.get(unit.unitCode)?._id || null
        }));
        
        // Format department units
        const formattedDepartmentUnits = departmentUnits.map(unit => ({
            ...unit.toObject(),
            type: 'department',
            isRegistered: registrationMap.has(unit.unitCode),
            registrationId: registrationMap.get(unit.unitCode)?._id || null
        }));
        
        // Combine both types of units
        const allUnits = [...formattedDepartmentUnits, ...formattedCommonUnits];
        
        if (allUnits.length === 0) {
            return res.status(404).json({ message: 'No units found for this course' });
        }

        // Count registered units
        const registeredUnits = allUnits.filter(unit => unit.isRegistered).length;

        res.json({
            success: true,
            courseCode: courseCode,
            totalUnits: allUnits.length,
            departmentUnits: formattedDepartmentUnits.length,
            commonUnits: formattedCommonUnits.length,
            registeredUnits: registeredUnits,
            academicYear: currentAcademicYear,
            semester: currentSemester,
            units: allUnits
        });
    } catch (error) {
        console.error('Error fetching units by course:', error);
        res.status(500).json({ message: 'Server error while fetching units' });
    }
});

// Get units by department (for admin use)
app.get('/api/units/department/:department', async (req, res) => {
    try {
        const { department } = req.params;
        
        // Validate department
        const validDepartments = ['applied_science', 'agriculture', 'building_civil', 'electromechanical', 'hospitality', 'business_liberal', 'computing_informatics', 'business_administration'];
        if (!validDepartments.includes(department)) {
            return res.status(400).json({ message: 'Invalid department' });
        }

        const units = await Unit.getUnitsByDepartment(department);
        
        res.json({
            success: true,
            department: department,
            totalUnits: units.length,
            units: units
        });
    } catch (error) {
        console.error('Error fetching units by department:', error);
        res.status(500).json({ message: 'Server error while fetching units' });
    }
});

// Get all units (for admin use with pagination)
app.get('/api/units', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 50;
        const skip = (page - 1) * limit;

        const units = await Unit.find({ isActive: true })
            .sort({ courseCode: 1, unitCode: 1 })
            .skip(skip)
            .limit(limit);

        const total = await Unit.countDocuments({ isActive: true });

        res.json({
            success: true,
            units: units,
            pagination: {
                currentPage: page,
                totalPages: Math.ceil(total / limit),
                totalUnits: total,
                hasNext: page < Math.ceil(total / limit),
                hasPrev: page > 1
            }
        });
    } catch (error) {
        console.error('Error fetching all units:', error);
        res.status(500).json({ message: 'Server error while fetching units' });
    }
});

// Get all courses
app.get('/api/courses', async (req, res) => {
    try {
        const { courseUnits } = require('./src/data/courseUnits');
        const courses = Object.keys(courseUnits).map(courseCode => ({
            code: courseCode,
            name: formatCourseNameServer(courseCode),
            department: courseUnits[courseCode].department,
            level: courseUnits[courseCode].level
        }));
        res.json(courses);
    } catch (error) {
        console.error('Error fetching courses:', error);
        res.status(500).json({ message: 'Error fetching courses' });
    }
});

// Common Units API Routes

// Get all common units
app.get('/api/common-units', async (req, res) => {
    try {
        const commonUnits = await CommonUnit.getActiveUnits();
        res.json({ 
            success: true, 
            commonUnits: commonUnits,
            total: commonUnits.length 
        });
    } catch (error) {
        console.error('Error fetching common units:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error while fetching common units' 
        });
    }
});

// Get common unit by code
app.get('/api/common-units/:unitCode', async (req, res) => {
    try {
        const { unitCode } = req.params;
        const commonUnit = await CommonUnit.findByCode(unitCode);
        
        if (!commonUnit) {
            return res.status(404).json({ 
                success: false, 
                message: 'Common unit not found' 
            });
        }
        
        res.json({ 
            success: true, 
            commonUnit: commonUnit 
        });
    } catch (error) {
        console.error('Error fetching common unit:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error while fetching common unit' 
        });
    }
});

// Create new common unit (admin only)
app.post('/api/common-units', async (req, res) => {
    try {
        const commonUnitData = req.body;
        
        // Check if unit code already exists
        const existingUnit = await CommonUnit.findOne({ 
            unitCode: commonUnitData.unitCode.toUpperCase() 
        });
        
        if (existingUnit) {
            return res.status(400).json({ 
                success: false, 
                message: 'Common unit with this code already exists' 
            });
        }
        
        const commonUnit = new CommonUnit(commonUnitData);
        await commonUnit.save();
        
        res.status(201).json({ 
            success: true, 
            commonUnit: commonUnit,
            message: 'Common unit created successfully' 
        });
    } catch (error) {
        console.error('Error creating common unit:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error while creating common unit' 
        });
    }
});

// Update common unit (admin only)
app.put('/api/common-units/:unitCode', async (req, res) => {
    try {
        const { unitCode } = req.params;
        const updateData = req.body;
        
        const commonUnit = await CommonUnit.findOneAndUpdate(
            { unitCode: unitCode.toUpperCase(), isActive: true },
            updateData,
            { new: true, runValidators: true }
        );
        
        if (!commonUnit) {
            return res.status(404).json({ 
                success: false, 
                message: 'Common unit not found' 
            });
        }
        
        res.json({ 
            success: true, 
            commonUnit: commonUnit,
            message: 'Common unit updated successfully' 
        });
    } catch (error) {
        console.error('Error updating common unit:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error while updating common unit' 
        });
    }
});

// Delete common unit (admin only)
app.delete('/api/common-units/:unitCode', async (req, res) => {
    try {
        const { unitCode } = req.params;
        
        const commonUnit = await CommonUnit.findOneAndUpdate(
            { unitCode: unitCode.toUpperCase() },
            { isActive: false },
            { new: true }
        );
        
        if (!commonUnit) {
            return res.status(404).json({ 
                success: false, 
                message: 'Common unit not found' 
            });
        }
        
        res.json({ 
            success: true, 
            message: 'Common unit deactivated successfully' 
        });
    } catch (error) {
        console.error('Error deactivating common unit:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error while deactivating common unit' 
        });
    }
});

// Common Unit Assignment API Routes

// Get all common unit assignments
app.get('/api/common-unit-assignments', async (req, res) => {
    try {
        const { status = 'active', department, trainerId, commonUnitId } = req.query;
        
        let query = { status };
        if (department) query.assignedByDepartment = department;
        if (trainerId) query.trainerId = trainerId;
        if (commonUnitId) query.commonUnitId = commonUnitId;
        
        const assignments = await CommonUnitAssignment.find(query)
            .populate('commonUnitId')
            .populate('trainerId', 'name email department')
            .populate('assignedBy', 'name department')
            .sort({ assignedAt: -1 });
        
        res.json({ 
            success: true, 
            assignments: assignments,
            total: assignments.length 
        });
    } catch (error) {
        console.error('Error fetching common unit assignments:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error while fetching common unit assignments' 
        });
    }
});

// Get common unit assignments by trainer
app.get('/api/common-unit-assignments/trainer/:trainerId', async (req, res) => {
    try {
        const { trainerId } = req.params;
        const { status = 'active' } = req.query;
        
        const assignments = await CommonUnitAssignment.getAssignmentsByTrainer(trainerId, status);
        
        res.json({ 
            success: true, 
            assignments: assignments,
            total: assignments.length 
        });
    } catch (error) {
        console.error('Error fetching trainer common unit assignments:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error while fetching trainer assignments' 
        });
    }
});

// Get common unit assignments by department
app.get('/api/common-unit-assignments/department/:department', async (req, res) => {
    try {
        const { department } = req.params;
        const { status = 'active' } = req.query;
        
        const assignments = await CommonUnitAssignment.getAssignmentsByDepartment(department, status);
        
        res.json({ 
            success: true, 
            assignments: assignments,
            total: assignments.length 
        });
    } catch (error) {
        console.error('Error fetching department common unit assignments:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error while fetching department assignments' 
        });
    }
});

// Create new common unit assignment
app.post('/api/common-unit-assignments', async (req, res) => {
    try {
        const { commonUnitId, trainerId, assignedBy, assignedByDepartment, trainerDepartment, notes } = req.body;
        
        console.log('📝 Common unit assignment request body:', req.body);
        console.log('🔍 Field validation:');
        console.log('  commonUnitId:', commonUnitId ? '✅' : '❌');
        console.log('  trainerId:', trainerId ? '✅' : '❌');
        console.log('  assignedBy:', assignedBy ? '✅' : '❌');
        console.log('  assignedByDepartment:', assignedByDepartment ? '✅' : '❌');
        console.log('  trainerDepartment:', trainerDepartment ? '✅' : '❌');
        
        // Validate required fields
        if (!commonUnitId || !trainerId || !assignedBy || !assignedByDepartment || !trainerDepartment) {
            console.log('❌ Validation failed - missing required fields');
            return res.status(400).json({ 
                success: false, 
                message: 'Missing required fields' 
            });
        }
        
        // Check if assignment already exists
        const existingAssignment = await CommonUnitAssignment.findOne({
            commonUnitId,
            trainerId,
            status: 'active'
        });
        
        if (existingAssignment) {
            return res.status(400).json({ 
                success: false, 
                message: 'This common unit is already assigned to this trainer' 
            });
        }
        
        // Verify common unit exists
        const commonUnit = await CommonUnit.findById(commonUnitId);
        if (!commonUnit) {
            return res.status(404).json({ 
                success: false, 
                message: 'Common unit not found' 
            });
        }
        
        // Verify trainer exists
        const trainer = await Trainer.findById(trainerId);
        if (!trainer) {
            return res.status(404).json({ 
                success: false, 
                message: 'Trainer not found' 
            });
        }
        
        // Create assignment
        const assignment = new CommonUnitAssignment({
            commonUnitId,
            trainerId,
            assignedBy,
            assignedByDepartment,
            trainerDepartment,
            notes
        });
        
        await assignment.save();
        
        // Populate the assignment for response
        await assignment.populate('commonUnitId');
        await assignment.populate('trainerId', 'name email department');
        await assignment.populate('assignedBy', 'name department');
        
        res.status(201).json({ 
            success: true, 
            assignment: assignment,
            message: 'Common unit assignment created successfully' 
        });
    } catch (error) {
        console.error('Error creating common unit assignment:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error while creating assignment' 
        });
    }
});

// Update common unit assignment
app.put('/api/common-unit-assignments/:assignmentId', async (req, res) => {
    try {
        const { assignmentId } = req.params;
        const updateData = req.body;
        
        const assignment = await CommonUnitAssignment.findById(assignmentId);
        if (!assignment) {
            return res.status(404).json({ 
                success: false, 
                message: 'Assignment not found' 
            });
        }
        
        if (!assignment.canModify()) {
            return res.status(400).json({ 
                success: false, 
                message: 'This assignment cannot be modified' 
            });
        }
        
        Object.assign(assignment, updateData);
        await assignment.save();
        
        await assignment.populate('commonUnitId');
        await assignment.populate('trainerId', 'name email department');
        await assignment.populate('assignedBy', 'name department');
        
        res.json({ 
            success: true, 
            assignment: assignment,
            message: 'Assignment updated successfully' 
        });
    } catch (error) {
        console.error('Error updating common unit assignment:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error while updating assignment' 
        });
    }
});

// Delete/deactivate common unit assignment
app.delete('/api/common-unit-assignments/:assignmentId', async (req, res) => {
    try {
        const { assignmentId } = req.params;
        
        const assignment = await CommonUnitAssignment.findByIdAndUpdate(
            assignmentId,
            { status: 'inactive' },
            { new: true }
        );
        
        if (!assignment) {
            return res.status(404).json({ 
                success: false, 
                message: 'Assignment not found' 
            });
        }
        
        res.json({ 
            success: true, 
            message: 'Assignment deactivated successfully' 
        });
    } catch (error) {
        console.error('Error deactivating common unit assignment:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error while deactivating assignment' 
        });
    }
});

// Get trainers from all departments for common unit assignment
app.get('/api/trainers/all-departments', async (req, res) => {
    try {
        const trainers = await Trainer.find({ isActive: true })
            .select('name email department specialization')
            .sort({ department: 1, name: 1 });
        
        // Group trainers by department
        const trainersByDepartment = trainers.reduce((acc, trainer) => {
            if (!acc[trainer.department]) {
                acc[trainer.department] = [];
            }
            acc[trainer.department].push(trainer);
            return acc;
        }, {});
        
        res.json({ 
            success: true, 
            trainers: trainers,
            trainersByDepartment: trainersByDepartment,
            departments: Object.keys(trainersByDepartment).sort()
        });
    } catch (error) {
        console.error('Error fetching trainers from all departments:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error while fetching trainers' 
        });
    }
});

// HOD & Trainer Management API Routes

// HOD Authentication
app.post('/api/hod/login', async (req, res) => {
    try {
        const { department, password } = req.body;

        if (!department || !password) {
            return res.status(400).json({ message: 'Department and password are required' });
        }

        const hod = await HOD.findOne({ department: department, isActive: true });
        if (!hod) {
            return res.status(401).json({ message: 'Invalid department or HOD not found' });
        }

        const isValidPassword = await hod.comparePassword(password);
        if (!isValidPassword) {
            return res.status(401).json({ message: 'Invalid password' });
        }

        // Update last login
        await hod.updateLastLogin();

        const response = {
            message: 'Login successful',
            _id: hod._id,
            department: hod.department,
            departmentName: HOD.getDepartmentDisplayName(hod.department),
            name: hod.name,
            email: hod.email,
            phone: hod.phone,
            lastLogin: hod.lastLogin
        };
        
        console.log('🔐 HOD Login Response:', response);
        res.json(response);
    } catch (error) {
        console.error('Error during HOD login:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Update HOD profile (email and phone)
app.put('/api/hod/:hodId/profile', async (req, res) => {
    try {
        const { hodId } = req.params;
        const { email, phone } = req.body;

        // Validate HOD ID format
        if (!hodId || !hodId.match(/^[0-9a-fA-F]{24}$/)) {
            return res.status(400).json({ message: 'Invalid HOD ID format' });
        }

        // Find HOD
        const hod = await HOD.findById(hodId);
        if (!hod) {
            return res.status(404).json({ message: 'HOD not found' });
        }

        // Update fields if provided
        if (email && email !== hod.email) {
            // Validate email format
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                return res.status(400).json({ message: 'Invalid email format' });
            }

            // Check if email is already in use
            const existingHOD = await HOD.findOne({ email: email, _id: { $ne: hodId } });
            if (existingHOD) {
                return res.status(400).json({ message: 'Email address is already in use' });
            }
            hod.email = email;
        }

        if (phone !== undefined) {
            hod.phone = phone || null;
        }

        hod.updatedAt = new Date();
        await hod.save();

        console.log(`✅ Updated profile for HOD: ${hod.name}`);

        res.json({
            message: 'Profile updated successfully',
            hod: {
                _id: hod._id,
                name: hod.name,
                email: hod.email,
                phone: hod.phone,
                department: hod.department,
                departmentName: HOD.getDepartmentDisplayName(hod.department)
            }
        });
    } catch (error) {
        console.error('Error updating HOD profile:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Get departments for HOD login
app.get('/api/hod/departments', async (req, res) => {
    try {
        const departments = HOD.getAllDepartments();
        res.json(departments);
    } catch (error) {
        console.error('Error fetching departments:', error);
        res.status(500).json({ message: 'Failed to fetch departments' });
    }
});

// Get trainers by department
app.get('/api/trainers/department/:department', async (req, res) => {
    try {
        const { department } = req.params;
        console.log(`API: Fetching trainers for department: ${department}`);
        
        // First, let's see what departments actually exist in the database
        const allTrainers = await Trainer.find({}).select('name department');
        console.log(`API: All trainers in database:`, allTrainers.map(t => ({ name: t.name, dept: t.department })));
        
        const trainers = await Trainer.getTrainersByDepartment(department);
        console.log(`API: Found ${trainers.length} trainers for department ${department}:`, trainers.map(t => ({ name: t.name, dept: t.department })));
        res.json(trainers);
    } catch (error) {
        console.error('Error fetching trainers:', error);
        res.status(500).json({ message: 'Failed to fetch trainers' });
    }
});

// Get trainer assignments by department
app.get('/api/assignments/department/:department', async (req, res) => {
    try {
        const { department } = req.params;
        console.log(`Fetching assignments for department: ${department}`);
        
        const assignments = await TrainerAssignment.getAssignmentsByDepartment(department);
        console.log(`Found ${assignments.length} assignments for department ${department}`);
        
        res.json(assignments);
    } catch (error) {
        console.error('Error fetching assignments:', error);
        res.status(500).json({ message: 'Failed to fetch assignments' });
    }
});

// Assign units to trainer
app.post('/api/assignments/assign', async (req, res) => {
    try {
        const { trainerId, unitIds, assignedBy, department } = req.body;

        if (!trainerId || !unitIds || !Array.isArray(unitIds) || unitIds.length === 0) {
            return res.status(400).json({ message: 'Trainer ID and unit IDs are required' });
        }

        const assignments = await TrainerAssignment.assignUnitsToTrainer(
            trainerId, 
            unitIds, 
            assignedBy, 
            department
        );

        res.json({
            message: 'Units assigned successfully',
            assignments: assignments
        });
    } catch (error) {
        console.error('Error assigning units:', error);
        res.status(500).json({ message: 'Failed to assign units' });
    }
});

// Unassign units
app.post('/api/assignments/unassign', async (req, res) => {
    try {
        const { unitIds } = req.body;

        if (!unitIds || !Array.isArray(unitIds) || unitIds.length === 0) {
            return res.status(400).json({ message: 'Unit IDs are required' });
        }

        await TrainerAssignment.unassignUnits(unitIds);

        res.json({
            message: 'Units unassigned successfully'
        });
    } catch (error) {
        console.error('Error unassigning units:', error);
        res.status(500).json({ message: 'Failed to unassign units' });
    }
});

// Trainer Authentication
app.post('/api/trainers/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        const trainer = await Trainer.findOne({ email: email, isActive: true });
        if (!trainer) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        // Compare password (plain text as per requirements)
        const isPasswordValid = await trainer.comparePassword(password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        // Update last login
        await trainer.updateLastLogin();

        // Get assigned units count
        const assignedUnitsCount = await trainer.getAssignedUnitsCount();

        res.json({
            message: 'Login successful',
            trainer: {
                _id: trainer._id,
                name: trainer.name,
                email: trainer.email,
                phone: trainer.phone,
                department: trainer.department,
                specialization: trainer.specialization,
                assignedUnitsCount: assignedUnitsCount,
                lastLogin: trainer.lastLogin
            }
        });
    } catch (error) {
        console.error('Error during trainer login:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Update trainer email
app.put('/api/trainers/:trainerId/email', async (req, res) => {
    try {
        const { trainerId } = req.params;
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ message: 'Email is required' });
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ message: 'Invalid email format' });
        }

        // Check if email already exists
        const existingTrainer = await Trainer.findOne({ email: email.toLowerCase(), _id: { $ne: trainerId } });
        if (existingTrainer) {
            return res.status(400).json({ message: 'Email already exists' });
        }

        // Update trainer email
        const trainer = await Trainer.findByIdAndUpdate(
            trainerId,
            { email: email.toLowerCase(), updatedAt: new Date() },
            { new: true }
        );

        if (!trainer) {
            return res.status(404).json({ message: 'Trainer not found' });
        }

        res.json({
            message: 'Email updated successfully',
            trainer: {
                _id: trainer._id,
                name: trainer.name,
                email: trainer.email,
                phone: trainer.phone,
                department: trainer.department,
                specialization: trainer.specialization
            }
        });
    } catch (error) {
        console.error('Error updating trainer email:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Get trainer assignments - Clean production version
app.get('/api/trainers/:trainerId/assignments', async (req, res) => {
    try {
        const { trainerId } = req.params;
        
        // Validate trainerId format
        if (!trainerId || !trainerId.match(/^[0-9a-fA-F]{24}$/)) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid trainer ID format' 
            });
        }
        
        // Verify trainer exists
        const trainer = await Trainer.findById(trainerId);
        if (!trainer) {
            return res.status(404).json({ 
                success: false, 
                message: 'Trainer not found' 
            });
        }
        
        // Get regular assignments with proper population
        const assignments = await TrainerAssignment.find({
            trainerId: trainerId,
            status: 'active'
        })
        .populate({
            path: 'unitId',
            select: 'unitName unitCode courseCode level department',
            match: { isActive: true }
        })
        .sort({ assignedAt: -1 })
        .lean();
        
        // Get common unit assignments
        const commonUnitAssignments = await CommonUnitAssignment.find({
            trainerId: trainerId,
            status: 'active'
        })
        .populate({
            path: 'commonUnitId',
            select: 'unitName unitCode courseCode level description',
            match: { isActive: true }
        })
        .sort({ assignedAt: -1 })
        .lean();
        
        // Filter out assignments with null/missing unit data
        const validAssignments = assignments.filter(assignment => 
            assignment.unitId && assignment.unitId.unitCode
        );
        
        const validCommonUnitAssignments = commonUnitAssignments.filter(assignment => 
            assignment.commonUnitId && assignment.commonUnitId.unitCode
        );
        
        // Format department unit assignments
        const formattedAssignments = validAssignments.map(assignment => ({
            _id: assignment._id,
            type: 'department',
            unitId: {
                _id: assignment.unitId._id,
                unitName: assignment.unitId.unitName,
                unitCode: assignment.unitId.unitCode,
                courseCode: assignment.unitId.courseCode,
                level: assignment.unitId.level,
                department: assignment.unitId.department
            },
            courseCode: assignment.courseCode,
            unitCode: assignment.unitCode,
            unitName: assignment.unitName,
            department: assignment.department,
            assignedBy: assignment.assignedBy,
            assignedAt: assignment.assignedAt,
            status: assignment.status,
            notes: assignment.notes || '',
            semester: assignment.semester || 'current'
        }));
        
        // Format common unit assignments
        const formattedCommonAssignments = validCommonUnitAssignments.map(assignment => ({
            _id: assignment._id,
            type: 'common',
            unitId: {
                _id: assignment.commonUnitId._id,
                unitName: assignment.commonUnitId.unitName,
                unitCode: assignment.commonUnitId.unitCode,
                courseCode: assignment.commonUnitId.courseCode,
                level: assignment.commonUnitId.level,
                department: 'common'
            },
            courseCode: assignment.commonUnitId.courseCode,
            unitCode: assignment.commonUnitId.unitCode,
            unitName: assignment.commonUnitId.unitName,
            department: 'common',
            assignedBy: assignment.assignedBy,
            assignedAt: assignment.assignedAt,
            status: assignment.status,
            notes: assignment.notes || '',
            assignedByDepartment: assignment.assignedByDepartment,
            trainerDepartment: assignment.trainerDepartment
        }));
        
        // Combine both types of assignments
        const allAssignments = [...formattedAssignments, ...formattedCommonAssignments]
            .sort((a, b) => new Date(b.assignedAt) - new Date(a.assignedAt));
        
        console.log(`✅ Fetched ${formattedAssignments.length} department assignments and ${formattedCommonAssignments.length} common unit assignments for trainer ${trainer.name}`);
        
        res.json({
            success: true,
            count: allAssignments.length,
            departmentAssignments: formattedAssignments.length,
            commonUnitAssignments: formattedCommonAssignments.length,
            assignments: allAssignments
        });
        
    } catch (error) {
        console.error('❌ Error fetching trainer assignments:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Internal server error while fetching assignments',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Update trainer profile
app.put('/api/trainers/:trainerId/profile', async (req, res) => {
    try {
        const { trainerId } = req.params;
        const { email, phone } = req.body;
        
        // Validate trainerId format
        if (!trainerId || !trainerId.match(/^[0-9a-fA-F]{24}$/)) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid trainer ID format' 
            });
        }
        
        // Find trainer
        const trainer = await Trainer.findById(trainerId);
        if (!trainer) {
            return res.status(404).json({ 
                success: false, 
                message: 'Trainer not found' 
            });
        }
        
        // Update fields if provided
        if (email && email !== trainer.email) {
            // Check if email is already in use
            const existingTrainer = await Trainer.findOne({ email: email, _id: { $ne: trainerId } });
            if (existingTrainer) {
                return res.status(400).json({
                    success: false,
                    message: 'Email address is already in use'
                });
            }
            trainer.email = email;
        }
        
        if (phone !== undefined) {
            trainer.phone = phone || null;
        }
        
        await trainer.save();
        
        console.log(`✅ Updated profile for trainer: ${trainer.name}`);
        
        res.json({
            success: true,
            message: 'Profile updated successfully',
            trainer: {
                _id: trainer._id,
                name: trainer.name,
                email: trainer.email,
                phone: trainer.phone,
                department: trainer.department,
                specialization: trainer.specialization
            }
        });
        
    } catch (error) {
        console.error('❌ Error updating trainer profile:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Internal server error while updating profile',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Get students for trainer's assigned units/courses (only enrolled students)
app.get('/api/trainers/:trainerId/students', async (req, res) => {
    try {
        const { trainerId } = req.params;
        
        // Get trainer's assignments (both department and common units)
        const departmentAssignments = await TrainerAssignment.getAssignmentsByTrainer(trainerId);
        const commonAssignments = await CommonUnitAssignment.getAssignmentsByTrainer(trainerId);
        
        if ((!departmentAssignments || departmentAssignments.length === 0) && 
            (!commonAssignments || commonAssignments.length === 0)) {
            return res.json({ students: [], courseStats: {} });
        }
        
        // Get unit codes from all assignments
        const departmentUnitCodes = departmentAssignments.map(assignment => {
            return assignment.unitId?.unitCode || assignment.courseCode;
        }).filter(Boolean);
        
        const commonUnitCodes = commonAssignments.map(assignment => {
            return assignment.commonUnitId?.unitCode;
        }).filter(Boolean);
        
        const allUnitCodes = [...departmentUnitCodes, ...commonUnitCodes];
        
        console.log(`🔍 Trainer ${trainerId} has ${departmentAssignments.length} department assignments and ${commonAssignments.length} common assignments`);
        console.log(`🎯 Unit codes for registered student search:`, allUnitCodes);
        
        if (allUnitCodes.length === 0) {
            return res.json({ students: [], courseStats: {} });
        }
        
        // Get current academic settings
        const currentAcademicYear = await SystemSettings.getSetting('current_academic_year', '2024/2025');
        const currentSemester = await SystemSettings.getSetting('current_semester', '1');
        
        // Find students who are registered for these units
        const studentRegistrations = await StudentUnitRegistration.find({
            unitCode: { $in: allUnitCodes },
            academicYear: currentAcademicYear,
            semester: currentSemester,
            status: 'registered',
            isActive: true
        }).populate('unitId').populate('commonUnitId');
        
        console.log(`🔍 Searching for registrations with criteria:`, {
            unitCodes: allUnitCodes,
            academicYear: currentAcademicYear,
            semester: currentSemester,
            status: 'registered',
            isActive: true
        });
        
        console.log(`📋 Found ${studentRegistrations.length} student registrations:`, 
            studentRegistrations.map(reg => ({
                studentId: reg.studentId,
                unitCode: reg.unitCode,
                unitName: reg.unitName,
                academicYear: reg.academicYear,
                semester: reg.semester,
                status: reg.status
            }))
        );
        
        // Get unique student IDs
        const enrolledStudentIds = [...new Set(studentRegistrations.map(reg => reg.studentId))];
        
        console.log(`📋 Found ${studentRegistrations.length} registrations for ${enrolledStudentIds.length} unique students`);
        
        if (enrolledStudentIds.length === 0) {
            return res.json({ students: [], courseStats: {} });
        }
        
        // Fetch student details for enrolled students only
        const students = await Student.find({
            admissionNumber: { $in: enrolledStudentIds }
        }).select('name admissionNumber course intake year email phone totalPaid balance');
        
        console.log(`Found ${students.length} enrolled students for trainer ${trainerId}:`, students.map(s => ({ name: s.name, course: s.course })));
        
        // Group students by course and calculate stats
        const courseStats = {};
        const studentsByCourse = {};
        
        // Get unique course codes from enrolled students
        const courseCodes = [...new Set(students.map(s => s.course))];
        
        courseCodes.forEach(courseCode => {
            const courseStudents = students.filter(student => student.course === courseCode);
            studentsByCourse[courseCode] = courseStudents;
            
            // Count units assigned to this trainer for this course
            const courseUnitCodes = studentRegistrations
                .filter(reg => {
                    const student = students.find(s => s.admissionNumber === reg.studentId);
                    return student && student.course === courseCode;
                })
                .map(reg => reg.unitCode);
            
            const uniqueUnitsForCourse = [...new Set(courseUnitCodes)];
            
            courseStats[courseCode] = {
                totalStudents: courseStudents.length,
                courseName: formatCourseNameServer(courseCode),
                unitsAssigned: uniqueUnitsForCourse.length
            };
        });
        
        res.json({
            students: studentsByCourse,
            courseStats: courseStats,
            totalStudents: students.length,
            totalCourses: courseCodes.length,
            academicYear: currentAcademicYear,
            semester: currentSemester
        });
        
    } catch (error) {
        console.error('Error fetching trainer students:', error);
        res.status(500).json({ message: 'Failed to fetch trainer students' });
    }
});

// Diagnostic: Get units without trainer assignments
app.get('/api/diagnostics/unassigned-units', async (req, res) => {
    try {
        // Get all active units
        const allUnits = await Unit.find({ isActive: true }).select('unitCode unitName courseCode department');
        
        // Get all trainer assignments
        const assignments = await TrainerAssignment.find({ status: 'active' }).select('unitId');
        const assignedUnitIds = assignments.map(a => a.unitId.toString());
        
        // Find units without assignments
        const unassignedUnits = allUnits.filter(unit => 
            !assignedUnitIds.includes(unit._id.toString())
        );
        
        console.log(`📊 Diagnostic: ${unassignedUnits.length} units without trainer assignments:`, 
            unassignedUnits.map(u => ({ unitCode: u.unitCode, unitName: u.unitName }))
        );
        
        res.json({
            totalUnits: allUnits.length,
            assignedUnits: assignedUnitIds.length,
            unassignedUnits: unassignedUnits.length,
            unassignedUnitsList: unassignedUnits.map(unit => ({
                unitId: unit._id,
                unitCode: unit.unitCode,
                unitName: unit.unitName,
                courseCode: unit.courseCode,
                department: unit.department
            }))
        });
        
    } catch (error) {
        console.error('Error in diagnostics:', error);
        res.status(500).json({ message: 'Diagnostic failed' });
    }
});

// Get students by department (for HOD)
app.get('/api/students/department/:department', async (req, res) => {
    try {
        const { department } = req.params;
        
        // Get all units for this department
        const units = await Unit.find({ department: department });
        const courseCodes = [...new Set(units.map(unit => unit.courseCode))];
        
        console.log(`Department: ${department}, Found ${units.length} units, Course codes:`, courseCodes);
        
        // First, let's see what courses students actually have
        const allStudents = await Student.find({}).select('course').distinct('course');
        console.log(`All student courses in database:`, allStudents);
        
        // Fetch students enrolled in courses from this department
        const students = await Student.find({
            course: { $in: courseCodes }
        }).select('name admissionNumber course intake year email phone totalPaid balance');
        
        console.log(`Found ${students.length} students for department ${department}:`, students.map(s => ({ name: s.name, course: s.course })));
        
        // If no exact matches, try partial matching
        if (students.length === 0) {
            console.log(`No exact matches found. Trying partial matching for department ${department}...`);
            const partialStudents = await Student.find({
                course: { $regex: new RegExp(courseCodes.map(code => code.replace(/_/g, '.*')).join('|'), 'i') }
            }).select('name admissionNumber course intake year email phone totalPaid balance');
            console.log(`Found ${partialStudents.length} students with partial matching:`, partialStudents.map(s => ({ name: s.name, course: s.course })));
        }
        
        // Group students by course
        const studentsByCourse = {};
        const courseStats = {};
        
        courseCodes.forEach(courseCode => {
            const courseStudents = students.filter(student => student.course === courseCode);
            studentsByCourse[courseCode] = courseStudents;
            courseStats[courseCode] = {
                totalStudents: courseStudents.length,
                courseName: formatCourseNameServer(courseCode)
            };
        });
        
        res.json({
            students: studentsByCourse,
            courseStats: courseStats,
            totalStudents: students.length,
            totalCourses: courseCodes.length
        });
        
    } catch (error) {
        console.error('Error fetching department students:', error);
        res.status(500).json({ message: 'Failed to fetch department students' });
    }
});

// Students API Routes

// Get Student Data by Admission Number
app.get('/api/students/admission/:admissionNumber', async (req, res) => {
    try {
        const { admissionNumber } = req.params;
        console.log('Fetching student data for admission number:', admissionNumber);
        
        const student = await Student.findOne({ admissionNumber }).select('-password');
        
        if (!student) {
            return res.status(404).json({ message: 'Student not found' });
        }
        
        console.log('Found student:', student.name);
        res.json(student);
        
    } catch (error) {
        console.error('Error fetching student data:', error);
        res.status(500).json({ message: 'Error fetching student data' });
    }
});

// Get Latest Admission Number Endpoint with Intake Support
app.get('/api/students/latest-admission/:courseCode/:intake/:intakeYear', async (req, res) => {
    try {
        const { courseCode, intake, intakeYear } = req.params;
        
        // Generate intake code for this specific intake
        const intakeCode = generateIntakeCode(intake, parseInt(intakeYear));
        
        // Find latest admission number for this course and intake combination
        const latestStudent = await Student.findOne({
            admissionNumber: { $regex: `^${courseCode}/\\d{4}/${intakeCode}$` }
        }).sort({ admissionNumber: -1 });

        if (latestStudent) {
            res.json({ 
                latestNumber: latestStudent.admissionNumber,
                intakeCode: intakeCode 
            });
        } else {
            res.json({ 
                latestNumber: null,
                intakeCode: intakeCode 
            });
        }
    } catch (error) {
        console.error('Error fetching latest admission number:', error);
        res.status(500).json({ message: 'Error fetching latest admission number' });
    }
});

// Legacy endpoint for backward compatibility
app.get('/api/students/latest-admission/:courseCode', async (req, res) => {
    try {
        const { courseCode } = req.params;
        
        // Default to current September intake
        const currentYear = new Date().getFullYear();
        const defaultIntake = 'september';
        const intakeCode = generateIntakeCode(defaultIntake, currentYear);
        
        const latestStudent = await Student.findOne({
            admissionNumber: { $regex: `^${courseCode}/\\d{4}/${intakeCode}$` }
        }).sort({ admissionNumber: -1 });

        if (latestStudent) {
        res.json({
                latestNumber: latestStudent.admissionNumber,
                intakeCode: intakeCode 
            });
        } else {
            res.json({ 
                latestNumber: null,
                intakeCode: intakeCode 
            });
        }
    } catch (error) {
        console.error('Error fetching latest admission number:', error);
        res.status(500).json({ message: 'Error fetching latest admission number' });
    }
});

// Get All Students Endpoint
app.get('/api/students', async (req, res) => {
    try {
        const students = await Student.find({}, { password: 0 });
        res.json(students);
    } catch (error) {
        console.error('Error fetching students:', error);
        res.status(500).json({ message: 'Error fetching students' });
    }
});

// Update student
app.patch('/api/students/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const updates = req.body;
        
        // Handle year promotion with balance update
        if (updates.year !== undefined) {
            // Get the current student to check if year is actually changing (promotion)
            const currentStudent = await Student.findById(id);
            
            if (currentStudent) {
                console.log(`🔄 Checking promotion: Current Year=${currentStudent.year}, New Year=${updates.year}, Course=${currentStudent.course}`);
                
                if (currentStudent.year !== updates.year) {
                    // Student is being promoted to a new year
                    console.log(`📚 Student ${currentStudent.admissionNumber} is being promoted from Year ${currentStudent.year} to Year ${updates.year}`);
                    
                    // Map course code to program name
                    const courseToProgram = {
                        'applied_biology_6': 'Applied Biology Level 6',
                        'analytical_chemistry_6': 'Analytical Chemistry Level 6',
                        'science_lab_technology_5': 'Science Lab Technology Level 5',
                        'science_laboratory_technology_5': 'Science Lab Technology Level 5',
                        'general_agriculture_4': 'General Agriculture Level 4',
                        'sustainable_agriculture_5': 'Sustainable Agriculture Level 5',
                        'building_construction_4': 'Building Construction Level 4',
                        'building_construction_5': 'Building Construction Level 5',
                        'plumbing_4': 'Plumbing Level 4',
                        'plumbing_5': 'Plumbing Level 5',
                        'electrical_engineering_4': 'Electrical Engineering Level 4',
                        'electrical_engineering_5': 'Electrical Engineering Level 5',
                        'electrical_engineering_6': 'Electrical Engineering Level 6',
                        'automotive_engineering_5': 'Automotive Engineering Level 5',
                        'automotive_engineering_6': 'Automotive Engineering Level 6',
                        'hospitality_management_5': 'Hospitality Management Level 5',
                        'hospitality_management_6': 'Hospitality Management Level 6',
                        'food_beverage_production_management_5': 'Food & Beverage Production Management Level 5',
                        'food_beverage_production_management_6': 'Food & Beverage Production Management Level 6',
                        'business_management_6': 'Business Management Level 6',
                        'supply_chain_management_6': 'Supply Chain Management Level 6',
                        'human_resource_management_6': 'Human Resource Management Level 6',
                        'journalism_mass_communication_6': 'Journalism & Mass Communication Level 6',
                        'information_communication_technology_6': 'Information Communication Technology Level 6',
                        'information_technology_5': 'Information Technology Level 5',
                        'computer_science_6': 'Computer Science Level 6'
                    };
                    
                    const programName = courseToProgram[currentStudent.course];
                    console.log(`🔍 Looking for program: ${programName} for course: ${currentStudent.course}`);
                    
                    // Get the program cost for their course
                    const program = programName ? await Program.findOne({ programName }) : null;
                    
                    if (program) {
                        console.log(`✅ Program found: ${program.programName}, Cost: KES ${program.programCost}`);
                        
                        if (program.programCost && program.programCost > 0) {
                            // Add the new year's cost to their existing balance
                            const existingBalance = currentStudent.balance || 0;
                            const newBalance = existingBalance + program.programCost;
                            updates.balance = newBalance;
                            
                            console.log(`💰 Adding program cost KES ${program.programCost.toLocaleString()} to existing balance KES ${existingBalance.toLocaleString()}`);
                            console.log(`💳 New balance will be: KES ${newBalance.toLocaleString()}`);
                        } else {
                            console.warn(`⚠️ Program cost is not set or is zero for ${program.programName}`);
                        }
                    } else {
                        console.warn(`⚠️ Program not found for course: ${currentStudent.course} (mapped to: ${programName})`);
                    }
                } else {
                    console.log(`ℹ️ Year not changed (both are ${updates.year}), no balance update needed`);
                }
            }
        }
        
        const student = await Student.findByIdAndUpdate(id, updates, { new: true });
        if (!student) {
            return res.status(404).json({ message: 'Student not found' });
        }
        
        res.json(student);
    } catch (error) {
        console.error('Error updating student:', error);
        res.status(500).json({ message: 'Error updating student' });
    }
});

// Export Students by Admission Type
app.get('/api/students/export/:admissionType', async (req, res) => {
    try {
        const { admissionType } = req.params;
        
        // Validate admission type
        if (!['walk-in', 'KUCCPS'].includes(admissionType)) {
            return res.status(400).json({ message: 'Invalid admission type. Must be walk-in or KUCCPS' });
        }
        
        const students = await Student.find(
            { admissionType: admissionType }, 
            { password: 0 }
        ).sort({ createdAt: -1 });
        
        // Format data for export
        const exportData = students.map(student => ({
            'Admission Number': student.admissionNumber,
            'Full Name': student.name,
            'ID Number': student.idNumber,
            'KCSE Grade': student.kcseGrade,
            'Course': student.course,
            'Department': student.department,
            'Year of Study': student.year,
            'Intake': student.intake,
            'Intake Year': student.intakeYear,
            'Admission Type': student.admissionType,
            'Phone Number': student.phoneNumber,
            'Registration Date': new Date(student.createdAt).toLocaleDateString()
        }));
        
        res.json({
            success: true,
            data: exportData,
            count: students.length,
            admissionType: admissionType
        });
    } catch (error) {
        console.error('Error exporting students:', error);
        res.status(500).json({ message: 'Error exporting students' });
    }
});

// Login Endpoint
app.post('/api/students/login', async (req, res) => {
    try {
        const { admissionNumber, password } = req.body;

        console.log('Login attempt:', { admissionNumber, password: '***' });

        if (!admissionNumber || !password) {
            return res.status(400).json({ message: 'Please provide both admission number and password' });
        }

        const student = await Student.findOne({ admissionNumber });
        if (!student) {
            console.log('Student not found with admission number:', admissionNumber);
            return res.status(401).json({ message: 'No student found with this admission number' });
        }

        console.log('Student found, comparing password with stored phone:', student.phoneNumber);
        console.log('Provided password:', password);

        // Format the provided password the same way we format during registration
        const normalizedPassword = password.replace(/\D/g, '');
        const formattedPassword = normalizedPassword.length === 12 ? '0' + normalizedPassword.slice(-9) : 
                                 normalizedPassword.length === 13 ? '0' + normalizedPassword.slice(-9) : 
                                 normalizedPassword;

        console.log('Formatted password for comparison:', formattedPassword);

        // Try multiple formats for backward compatibility
        const passwordsToTry = [
            formattedPassword,           // Properly formatted phone
            password,                    // Raw password as entered
            password.replace(/\D/g, ''), // Numbers only
            '254' + password.slice(1),   // Convert 07... to 254...
            '+254' + password.slice(1)   // Convert 07... to +254...
        ];

        let isValidPassword = false;
        let matchedFormat = '';

        for (const pwd of passwordsToTry) {
            try {
                if (await student.comparePassword(pwd)) {
                    isValidPassword = true;
                    matchedFormat = pwd;
                    console.log('Password matched with format:', pwd);
                    break;
                }
            } catch (error) {
                console.log('Error comparing password format:', pwd, error.message);
            }
        }

        console.log('Final login result:', isValidPassword, 'Matched format:', matchedFormat);

        if (!isValidPassword) {
            return res.status(401).json({ message: 'Incorrect password. Use your phone number as password.' });
        }

        res.status(200).json({
            message: 'Login successful',
                name: student.name,
                admissionNumber: student.admissionNumber,
            course: student.course,
            idNumber: student.idNumber,
            kcseGrade: student.kcseGrade,
            department: student.department,
            phoneNumber: student.phoneNumber,
            year: student.year
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Error during login' });
    }
});

// Check if student can register (fee threshold check) - MUST be before /:id route
app.get('/api/students/:studentId/can-register', async (req, res) => {
    console.log('🔍 CAN-REGISTER API called for student:', req.params.studentId);
    try {
        const { studentId } = req.params;
        
        // Get fee threshold
        const feeThreshold = await SystemSettings.getSetting('fee_threshold', 50000);
        
        // Find student
        const student = await Student.findOne({ admissionNumber: studentId });
        if (!student) {
            return res.status(404).json({ message: 'Student not found' });
        }
        
        // Calculate outstanding balance using the same method as the dashboard
        const payments = await Payment.find({ studentId: studentId }).sort({ date: -1 });
        const paidAmount = payments.reduce((sum, payment) => sum + (payment.amount || 0), 0);
        
        // Get program cost using the same mapping as frontend
        const courseToProgram = {
            'applied_biology_6': 'Applied Biology Level 6',
            'analytical_chemistry_6': 'Analytical Chemistry Level 6',
            'science_lab_technology_5': 'Science Lab Technology Level 5',
            'science_laboratory_technology_5': 'Science Lab Technology Level 5',
            'general_agriculture_4': 'General Agriculture Level 4',
            'sustainable_agriculture_5': 'Sustainable Agriculture Level 5',
            'building_construction_4': 'Building Construction Level 4',
            'building_construction_5': 'Building Construction Level 5',
            'plumbing_4': 'Plumbing Level 4',
            'plumbing_5': 'Plumbing Level 5',
            'electrical_engineering_4': 'Electrical Engineering Level 4',
            'electrical_engineering_5': 'Electrical Engineering Level 5',
            'electrical_engineering_6': 'Electrical Engineering Level 6',
            'automotive_engineering_5': 'Automotive Engineering Level 5',
            'automotive_engineering_6': 'Automotive Engineering Level 6',
            'food_beverage_4': 'Food and Beverage Level 4',
            'food_beverage_5': 'Food & Beverage Level 5',
            'food_beverage_6': 'Food & Beverage Level 6',
            'hospitality_management_4': 'Hospitality Management Level 4',
            'hospitality_management_5': 'Hospitality Management Level 5',
            'hospitality_management_6': 'Hospitality Management Level 6',
            'business_administration_4': 'Business Administration Level 4',
            'business_administration_5': 'Business Administration Level 5',
            'business_administration_6': 'Business Administration Level 6',
            'liberal_studies_4': 'Liberal Studies Level 4',
            'liberal_studies_5': 'Liberal Studies Level 5',
            'liberal_studies_6': 'Liberal Studies Level 6',
            'computing_informatics_4': 'Computing & Informatics Level 4',
            'computing_informatics_5': 'Computing & Informatics Level 5',
            'computing_informatics_6': 'Computing & Informatics Level 6'
        };
        
        const programName = courseToProgram[student.course];
        const program = programName ? await Program.findOne({ programName: programName }) : null;
        const totalFees = program ? program.programCost : 67189; // Default to standard program cost
        
        const outstandingBalance = totalFees - paidAmount;
        const canRegister = outstandingBalance < feeThreshold;
        
        res.json({
            canRegister,
            outstandingBalance,
            feeThreshold,
            totalFees,
            paidAmount
        });
        
    } catch (error) {
        console.error('Error checking registration eligibility:', error);
        res.status(500).json({ message: 'Error checking registration eligibility' });
    }
});

// Get Student by Mongo _id (used by registrar view/edit)
app.get('/api/students/:id', async (req, res) => {
    try {
        const student = await Student.findById(req.params.id, { password: 0 });
        if (!student) {
            return res.status(404).json({ message: 'Student not found' });
        }
        res.json(student);
    } catch (error) {
        console.error('Error fetching student by id:', error);
        res.status(500).json({ message: 'Error fetching student' });
    }
});

// Update Student by Mongo _id
app.put('/api/students/:id', async (req, res) => {
    try {
        const { name, idNumber, phoneNumber, year } = req.body;
        
        // Validate phone number format if provided
        if (phoneNumber) {
            const normalizedPhone = phoneNumber.replace(/\D/g, '');
            if (!/^(?:254|\+254|0)?([17](?:(?:[0-9][0-9])|(?:0[0-8])|(4[0-1]))[0-9]{6})$/.test(normalizedPhone)) {
                return res.status(400).json({
                    message: 'Invalid phone number format. Please enter a valid Kenyan phone number'
                });
            }
        }

        const updateData = {};
        if (name) updateData.name = name;
        if (idNumber) updateData.idNumber = idNumber;
        if (phoneNumber) {
            const normalizedPhone = phoneNumber.replace(/\D/g, '');
            const formattedPhone = normalizedPhone.length === 12 ? '0' + normalizedPhone.slice(-9) : 
                                  normalizedPhone.length === 13 ? '0' + normalizedPhone.slice(-9) : 
                                  normalizedPhone;
            updateData.phoneNumber = formattedPhone;
        }
        
        // Handle year promotion with balance update
        if (year !== undefined) {
            updateData.year = year;
            
            // Get the current student to check if year is actually changing (promotion)
            const currentStudent = await Student.findById(req.params.id);
            
            if (currentStudent) {
                console.log(`🔄 Checking promotion: Current Year=${currentStudent.year}, New Year=${year}, Course=${currentStudent.course}`);
                
                if (currentStudent.year !== year) {
                    // Student is being promoted to a new year
                    console.log(`📚 Student ${currentStudent.admissionNumber} is being promoted from Year ${currentStudent.year} to Year ${year}`);
                    
                    // Map course code to program name
                    const courseToProgram = {
                        'applied_biology_6': 'Applied Biology Level 6',
                        'analytical_chemistry_6': 'Analytical Chemistry Level 6',
                        'science_lab_technology_5': 'Science Lab Technology Level 5',
                        'science_laboratory_technology_5': 'Science Lab Technology Level 5',
                        'general_agriculture_4': 'General Agriculture Level 4',
                        'sustainable_agriculture_5': 'Sustainable Agriculture Level 5',
                        'building_construction_4': 'Building Construction Level 4',
                        'building_construction_5': 'Building Construction Level 5',
                        'plumbing_4': 'Plumbing Level 4',
                        'plumbing_5': 'Plumbing Level 5',
                        'electrical_engineering_4': 'Electrical Engineering Level 4',
                        'electrical_engineering_5': 'Electrical Engineering Level 5',
                        'electrical_engineering_6': 'Electrical Engineering Level 6',
                        'automotive_engineering_5': 'Automotive Engineering Level 5',
                        'automotive_engineering_6': 'Automotive Engineering Level 6',
                        'hospitality_management_5': 'Hospitality Management Level 5',
                        'hospitality_management_6': 'Hospitality Management Level 6',
                        'food_beverage_production_management_5': 'Food & Beverage Production Management Level 5',
                        'food_beverage_production_management_6': 'Food & Beverage Production Management Level 6',
                        'business_management_6': 'Business Management Level 6',
                        'supply_chain_management_6': 'Supply Chain Management Level 6',
                        'human_resource_management_6': 'Human Resource Management Level 6',
                        'journalism_mass_communication_6': 'Journalism & Mass Communication Level 6',
                        'information_communication_technology_6': 'Information Communication Technology Level 6',
                        'information_technology_5': 'Information Technology Level 5',
                        'computer_science_6': 'Computer Science Level 6'
                    };
                    
                    const programName = courseToProgram[currentStudent.course];
                    console.log(`🔍 Looking for program: ${programName} for course: ${currentStudent.course}`);
                    
                    // Get the program cost for their course
                    const program = programName ? await Program.findOne({ programName }) : null;
                    
                    if (program) {
                        console.log(`✅ Program found: ${program.programName}, Cost: KES ${program.programCost}`);
                        
                        if (program.programCost && program.programCost > 0) {
                            // Add the new year's cost to their existing balance
                            const existingBalance = currentStudent.balance || 0;
                            const newBalance = existingBalance + program.programCost;
                            updateData.balance = newBalance;
                            
                            console.log(`💰 Adding program cost KES ${program.programCost.toLocaleString()} to existing balance KES ${existingBalance.toLocaleString()}`);
                            console.log(`💳 New balance will be: KES ${newBalance.toLocaleString()}`);
                        } else {
                            console.warn(`⚠️ Program cost is not set or is zero for ${program.programName}`);
                        }
                    } else {
                        console.warn(`⚠️ Program not found for course: ${currentStudent.course} (mapped to: ${programName})`);
                    }
                } else {
                    console.log(`ℹ️ Year not changed (both are ${year}), no balance update needed`);
                }
            }
        }

        const student = await Student.findByIdAndUpdate(
            req.params.id,
            updateData,
            { new: true, runValidators: true }
        ).select('-password');

        if (!student) {
            return res.status(404).json({ message: 'Student not found' });
        }

        res.json({
            message: 'Student updated successfully',
            student
        });
    } catch (error) {
        console.error('Error updating student:', error);
        if (error.code === 11000) {
            return res.status(400).json({ message: 'ID number or phone number already exists' });
        }
        res.status(500).json({ message: 'Error updating student' });
    }
});

// Update student email
app.put('/api/students/:studentId/email', async (req, res) => {
    try {
        const { studentId } = req.params;
        const { email } = req.body;

        console.log('📧 Student email update request:', { studentId, newEmail: email });

        if (!email) {
            console.log('❌ Email is missing in request body');
            return res.status(400).json({ message: 'Email is required' });
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            console.log('❌ Invalid email format:', email);
            return res.status(400).json({ message: 'Invalid email format' });
        }

        // Check if email already exists
        const existingStudent = await Student.findOne({ email: email.toLowerCase(), admissionNumber: { $ne: studentId } });
        if (existingStudent) {
            console.log('❌ Email already in use by another student:', existingStudent.admissionNumber);
            return res.status(400).json({ message: 'Email already exists' });
        }

        // Update student email using admission number as identifier
        const student = await Student.findOneAndUpdate(
            { admissionNumber: studentId },
            { email: email.toLowerCase() },
            { new: true, runValidators: true }
        ).select('-password');

        if (!student) {
            console.log('❌ Student not found:', studentId);
            return res.status(404).json({ message: 'Student not found' });
        }

        console.log('✅ Student email updated successfully:', { 
            admissionNumber: student.admissionNumber, 
            newEmail: student.email 
        });

        res.json({
            message: 'Email updated successfully',
            student: {
                admissionNumber: student.admissionNumber,
                name: student.name,
                email: student.email,
                phoneNumber: student.phoneNumber
            }
        });
    } catch (error) {
        console.error('❌ Error updating student email:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// ========================================
// SYSTEM SETTINGS API ROUTES
// ========================================

// Get all system settings
app.get('/api/system-settings', async (req, res) => {
    try {
        const { category } = req.query;
        let settings;
        
        if (category) {
            settings = await SystemSettings.getSettingsByCategory(category);
        } else {
            settings = await SystemSettings.find({ isActive: true }).sort({ category: 1, key: 1 });
        }
        
        res.json(settings);
    } catch (error) {
        console.error('Error fetching system settings:', error);
        res.status(500).json({ message: 'Error fetching system settings' });
    }
});

// Get a specific system setting
app.get('/api/system-settings/:key', async (req, res) => {
    try {
        const { key } = req.params;
        const setting = await SystemSettings.findOne({ key, isActive: true });
        
        if (!setting) {
            return res.status(404).json({ message: 'Setting not found' });
        }
        
        res.json(setting);
    } catch (error) {
        console.error('Error fetching system setting:', error);
        res.status(500).json({ message: 'Error fetching system setting' });
    }
});

// Update system setting
app.put('/api/system-settings/:key', async (req, res) => {
    try {
        const { key } = req.params;
        const { value, description } = req.body;
        
        if (value === undefined) {
            return res.status(400).json({ message: 'Value is required' });
        }
        
        const setting = await SystemSettings.setSetting(key, value, description);
        res.json({ message: 'Setting updated successfully', setting });
    } catch (error) {
        console.error('Error updating system setting:', error);
        res.status(500).json({ message: 'Error updating system setting' });
    }
});

// ========================================
// STUDENT UNIT REGISTRATION API ROUTES
// ========================================

// Get student's unit registrations
app.get('/api/students/:studentId/registrations', async (req, res) => {
    try {
        const { studentId } = req.params;
        const { status = 'registered' } = req.query;
        
        const registrations = await StudentUnitRegistration.getStudentRegistrations(studentId, status);
        res.json(registrations);
    } catch (error) {
        console.error('Error fetching student registrations:', error);
        res.status(500).json({ message: 'Error fetching student registrations' });
    }
});

// Register student for units
app.post('/api/students/register-units', async (req, res) => {
    try {
        const { studentId } = req.body;
        const { unitIds, commonUnitIds, academicYear, semester } = req.body;
        
        // Get fee threshold
        const feeThreshold = await SystemSettings.getSetting('fee_threshold', 50000);
        
        // Check student's outstanding balance (you'll need to implement this based on your payment system)
        const student = await Student.findOne({ admissionNumber: studentId });
        if (!student) {
            return res.status(404).json({ message: 'Student not found' });
        }
        
        // Calculate outstanding balance using the same method as the dashboard
        const payments = await Payment.find({ studentId: studentId }).sort({ date: -1 });
        const paidAmount = payments.reduce((sum, payment) => sum + (payment.amount || 0), 0);
        
        // Get program cost using the same mapping as frontend
        const courseToProgram = {
            'applied_biology_6': 'Applied Biology Level 6',
            'analytical_chemistry_6': 'Analytical Chemistry Level 6',
            'science_lab_technology_5': 'Science Lab Technology Level 5',
            'science_laboratory_technology_5': 'Science Lab Technology Level 5',
            'general_agriculture_4': 'General Agriculture Level 4',
            'sustainable_agriculture_5': 'Sustainable Agriculture Level 5',
            'building_construction_4': 'Building Construction Level 4',
            'building_construction_5': 'Building Construction Level 5',
            'plumbing_4': 'Plumbing Level 4',
            'plumbing_5': 'Plumbing Level 5',
            'electrical_engineering_4': 'Electrical Engineering Level 4',
            'electrical_engineering_5': 'Electrical Engineering Level 5',
            'electrical_engineering_6': 'Electrical Engineering Level 6',
            'automotive_engineering_5': 'Automotive Engineering Level 5',
            'automotive_engineering_6': 'Automotive Engineering Level 6',
            'food_beverage_4': 'Food and Beverage Level 4',
            'food_beverage_5': 'Food & Beverage Level 5',
            'food_beverage_6': 'Food & Beverage Level 6',
            'hospitality_management_4': 'Hospitality Management Level 4',
            'hospitality_management_5': 'Hospitality Management Level 5',
            'hospitality_management_6': 'Hospitality Management Level 6',
            'business_administration_4': 'Business Administration Level 4',
            'business_administration_5': 'Business Administration Level 5',
            'business_administration_6': 'Business Administration Level 6',
            'liberal_studies_4': 'Liberal Studies Level 4',
            'liberal_studies_5': 'Liberal Studies Level 5',
            'liberal_studies_6': 'Liberal Studies Level 6',
            'computing_informatics_4': 'Computing & Informatics Level 4',
            'computing_informatics_5': 'Computing & Informatics Level 5',
            'computing_informatics_6': 'Computing & Informatics Level 6'
        };
        
        const programName = courseToProgram[student.course];
        const program = programName ? await Program.findOne({ programName: programName }) : null;
        const totalFees = program ? program.programCost : 67189; // Default to standard program cost
        
        const outstandingBalance = totalFees - paidAmount;
        
        console.log('🔍 Backend register-units balance calculation:', {
            studentId,
            studentCourse: student.course,
            programName: programName,
            programFound: !!program,
            actualProgramCost: program?.programCost,
            finalProgramCost: totalFees,
            paidAmount,
            outstandingBalance,
            feeThreshold,
            paymentsCount: payments.length,
            canRegister: outstandingBalance < feeThreshold
        });
        
        // Check if student can register based on fee threshold
        if (outstandingBalance >= feeThreshold) {
            return res.status(400).json({ 
                message: `Cannot register units. Outstanding balance of ${outstandingBalance} exceeds threshold of ${feeThreshold}`,
                outstandingBalance,
                feeThreshold
            });
        }
        
        const registrations = [];
        const errors = [];
        
        // Register department units
        if (unitIds && unitIds.length > 0) {
            for (const unitId of unitIds) {
                try {
                    const unit = await Unit.findById(unitId);
                    if (!unit) {
                        errors.push(`Unit with ID ${unitId} not found`);
                        continue;
                    }
                    
                    const registrationData = {
                        studentId,
                        unitId,
                        courseCode: unit.courseCode,
                        unitCode: unit.unitCode,
                        unitName: unit.unitName,
                        unitType: 'department',
                        academicYear,
                        semester
                    };
                    
                    const registration = await StudentUnitRegistration.registerStudent(registrationData);
                    registrations.push(registration);
                } catch (error) {
                    errors.push(`Error registering unit ${unitId}: ${error.message}`);
                }
            }
        }
        
        // Register common units
        if (commonUnitIds && commonUnitIds.length > 0) {
            for (const commonUnitId of commonUnitIds) {
                try {
                    const commonUnit = await CommonUnit.findById(commonUnitId);
                    if (!commonUnit) {
                        errors.push(`Common unit with ID ${commonUnitId} not found`);
                        continue;
                    }
                    
                    const registrationData = {
                        studentId,
                        unitId: commonUnitId,  // Use unitId instead of commonUnitId for consistency
                        courseCode: commonUnit.courseCode,
                        unitCode: commonUnit.unitCode,
                        unitName: commonUnit.unitName,
                        unitType: 'common',
                        academicYear,
                        semester
                    };
                    
                    const registration = await StudentUnitRegistration.registerStudent(registrationData);
                    registrations.push(registration);
                } catch (error) {
                    errors.push(`Error registering common unit ${commonUnitId}: ${error.message}`);
                }
            }
        }
        
        res.json({
            message: `Successfully registered ${registrations.length} units`,
            registrations,
            errors: errors.length > 0 ? errors : undefined
        });
        
    } catch (error) {
        console.error('Error registering student for units:', error);
        res.status(500).json({ message: 'Error registering student for units' });
    }
});


// Program Routes

// Create a new program
app.post('/api/programs', async (req, res) => {
    try {
        const { programName, programCost, department } = req.body;

        if (!programName || programCost === undefined || !department) {
            return res.status(400).json({ message: 'Please provide program name, cost, and department' });
        }

        if (isNaN(programCost) || programCost <= 0) {
            return res.status(400).json({ message: 'Program cost must be a positive number' });
        }

        const existingProgram = await Program.findOne({ programName });
        if (existingProgram) {
            return res.status(400).json({ message: 'A program with this name already exists' });
        }

        const program = new Program({
            programName,
            programCost,
            department
        });

        await program.save();

        res.status(201).json({
            message: 'Program created successfully',
            program
        });

    } catch (error) {
        if (error.name === 'ValidationError') {
            const messages = Object.values(error.errors).map(err => err.message);
            return res.status(400).json({ message: messages.join(', ') });
        }

        if (error.code === 11000) {
            return res.status(400).json({ message: 'A program with this name already exists' });
        }

        console.error('Error creating program:', error);
        res.status(500).json({ message: 'Error creating program' });
    }
});

// Get all programs
app.get('/api/programs', async (req, res) => {
    try {
        const programs = await Program.find().sort({ createdAt: -1 });
        res.json(programs);
    } catch (error) {
        console.error('Error fetching programs:', error);
        res.status(500).json({ message: 'Error fetching programs' });
    }
});

// Get a specific program
app.get('/api/programs/:id', async (req, res) => {
    try {
        const program = await Program.findById(req.params.id);
        
        if (!program) {
            return res.status(404).json({ message: 'Program not found' });
        }

        res.json(program);
    } catch (error) {
        console.error('Error fetching program:', error);
        res.status(500).json({ message: 'Error fetching program' });
    }
});

// Update a program
app.put('/api/programs/:id', async (req, res) => {
    try {
        const { programName, programCost, department } = req.body;
        const { id } = req.params;

        if (!programName || programCost === undefined || !department) {
            return res.status(400).json({ message: 'Please provide program name, cost, and department' });
        }

        if (isNaN(programCost) || programCost <= 0) {
            return res.status(400).json({ message: 'Program cost must be a positive number' });
        }

        const program = await Program.findById(id);
        if (!program) {
            return res.status(404).json({ message: 'Program not found' });
        }

        const existingProgram = await Program.findOne({ programName, _id: { $ne: id } });
        if (existingProgram) {
            return res.status(400).json({ message: 'A program with this name already exists' });
        }

        const updatedProgram = await Program.findByIdAndUpdate(
            id,
            { programName, programCost, department },
            { new: true, runValidators: true }
        );

        res.json({
            message: 'Program updated successfully',
            program: updatedProgram
        });

    } catch (error) {
        if (error.name === 'ValidationError') {
            const messages = Object.values(error.errors).map(err => err.message);
            return res.status(400).json({ message: messages.join(', ') });
        }

        console.error('Error updating program:', error);
        res.status(500).json({ message: 'Error updating program' });
    }
});

// Delete a program
app.delete('/api/programs/:id', async (req, res) => {
    try {
        const program = await Program.findByIdAndDelete(req.params.id);
        
        if (!program) {
            return res.status(404).json({ message: 'Program not found' });
        }

        res.json({ message: 'Program deleted successfully' });
    } catch (error) {
        console.error('Error deleting program:', error);
        res.status(500).json({ message: 'Error deleting program' });
    }
});

// Payment Routes

// Create a new payment
app.post('/api/payments', async (req, res) => {
    try {
        const { 
            studentId, 
            amount, 
            paymentMode, 
            bankName, 
            receiptNumber, 
            mpesaTransactionId, 
            bursaryReference, 
            reference, 
            paymentDate 
        } = req.body;

        console.log('💰 Processing payment:', { studentId, amount, paymentMode, reference });

        if (!studentId || !amount || !paymentMode || !reference) {
            return res.status(400).json({ message: 'Please provide all required payment details' });
        }

        // Validate payment mode specific details
        if (paymentMode === 'bank' && (!bankName || !receiptNumber)) {
            return res.status(400).json({ message: 'Bank name and receipt number are required for bank transfers' });
        }

        if (paymentMode === 'mpesa' && !mpesaTransactionId) {
            return res.status(400).json({ message: 'M-Pesa transaction ID is required for M-Pesa payments' });
        }

        if (paymentMode === 'bursary' && !bursaryReference) {
            return res.status(400).json({ message: 'Bursary reference is required for bursary payments' });
        }

        const payment = new Payment({
            studentId,
            amount,
            paymentMode,
            bankName,
            receiptNumber,
            mpesaTransactionId,
            bursaryReference,
            reference,
            paymentDate: paymentDate || new Date()
        });

        await payment.save();

        console.log('✅ Payment saved successfully:', payment._id);

        res.status(201).json({
            message: 'Payment recorded successfully',
            payment
        });

    } catch (error) {
        if (error.name === 'ValidationError') {
            const messages = Object.values(error.errors).map(err => err.message);
            console.error('❌ Payment validation error:', messages);
            return res.status(400).json({ message: messages.join(', ') });
        }

        console.error('❌ Error recording payment:', error);
        res.status(500).json({ message: 'Error recording payment' });
    }
});

// Get all payments
app.get('/api/payments', async (req, res) => {
    try {
        const payments = await Payment.find().sort({ paymentDate: -1 });
        res.json(payments);
    } catch (error) {
        console.error('Error fetching payments:', error);
        res.status(500).json({ message: 'Error fetching payments' });
    }
});

// Get payments for a specific student
app.get('/api/payments/student/:studentId', async (req, res) => {
    try {
        const payments = await Payment.find({ studentId: req.params.studentId }).sort({ paymentDate: -1 });
        res.json(payments);
    } catch (error) {
        console.error('Error fetching student payments:', error);
        res.status(500).json({ message: 'Error fetching student payments' });
    }
});





app.use((req, res, next) => {
    console.log(`Static file request: ${req.path}`);
    next();
});

// Tools of Trade API Endpoints

// Upload Tools of Trade
app.post('/api/tools/upload', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ message: 'No file uploaded' });
        }

        const { trainerId, unitId, commonUnitId, toolType, academicYear, semester } = req.body;

        if (!trainerId || !toolType || !academicYear || !semester) {
            return res.status(400).json({ message: 'Missing required fields' });
        }

        if (!unitId && !commonUnitId) {
            return res.status(400).json({ message: 'Either unitId or commonUnitId is required' });
        }

        let filePath, s3Key, s3Bucket, storageType;
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const extension = path.extname(req.file.originalname);
        const fileName = `file-${uniqueSuffix}${extension}`;

        // Check if S3 is configured
        if (isS3Configured()) {
            // Upload to S3
            console.log('📤 Uploading to S3...');
            const folder = `tools-of-trade/${toolType}`;
            const s3Result = await uploadToS3(
                req.file.buffer, 
                fileName, 
                req.file.mimetype, 
                folder
            );
            
            s3Key = s3Result.key;
            s3Bucket = s3Result.bucket;
            filePath = s3Result.location; // Store S3 URL as filePath for backward compatibility
            storageType = 's3';
            
            console.log('✅ File uploaded to S3:', s3Key);
        } else {
            // Fallback to local storage
            console.log('💾 S3 not configured, using local storage...');
            const correctFolder = path.join(uploadsDir, 'tools-of-trade', toolType);
            if (!fs.existsSync(correctFolder)) {
                fs.mkdirSync(correctFolder, { recursive: true });
            }
            
            const oldPath = req.file.path;
            const newPath = path.join(correctFolder, fileName);
            
            // Move file to correct location
            fs.renameSync(oldPath, newPath);
            
            filePath = newPath;
            storageType = 'local';
            
            console.log('✅ File saved locally:', filePath);
        }

        const toolSubmission = new ToolsOfTrade({
            trainerId,
            unitId: unitId || null,
            commonUnitId: commonUnitId || null,
            toolType,
            fileName: fileName,
            originalFileName: req.file.originalname,
            filePath: filePath,
            s3Key: s3Key || null,
            s3Bucket: s3Bucket || null,
            storageType: storageType,
            fileSize: req.file.size,
            mimeType: req.file.mimetype,
            academicYear,
            semester
        });

        await toolSubmission.save();

        // Create notification for HOD
        const notification = new Notification({
            recipientId: 'hod', // This should be the actual HOD ID
            recipientType: 'hod',
            title: 'New Tools of Trade Submission',
            message: `New ${toolType.replace(/_/g, ' ')} submitted by trainer`,
            type: 'tool_request',
            relatedId: toolSubmission._id.toString(),
            priority: 'medium'
        });

        await notification.save();

        res.json({
            success: true,
            message: `File uploaded successfully to ${storageType === 's3' ? 'S3' : 'local storage'}`,
            data: {
                id: toolSubmission._id,
                fileName: toolSubmission.fileName,
                originalFileName: toolSubmission.originalFileName,
                fileSize: toolSubmission.fileSize,
                toolType: toolSubmission.toolType,
                status: toolSubmission.status,
                storageType: storageType
            }
        });
    } catch (error) {
        console.error('❌ Error uploading file:', error);
        res.status(500).json({ 
            message: 'Error uploading file', 
            error: error.message 
        });
    }
});

// Get Tools of Trade for a trainer
app.get('/api/tools/trainer/:trainerId', async (req, res) => {
    try {
        const { trainerId } = req.params;
        const { toolType, status, academicYear, semester } = req.query;

        let query = { trainerId };
        if (toolType) query.toolType = toolType;
        if (status) query.status = status;
        if (academicYear) query.academicYear = academicYear;
        if (semester) query.semester = semester;

        const tools = await ToolsOfTrade.find(query)
            .populate('unitId', 'unitName courseCode')
            .populate('commonUnitId', 'unitName unitCode')
            .sort({ submittedAt: -1 });

        res.json(tools);
    } catch (error) {
        console.error('Error fetching tools:', error);
        res.status(500).json({ message: 'Error fetching tools' });
    }
});

// Get all Tools of Trade (for HOD/Deputy)
app.get('/api/tools', async (req, res) => {
    try {
        const { status, toolType, department, academicYear, semester } = req.query;

        let query = {};
        if (status) query.status = status;
        if (toolType) query.toolType = toolType;
        if (academicYear) query.academicYear = academicYear;
        if (semester) query.semester = semester;

        const tools = await ToolsOfTrade.find(query)
            .populate('unitId', 'unitName courseCode department')
            .populate('commonUnitId', 'unitName unitCode')
            .populate('trainerId', 'name department')
            .sort({ submittedAt: -1 });

        // Filter by department if specified
        let filteredTools = tools;
        if (department) {
            filteredTools = tools.filter(tool => {
                const toolDepartment = tool.unitId?.department || tool.trainerId?.department;
                return toolDepartment === department;
            });
        }

        res.json(filteredTools);
    } catch (error) {
        console.error('Error fetching tools:', error);
        res.status(500).json({ message: 'Error fetching tools' });
    }
});

// Update tool status (for Deputy only)
app.patch('/api/tools/:toolId/status', async (req, res) => {
    try {
        const { toolId } = req.params;
        const { status, feedback } = req.body;

        console.log('Status update request:', { toolId, status, feedback, reviewedBy: 'deputy_academics' });

        const tool = await ToolsOfTrade.findById(toolId);
        if (!tool) {
            return res.status(404).json({ message: 'Tool not found' });
        }

        console.log('Tool before update:', tool.status);
        
        // Only update if status is provided and not undefined
        if (status && status !== undefined && status !== '') {
            tool.status = status;
            console.log('Tool after update:', tool.status);
        } else {
            console.log('⚠️ Status is undefined or empty, not updating');
            return res.status(400).json({ message: 'Status is required' });
        }
        
        if (feedback) tool.feedback = feedback;
        tool.reviewedBy = 'deputy_academics'; // Only deputy can review tools
        tool.reviewedAt = new Date();

        const savedTool = await tool.save();
        
        console.log('Tool after save:', savedTool.status);
        console.log('Tool document after save:', { 
            id: savedTool._id, 
            status: savedTool.status, 
            feedback: savedTool.feedback,
            reviewedBy: savedTool.reviewedBy 
        });

        // Create notification for trainer
        const statusText = status ? status.replace(/_/g, ' ') : 'updated';
        const toolTypeText = tool.toolType ? tool.toolType.replace(/_/g, ' ') : 'tool';
        
        const notification = new Notification({
            recipientId: tool.trainerId,
            recipientType: 'trainer',
            title: `Tools of Trade ${statusText}`,
            message: `Your ${toolTypeText} has been ${statusText}`,
            type: status === 'approved' ? 'tool_approved' : status === 'rejected' ? 'tool_rejected' : 'tool_revision_needed',
            relatedId: toolId,
            priority: 'medium'
        });

        await notification.save();

        res.json({
            success: true,
            message: 'Tool status updated successfully',
            data: tool
        });
    } catch (error) {
        console.error('Error updating tool status:', error);
        res.status(500).json({ message: 'Error updating tool status' });
    }
});

// Get presigned URL for downloading a file from S3
app.get('/api/tools/:toolId/download', async (req, res) => {
    try {
        const { toolId } = req.params;

        const tool = await ToolsOfTrade.findById(toolId);
        if (!tool) {
            return res.status(404).json({ message: 'Tool not found' });
        }

        // If stored in S3, generate presigned URL
        if (tool.storageType === 's3' && tool.s3Key) {
            const presignedUrl = await getPresignedUrl(tool.s3Key, 3600); // 1 hour expiry
            res.json({
                success: true,
                url: presignedUrl,
                fileName: tool.originalFileName,
                storageType: 's3'
            });
        } else {
            // Return local file path for local storage
            res.json({
                success: true,
                url: `/uploads/${path.relative(uploadsDir, tool.filePath).replace(/\\/g, '/')}`,
                fileName: tool.originalFileName,
                storageType: 'local'
            });
        }
    } catch (error) {
        console.error('❌ Error getting download URL:', error);
        res.status(500).json({ 
            message: 'Error getting download URL',
            error: error.message 
        });
    }
});

// Delete tool submission
app.delete('/api/tools/:toolId', async (req, res) => {
    try {
        const { toolId } = req.params;

        const tool = await ToolsOfTrade.findById(toolId);
        if (!tool) {
            return res.status(404).json({ message: 'Tool not found' });
        }

        // Delete the file from storage
        if (tool.storageType === 's3' && tool.s3Key) {
            // Delete from S3
            await deleteFromS3(tool.s3Key);
            console.log('✅ File deleted from S3:', tool.s3Key);
        } else if (tool.filePath && fs.existsSync(tool.filePath)) {
            // Delete from local filesystem
            fs.unlinkSync(tool.filePath);
            console.log('✅ File deleted from local storage:', tool.filePath);
        }

        await ToolsOfTrade.findByIdAndDelete(toolId);

        res.json({
            success: true,
            message: 'Tool submission deleted successfully'
        });
    } catch (error) {
        console.error('❌ Error deleting tool:', error);
        res.status(500).json({ 
            message: 'Error deleting tool',
            error: error.message 
        });
    }
});

// Notifications API

// Get all notifications (for admin/deputy)
app.get('/api/notifications', async (req, res) => {
    try {
        const notifications = await Notification.find().sort({ createdAt: -1 });
        res.json(notifications);
    } catch (error) {
        console.error('Error fetching all notifications:', error);
        res.status(500).json({ message: 'Error fetching notifications' });
    }
});

// Get notifications for a user
app.get('/api/notifications/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        const { isRead, type, limit = 50 } = req.query;

        let query = { recipientId: userId };
        if (isRead !== undefined) query.isRead = isRead === 'true';
        if (type) query.type = type;

        const notifications = await Notification.find(query)
            .sort({ createdAt: -1 })
            .limit(parseInt(limit));

        res.json(notifications);
    } catch (error) {
        console.error('Error fetching notifications:', error);
        res.status(500).json({ message: 'Error fetching notifications' });
    }
});

// Mark notification as read
app.patch('/api/notifications/:notificationId/read', async (req, res) => {
    try {
        const { notificationId } = req.params;

        const notification = await Notification.findById(notificationId);
        if (!notification) {
            return res.status(404).json({ message: 'Notification not found' });
        }

        notification.isRead = true;
        notification.readAt = new Date();
        await notification.save();

        res.json({
            success: true,
            message: 'Notification marked as read'
        });
    } catch (error) {
        console.error('Error marking notification as read:', error);
        res.status(500).json({ message: 'Error marking notification as read' });
    }
});

// Mark all notifications as read for a user
app.patch('/api/notifications/:userId/read-all', async (req, res) => {
    try {
        const { userId } = req.params;

        await Notification.updateMany(
            { recipientId: userId, isRead: false },
            { isRead: true, readAt: new Date() }
        );

        res.json({
            success: true,
            message: 'All notifications marked as read'
        });
    } catch (error) {
        console.error('Error marking notifications as read:', error);
        res.status(500).json({ message: 'Error marking notifications as read' });
    }
});

// Create notification
app.post('/api/notifications', async (req, res) => {
    try {
        const { recipientId, recipientType, title, message, type, relatedId, priority = 'medium' } = req.body;

        if (!recipientId || !recipientType || !title || !message || !type) {
            return res.status(400).json({ message: 'Missing required fields' });
        }

        const notification = new Notification({
            recipientId,
            recipientType,
            title,
            message,
            type,
            relatedId,
            priority
        });

        await notification.save();

        res.json({
            success: true,
            message: 'Notification created successfully',
            data: notification
        });
    } catch (error) {
        console.error('Error creating notification:', error);
        res.status(500).json({ message: 'Error creating notification' });
    }
});

// Broadcast notification to all users of a type
app.post('/api/notifications/broadcast', async (req, res) => {
    try {
        const { recipientType, title, message, type, relatedId, priority = 'medium' } = req.body;

        if (!recipientType || !title || !message || !type) {
            return res.status(400).json({ message: 'Missing required fields' });
        }

        // Get all users of the specified type
        let users = [];
        if (recipientType === 'trainer') {
            users = await Trainer.find({}, '_id');
        } else if (recipientType === 'student') {
            users = await Student.find({}, '_id');
        } else if (recipientType === 'hod') {
            users = await HOD.find({}, '_id');
        }

        // Create notifications for all users
        const notifications = users.map(user => ({
            recipientId: user._id,
            recipientType,
            title,
            message,
            type,
            relatedId,
            priority
        }));

        await Notification.insertMany(notifications);

        res.json({
            success: true,
            message: `Notification sent to ${users.length} ${recipientType}s`,
            count: users.length
        });
    } catch (error) {
        console.error('Error broadcasting notification:', error);
        res.status(500).json({ message: 'Error broadcasting notification' });
    }
});

// ========================================
// GRADUATION APPLICATION ENDPOINTS
// ========================================

// Check if student can apply for graduation
app.get('/api/students/:studentId/graduation-eligibility', async (req, res) => {
    try {
        const { studentId } = req.params;
        
        const student = await Student.findOne({ admissionNumber: studentId });
        if (!student) {
            return res.status(404).json({ message: 'Student not found' });
        }
        
        // Extract level from course name (e.g., "science_laboratory_technology_5" -> level 5)
        const level = parseInt(student.course.match(/(\d+)$/)?.[1]) || 4;
        const yearOfStudy = student.year || 1;
        
        const canApply = GraduationApplication.canStudentApply(level, yearOfStudy);
        
        // Check if already applied for current academic year
        const currentAcademicYear = await SystemSettings.getSetting('current_academic_year', '2024/2025');
        
        const existingApplication = await GraduationApplication.findOne({
            studentId,
            academicYear: currentAcademicYear
        });
        
        res.json({
            canApply: canApply && !existingApplication,
            level,
            yearOfStudy,
            hasExistingApplication: !!existingApplication,
            existingApplication: existingApplication,
            reason: !canApply ? `Level ${level} students can only apply in Year ${level - 3}` : null
        });
        
    } catch (error) {
        console.error('Error checking graduation eligibility:', error);
        res.status(500).json({ message: 'Error checking eligibility' });
    }
});

// Submit graduation application
app.post('/api/students/:studentId/graduation-application', async (req, res) => {
    try {
        const { studentId } = req.params;
        
        const student = await Student.findOne({ admissionNumber: studentId });
        if (!student) {
            return res.status(404).json({ message: 'Student not found' });
        }
        
        // Extract level from course name
        const level = parseInt(student.course.match(/(\d+)$/)?.[1]) || 4;
        const yearOfStudy = student.year || 1;
        
        // Validate eligibility
        if (!GraduationApplication.canStudentApply(level, yearOfStudy)) {
            return res.status(400).json({ 
                message: `Level ${level} students can only apply for graduation in Year ${level - 3}` 
            });
        }
        
        // Get current academic settings
        const currentAcademicYear = await SystemSettings.getSetting('current_academic_year', '2024/2025');
        
        // Check if already applied
        const existingApplication = await GraduationApplication.findOne({
            studentId,
            academicYear: currentAcademicYear
        });
        
        if (existingApplication) {
            return res.status(400).json({ message: 'You have already applied for graduation this academic period' });
        }
        
        // Get student's unit registrations to check completion
        const registrations = await StudentUnitRegistration.find({
            studentId,
            status: 'registered',
            isActive: true
        });
        
        const application = new GraduationApplication({
            studentId,
            name: student.name,
            admissionNumber: student.admissionNumber,
            idNumber: student.idNumber,
            phoneNumber: student.phoneNumber,
            kcseGrade: student.kcseGrade,
            course: student.course,
            department: student.department,
            yearOfStudy,
            intake: student.intake,
            admissionType: student.admissionType,
            level,
            academicYear: currentAcademicYear,
            unitsCompleted: registrations.length,
            totalUnits: registrations.length // This should be calculated based on course requirements
        });
        
        await application.save();
        
        // Create notification for ILO office
        const notification = new Notification({
            recipientId: 'ilo_office',
            recipientType: 'deputy',
            title: 'New Graduation Application',
            message: `${student.name} (${studentId}) has applied for graduation`,
            type: 'general',
            relatedId: application._id.toString(),
            priority: 'medium'
        });
        
        await notification.save();
        
        res.json({
            success: true,
            message: 'Graduation application submitted successfully',
            application
        });
        
    } catch (error) {
        console.error('Error submitting graduation application:', error);
        res.status(500).json({ message: 'Error submitting application' });
    }
});

// ========================================
// ATTACHMENT APPLICATION ENDPOINTS
// ========================================

// Check if student can apply for attachment
app.get('/api/students/:studentId/attachment-eligibility', async (req, res) => {
    try {
        const { studentId } = req.params;
        
        const student = await Student.findOne({ admissionNumber: studentId });
        if (!student) {
            return res.status(404).json({ message: 'Student not found' });
        }
        
        // Extract level from course name
        const level = parseInt(student.course.match(/(\d+)$/)?.[1]) || 4;
        const yearOfStudy = student.year || 1;
        
        const canApply = AttachmentApplication.canStudentApply(level, yearOfStudy);
        
        // Check if already applied for current academic year
        const currentAcademicYear = await SystemSettings.getSetting('current_academic_year', '2024/2025');
        
        const existingApplication = await AttachmentApplication.findOne({
            studentId,
            academicYear: currentAcademicYear
        });
        
        res.json({
            canApply: canApply && !existingApplication,
            level,
            yearOfStudy,
            hasExistingApplication: !!existingApplication,
            existingApplication: existingApplication,
            reason: !canApply ? `Level ${level} students can only apply in Year ${level - 3}` : null
        });
        
    } catch (error) {
        console.error('Error checking attachment eligibility:', error);
        res.status(500).json({ message: 'Error checking eligibility' });
    }
});

// Submit attachment application
app.post('/api/students/:studentId/attachment-application', async (req, res) => {
    try {
        const { studentId } = req.params;
        const { county, nearestTown } = req.body;
        
        if (!county || !nearestTown) {
            return res.status(400).json({ message: 'County and nearest town are required' });
        }
        
        const student = await Student.findOne({ admissionNumber: studentId });
        if (!student) {
            return res.status(404).json({ message: 'Student not found' });
        }
        
        // Extract level from course name
        const level = parseInt(student.course.match(/(\d+)$/)?.[1]) || 4;
        const yearOfStudy = student.year || 1;
        
        // Validate eligibility
        if (!AttachmentApplication.canStudentApply(level, yearOfStudy)) {
            return res.status(400).json({ 
                message: `Level ${level} students can only apply for attachment in Year ${level - 3}` 
            });
        }
        
        // Get current academic settings
        const currentAcademicYear = await SystemSettings.getSetting('current_academic_year', '2024/2025');
        
        // Check if already applied
        const existingApplication = await AttachmentApplication.findOne({
            studentId,
            academicYear: currentAcademicYear
        });
        
        if (existingApplication) {
            return res.status(400).json({ message: 'You have already applied for attachment this academic period' });
        }
        
        // Get student's unit registrations to check completion
        const registrations = await StudentUnitRegistration.find({
            studentId,
            status: 'registered',
            isActive: true
        });
        
        const application = new AttachmentApplication({
            studentId,
            name: student.name,
            admissionNumber: student.admissionNumber,
            idNumber: student.idNumber,
            phoneNumber: student.phoneNumber,
            kcseGrade: student.kcseGrade,
            course: student.course,
            department: student.department,
            yearOfStudy,
            intake: student.intake,
            admissionType: student.admissionType,
            level,
            county: county.trim(),
            nearestTown: nearestTown.trim(),
            academicYear: currentAcademicYear,
            unitsCompleted: registrations.length,
            totalUnits: registrations.length // This should be calculated based on course requirements
        });
        
        await application.save();
        
        // Create notification for ILO office
        const notification = new Notification({
            recipientId: 'ilo_office',
            recipientType: 'deputy',
            title: 'New Attachment Application',
            message: `${student.name} (${studentId}) has applied for attachment in ${county}, ${nearestTown}`,
            type: 'general',
            relatedId: application._id.toString(),
            priority: 'medium'
        });
        
        await notification.save();
        
        res.json({
            success: true,
            message: 'Attachment application submitted successfully',
            application
        });
        
    } catch (error) {
        console.error('Error submitting attachment application:', error);
        res.status(500).json({ message: 'Error submitting application' });
    }
});

// ========================================
// ILO OFFICE MANAGEMENT ENDPOINTS
// ========================================

// Get all graduation applications
app.get('/api/ilo/graduation-applications', async (req, res) => {
    try {
        const { status, department } = req.query;
        
        let query = {};
        if (status) query.status = status;
        if (department) query.department = department;
        
        const applications = await GraduationApplication.find(query)
            .sort({ applicationDate: -1 });
            
        res.json({
            success: true,
            applications,
            total: applications.length
        });
        
    } catch (error) {
        console.error('Error fetching graduation applications:', error);
        res.status(500).json({ message: 'Error fetching applications' });
    }
});

// Get all attachment applications
app.get('/api/ilo/attachment-applications', async (req, res) => {
    try {
        const { status, department, county } = req.query;
        
        let query = {};
        if (status) query.status = status;
        if (department) query.department = department;
        if (county) query.county = county;
        
        const applications = await AttachmentApplication.find(query)
            .sort({ applicationDate: -1 });
            
        res.json({
            success: true,
            applications,
            total: applications.length
        });
        
    } catch (error) {
        console.error('Error fetching attachment applications:', error);
        res.status(500).json({ message: 'Error fetching applications' });
    }
});

// Update application status
app.patch('/api/ilo/applications/:type/:applicationId/status', async (req, res) => {
    try {
        const { type, applicationId } = req.params;
        const { status, comments } = req.body;
        
        if (!['graduation', 'attachment'].includes(type)) {
            return res.status(400).json({ message: 'Invalid application type' });
        }
        
        const Model = type === 'graduation' ? GraduationApplication : AttachmentApplication;
        
        const application = await Model.findById(applicationId);
        if (!application) {
            return res.status(404).json({ message: 'Application not found' });
        }
        
        application.status = status;
        if (comments) application.comments = comments;
        application.reviewedBy = 'ilo_office';
        application.reviewedAt = new Date();
        
        await application.save();
        
        // Create notification for student
        const notification = new Notification({
            recipientId: application.studentId,
            recipientType: 'student',
            title: `${type === 'graduation' ? 'Graduation' : 'Attachment'} Application ${status}`,
            message: `Your ${type} application has been ${status}${comments ? `: ${comments}` : ''}`,
            type: 'general',
            relatedId: applicationId,
            priority: 'high'
        });
        
        await notification.save();
        
        res.json({
            success: true,
            message: 'Application status updated successfully',
            application
        });
        
    } catch (error) {
        console.error('Error updating application status:', error);
        res.status(500).json({ message: 'Error updating application' });
    }
});

// ========================================
// CLEAN URL ROUTES (Hide .html extensions)
// ========================================

// Admin routes are defined at the top of the file (after API routes)
// See lines 630-659

// Student routes
app.get('/student/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'src', 'login.html'));
});

app.get('/student/portal', (req, res) => {
    res.sendFile(path.join(__dirname, 'src', 'components', 'student', 'StudentPortalTailwind.html'));
});

// Trainer routes
app.get('/trainer/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'src', 'components', 'trainer', 'TrainerLogin.html'));
});

app.get('/trainer/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'src', 'components', 'trainer', 'TrainerDashboard.html'));
});

// Finance routes (using dashboard as login for now)
app.get('/finance/login', (req, res) => {
    res.redirect('/finance/dashboard');
});

app.get('/finance/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'src', 'components', 'finance', 'FinanceDashboard.html'));
});

// Registrar routes (using dashboard as login for now)
app.get('/registrar/login', (req, res) => {
    res.redirect('/registrar/dashboard');
});

app.get('/registrar/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'src', 'components', 'registrar', 'RegistrarDashboardNew.html'));
});

// Dean routes (using dashboard as login for now)
app.get('/dean/login', (req, res) => {
    res.redirect('/dean/dashboard');
});

app.get('/dean/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'src', 'components', 'dean', 'DeanDashboard.html'));
});

// Deputy routes
app.get('/deputy/login', (req, res) => {
    res.redirect('/deputy/dashboard');
});

app.get('/deputy/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'src', 'components', 'deputy', 'DeputyDashboard.html'));
});

// HOD routes
app.get('/hod/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'src', 'components', 'hod', 'HODLogin.html'));
});

app.get('/hod/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'src', 'components', 'hod', 'HODDashboard.html'));
});

// ILO routes (Industrial Liaison Office)
app.get('/ilo/login', (req, res) => {
    res.redirect('/ilo/dashboard');
});

app.get('/ilo/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'src', 'components', 'ilo', 'ILODashboard.html'));
});

// CIBEC routes (Competency-Based Education & Training Center)
app.get('/cibec/login', (req, res) => {
    res.redirect('/cibec/dashboard');
});

app.get('/cibec/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'src', 'components', 'cibec', 'CIBECDashboard.html'));
});

// Root redirect to student login
app.get('/', (req, res) => {
    res.redirect('/student/login');
});

// Serve static files after routes
// Prevent caching for admin dashboard JS file
app.use(express.static(path.join(__dirname, 'src', 'components'), {
    setHeaders: (res, filePath) => {
        if (filePath.includes('adminDashboard.js')) {
            res.set({
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0'
            });
        }
    }
}));
app.use(express.static('.'));

const PORT = config.port;
// ========================================
// STUDENT UPLOADS API ENDPOINTS
// ========================================

// Upload student file (profile, KCSE, KCPE, assessment, practical)
app.post('/api/student-uploads', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ message: 'No file uploaded' });
        }

        const {
            studentId,
            uploadType,
            unitId,
            unitCode,
            unitName,
            assessmentNumber,
            practicalNumber,
            academicYear,
            semester
        } = req.body;

        // Validate required fields
        if (!studentId || !uploadType || !academicYear || !semester) {
            return res.status(400).json({ message: 'Missing required fields' });
        }

        // Get student details
        const student = await Student.findOne({ admissionNumber: studentId });
        if (!student) {
            return res.status(404).json({ message: 'Student not found' });
        }

        // Validate unit-related uploads
        if (['assessment', 'practical', 'combined_video'].includes(uploadType)) {
            if (!unitId || !unitCode) {
                return res.status(400).json({ message: 'Unit information required for this upload type' });
            }

            // Check if student is registered for this unit
            const registration = await StudentUnitRegistration.findOne({
                studentId,
                unitId,
                status: 'registered',
                isActive: true,
                academicYear,
                semester
            });

            if (!registration) {
                return res.status(403).json({ message: 'You are not registered for this unit' });
            }

            // Check if unit is common (should not allow uploads for common units)
            if (registration.unitType === 'common') {
                return res.status(403).json({ message: 'Cannot upload assessments for common units' });
            }
        }

        // Validate assessment number
        if (uploadType === 'assessment') {
            if (!assessmentNumber || assessmentNumber < 1 || assessmentNumber > 3) {
                return res.status(400).json({ message: 'Invalid assessment number (must be 1-3)' });
            }
        }

        // Validate practical number
        if (uploadType === 'practical') {
            if (!practicalNumber || practicalNumber < 1 || practicalNumber > 3) {
                return res.status(400).json({ message: 'Invalid practical number (must be 1-3)' });
            }
            
            // Validate file type for practical uploads
            // Practical 1, 2, 3 should be PDF only
            if (practicalNumber >= 1 && practicalNumber <= 3) {
                if (req.file.mimetype !== 'application/pdf') {
                    return res.status(400).json({ 
                        message: 'Practical documents must be PDF files. Please upload a PDF file.' 
                    });
                }
            }
        }

            // Check for existing upload (to replace)
            let existingUpload = null;
            const searchCriteria = {
                studentId,
                uploadType,
                status: 'uploaded'
            };

            // For profile/results, only check by studentId and uploadType
            // For assessments/practicals/combined_video, also check unit and semester
            if (uploadType === 'assessment') {
                searchCriteria.unitId = unitId;
                searchCriteria.assessmentNumber = assessmentNumber;
                searchCriteria.academicYear = academicYear;
                searchCriteria.semester = semester;
            } else if (uploadType === 'practical') {
                searchCriteria.unitId = unitId;
                searchCriteria.practicalNumber = practicalNumber;
                searchCriteria.academicYear = academicYear;
                searchCriteria.semester = semester;
            } else if (uploadType === 'combined_video') {
                searchCriteria.unitId = unitId;
                searchCriteria.academicYear = academicYear;
                searchCriteria.semester = semester;
            }
            // For profile_photo, kcse_results, kcpe_results - don't filter by academic year/semester

            existingUpload = await StudentUpload.findOne(searchCriteria);

            console.log('Existing upload check:', searchCriteria, 'Found:', !!existingUpload);

        // If replacing existing, mark old as replaced FIRST to avoid duplicate key error
        if (existingUpload) {
            existingUpload.status = 'replaced';
            existingUpload.updatedAt = Date.now();
            await existingUpload.save();
            console.log('✅ Marked old upload as replaced:', existingUpload._id);
        }

        // Upload to S3
        const timestamp = Date.now();
        const month = new Date().getMonth() + 1;
        const year = new Date().getFullYear();
        const extension = path.extname(req.file.originalname);
        const fileName = `${timestamp}_${req.file.originalname}`;

        let folderPath;
        if (['profile_photo', 'kcse_results', 'kcpe_results'].includes(uploadType)) {
            folderPath = `cibec/${uploadType}/${studentId}/${year}/${month.toString().padStart(2, '0')}`;
        } else {
            folderPath = `cibec/${unitId}/${studentId}/${uploadType}/${year}/${month.toString().padStart(2, '0')}`;
        }

        const s3Result = await uploadToS3(
            req.file.buffer,
            fileName,
            req.file.mimetype,
            folderPath
        );

        // Create new upload record
        const newUpload = new StudentUpload({
            studentId,
            studentName: student.name,
            admissionNumber: student.admissionNumber,
            course: student.course,
            department: student.department,
            year: student.year,
            uploadType,
            unitId: unitId || null,
            unitCode: unitCode || null,
            unitName: unitName || null,
            assessmentNumber: assessmentNumber || null,
            practicalNumber: practicalNumber || null,
            fileName: fileName,
            originalFileName: req.file.originalname,
            s3Key: s3Result.key,
            s3Bucket: s3Result.bucket,
            fileSize: req.file.size,
            mimeType: req.file.mimetype,
            status: 'uploaded',
            version: existingUpload ? existingUpload.version + 1 : 1,
            replaces: existingUpload ? existingUpload._id : null,
            academicYear,
            semester
        });

        await newUpload.save();
        console.log('✅ Saved new upload:', newUpload._id, 'version:', newUpload.version);

        // Create audit log
        await AuditLog.logAction({
            userId: studentId,
            userType: 'student',
            action: existingUpload ? 'replace' : 'upload',
            fileId: newUpload._id,
            studentId,
            details: {
                uploadType,
                unitCode,
                assessmentNumber,
                practicalNumber,
                fileName: req.file.originalname,
                fileSize: req.file.size,
                replaced: !!existingUpload
            }
        });

        // Notify CIBEC
        await Notification.create({
            recipientId: 'cibec',
            recipientType: 'cibec',
            title: `New ${uploadType.replace(/_/g, ' ')} Upload`,
            message: `${student.name} (${student.admissionNumber}) uploaded ${uploadType.replace(/_/g, ' ')}${unitName ? ` for ${unitName}` : ''}`,
            type: 'student_upload',
            relatedId: newUpload._id.toString(),
            priority: 'medium'
        });

        res.json({
            success: true,
            message: existingUpload ? 'File replaced successfully' : 'File uploaded successfully',
            data: {
                id: newUpload._id,
                uploadType: newUpload.uploadType,
                fileName: newUpload.originalFileName,
                status: newUpload.status,
                version: newUpload.version,
                uploadedAt: newUpload.uploadedAt
            }
        });

    } catch (error) {
        console.error('❌ Error uploading student file:', error);
        res.status(500).json({
            message: 'Error uploading file',
            error: error.message
        });
    }
});

// Get student's uploads
app.get('/api/student-uploads/:studentId', async (req, res) => {
    try {
        const { studentId } = req.params;
        const { uploadType, status = 'uploaded' } = req.query;

        const query = { studentId, status };
        if (uploadType) query.uploadType = uploadType;

        const uploads = await StudentUpload.find(query)
            .populate('unitId')
            .sort({ uploadedAt: -1 });

        // Log view action
        await AuditLog.logAction({
            userId: studentId,
            userType: 'student',
            action: 'view',
            studentId,
            details: { uploadType, status, count: uploads.length }
        });

        res.json(uploads);
    } catch (error) {
        console.error('Error fetching student uploads:', error);
        res.status(500).json({ message: 'Error fetching uploads' });
    }
});

// Get student's unit uploads
app.get('/api/student-uploads/:studentId/unit/:unitId', async (req, res) => {
    try {
        const { studentId, unitId } = req.params;

        const uploads = await StudentUpload.find({
            studentId,
            unitId,
            status: 'uploaded'
        }).sort({ uploadType: 1, assessmentNumber: 1 });

        res.json(uploads);
    } catch (error) {
        console.error('Error fetching unit uploads:', error);
        res.status(500).json({ message: 'Error fetching unit uploads' });
    }
});

// Get download URL for student upload
app.get('/api/student-uploads/:uploadId/download', async (req, res) => {
    try {
        const { uploadId } = req.params;
        const { userId, userType } = req.query;

        const upload = await StudentUpload.findById(uploadId);
        if (!upload) {
            return res.status(404).json({ message: 'Upload not found' });
        }

        // Generate presigned URL
        const presignedUrl = await getPresignedUrl(upload.s3Key, 3600);

        // Log download action
        await AuditLog.logAction({
            userId: userId || upload.studentId,
            userType: userType || 'student',
            action: 'download',
            fileId: upload._id,
            studentId: upload.studentId,
            details: {
                fileName: upload.originalFileName,
                uploadType: upload.uploadType
            }
        });

        res.json({
            success: true,
            url: presignedUrl,
            fileName: upload.originalFileName,
            uploadType: upload.uploadType
        });
    } catch (error) {
        console.error('❌ Error getting download URL:', error);
        res.status(500).json({
            message: 'Error getting download URL',
            error: error.message
        });
    }
});

// Delete student upload
app.delete('/api/student-uploads/:uploadId', async (req, res) => {
    try {
        const { uploadId } = req.params;
        const { studentId } = req.query;

        const upload = await StudentUpload.findById(uploadId);
        if (!upload) {
            return res.status(404).json({ message: 'Upload not found' });
        }

        // Verify ownership
        if (upload.studentId !== studentId) {
            return res.status(403).json({ message: 'Unauthorized' });
        }

        // Delete from S3
        await deleteFromS3(upload.s3Key);

        // Mark as deleted in DB (soft delete)
        upload.status = 'deleted';
        upload.updatedAt = Date.now();
        await upload.save();

        // Log delete action
        await AuditLog.logAction({
            userId: studentId,
            userType: 'student',
            action: 'delete',
            fileId: upload._id,
            studentId,
            details: {
                fileName: upload.originalFileName,
                uploadType: upload.uploadType
            }
        });

        res.json({
            success: true,
            message: 'File deleted successfully'
        });
    } catch (error) {
        console.error('❌ Error deleting upload:', error);
        res.status(500).json({
            message: 'Error deleting file',
            error: error.message
        });
    }
});

// ========================================
// CIBEC PORTAL API ENDPOINTS
// ========================================

// Get all uploads with filters (CIBEC)
app.get('/api/cibec/uploads', async (req, res) => {
    try {
        const filters = {
            course: req.query.course,
            department: req.query.department,
            unitCode: req.query.unitCode,
            year: req.query.year,
            courseLevel: req.query.courseLevel,
            uploadType: req.query.uploadType,
            academicYear: req.query.academicYear,
            semester: req.query.semester,
            studentId: req.query.studentId,
            admissionNumber: req.query.admissionNumber,
            status: req.query.status || 'uploaded'
        };

        const uploads = await StudentUpload.getCIBECUploads(filters);

        // Log search action
        await AuditLog.logAction({
            userId: req.query.cibecUserId || 'cibec',
            userType: 'cibec',
            action: 'search',
            details: { filters, resultCount: uploads.length }
        });

        res.json({
            success: true,
            count: uploads.length,
            uploads
        });
    } catch (error) {
        console.error('Error fetching CIBEC uploads:', error);
        res.status(500).json({ message: 'Error fetching uploads' });
    }
});

// Get CIBEC statistics
app.get('/api/cibec/statistics', async (req, res) => {
    try {
        const { academicYear, semester } = req.query;

        const query = academicYear && semester
            ? { academicYear, semester, status: 'uploaded' }
            : { status: 'uploaded' };

        const [
            totalUploads,
            byType,
            byDepartment,
            byCourse,
            recentUploads
        ] = await Promise.all([
            StudentUpload.countDocuments(query),
            StudentUpload.aggregate([
                { $match: query },
                { $group: { _id: '$uploadType', count: { $sum: 1 } } }
            ]),
            StudentUpload.aggregate([
                { $match: query },
                { $group: { _id: '$department', count: { $sum: 1 } } }
            ]),
            StudentUpload.aggregate([
                { $match: query },
                { $group: { _id: '$course', count: { $sum: 1 } } }
            ]),
            StudentUpload.find(query)
                .sort({ uploadedAt: -1 })
                .limit(10)
                .populate('unitId')
        ]);

        res.json({
            success: true,
            statistics: {
                totalUploads,
                byType,
                byDepartment,
                byCourse,
                recentUploads
            }
        });
    } catch (error) {
        console.error('Error fetching CIBEC statistics:', error);
        res.status(500).json({ message: 'Error fetching statistics' });
    }
});

// Get student's all uploads (CIBEC view)
app.get('/api/cibec/student/:studentId/uploads', async (req, res) => {
    try {
        const { studentId } = req.params;
        const { cibecUserId } = req.query;

        const student = await Student.findOne({ admissionNumber: studentId });
        if (!student) {
            return res.status(404).json({ message: 'Student not found' });
        }

        const uploads = await StudentUpload.find({
            studentId,
            status: 'uploaded'
        })
            .populate('unitId')
            .sort({ uploadedAt: -1 });

        // Log view action
        await AuditLog.logAction({
            userId: cibecUserId || 'cibec',
            userType: 'cibec',
            action: 'view',
            studentId,
            details: {
                studentName: student.name,
                admissionNumber: student.admissionNumber,
                uploadCount: uploads.length
            }
        });

        res.json({
            success: true,
            student: {
                studentId: student.admissionNumber,
                name: student.name,
                course: student.course,
                department: student.department,
                year: student.year
            },
            uploads
        });
    } catch (error) {
        console.error('Error fetching student uploads for CIBEC:', error);
        res.status(500).json({ message: 'Error fetching student uploads' });
    }
});

// Get audit logs (CIBEC)
app.get('/api/cibec/audit-logs', async (req, res) => {
    try {
        const { dateFrom, dateTo, action, userId, limit = 100 } = req.query;

        const query = {};
        if (dateFrom || dateTo) {
            query.timestamp = {};
            if (dateFrom) query.timestamp.$gte = new Date(dateFrom);
            if (dateTo) query.timestamp.$lte = new Date(dateTo);
        }
        if (action) query.action = action;
        if (userId) query.userId = userId;

        const logs = await AuditLog.find(query)
            .sort({ timestamp: -1 })
            .limit(parseInt(limit))
            .populate('fileId');

        res.json({
            success: true,
            count: logs.length,
            logs
        });
    } catch (error) {
        console.error('Error fetching audit logs:', error);
        res.status(500).json({ message: 'Error fetching audit logs' });
    }
});

// ========================================
// DEAN PORTAL API ENDPOINTS
// ========================================

// Get all students for Dean Portal
app.get('/api/dean/students', async (req, res) => {
    try {
        const { course, department, year, intake, search } = req.query;
        
        let query = {};
        if (course) query.course = course;
        if (department) query.department = department;
        if (year) query.year = parseInt(year);
        if (intake) query.intake = intake;
        
        if (search) {
            query.$or = [
                { name: { $regex: search, $options: 'i' } },
                { admissionNumber: { $regex: search, $options: 'i' } },
                { idNumber: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } }
            ];
        }
        
        const students = await Student.find(query)
            .select('-password')
            .sort({ name: 1 });
        
        res.json(students);
    } catch (error) {
        console.error('Error fetching students for dean:', error);
        res.status(500).json({ message: 'Error fetching students' });
    }
});

// Add note to student
app.post('/api/dean/students/:studentId/notes', async (req, res) => {
    try {
        const { studentId } = req.params;
        const { noteType, title, content, category, priority, createdBy } = req.body;
        
        if (!noteType || !title || !content || !createdBy) {
            return res.status(400).json({ message: 'Missing required fields' });
        }
        
        const student = await Student.findOne({ admissionNumber: studentId });
        if (!student) {
            return res.status(404).json({ message: 'Student not found' });
        }
        
        const note = new StudentNote({
            studentId,
            studentName: student.name,
            admissionNumber: student.admissionNumber,
            noteType,
            title,
            content,
            category: category || 'general',
            priority: priority || 'medium',
            createdBy
        });
        
        await note.save();
        
        // If public note, create notification
        if (noteType === 'public') {
            await Notification.create({
                recipientId: studentId,
                recipientType: 'student',
                title: `New Note: ${title}`,
                message: content,
                type: 'general',
                relatedId: note._id.toString(),
                priority: priority || 'medium'
            });
        }
        
        res.json({
            success: true,
            message: 'Note added successfully',
            note
        });
    } catch (error) {
        console.error('Error adding student note:', error);
        res.status(500).json({ message: 'Error adding note', error: error.message });
    }
});

// Get student notes
app.get('/api/dean/students/:studentId/notes', async (req, res) => {
    try {
        const { studentId } = req.params;
        const { noteType } = req.query;
        
        const notes = await StudentNote.getStudentNotes(studentId, noteType);
        res.json(notes);
    } catch (error) {
        console.error('Error fetching student notes:', error);
        res.status(500).json({ message: 'Error fetching notes' });
    }
});

// Get student's public notes (for student portal)
app.get('/api/students/:studentId/public-notes', async (req, res) => {
    try {
        const { studentId } = req.params;
        
        // Public notes should be visible to all students, not just the assigned student
        // Remove studentId filter to show all public notes
        const notes = await StudentNote.find({
            noteType: 'public'
        }).sort({ createdAt: -1 });
        
        res.json({ notes });
    } catch (error) {
        console.error('Error fetching public notes:', error);
        res.status(500).json({ message: 'Error fetching public notes' });
    }
});

// Mark note as read
app.put('/api/students/:studentId/notes/:noteId/read', async (req, res) => {
    try {
        const { noteId } = req.params;
        
        const note = await StudentNote.findById(noteId);
        if (!note) {
            return res.status(404).json({ message: 'Note not found' });
        }
        
        note.isRead = true;
        note.readAt = new Date();
        await note.save();
        
        res.json({ success: true, message: 'Note marked as read' });
    } catch (error) {
        console.error('Error marking note as read:', error);
        res.status(500).json({ message: 'Error updating note' });
    }
});

// ========================================
// PAYSLIP API ENDPOINTS
// ========================================

// Generate payslips (Finance admin)
app.post('/api/payslips/generate', async (req, res) => {
    try {
        const { trainerIds, month, year, amount, description, generatedBy } = req.body;
        
        if (!trainerIds || !month || !year || !amount || !generatedBy) {
            return res.status(400).json({ message: 'Missing required fields' });
        }
        
        const period = `${month} ${year}`;
        const payslips = [];
        
        for (const trainerId of trainerIds) {
            // Find trainer by _id (MongoDB ObjectId)
            const trainer = await Trainer.findById(trainerId);
            if (!trainer) {
                console.warn(`Trainer ${trainerId} not found`);
                continue;
            }
            
            // Use trainer's email as the unique trainerId for payslip
            const trainerIdentifier = trainer.email;
            
            // Check if payslip already exists for this period
            const existing = await Payslip.findOne({ trainerId: trainerIdentifier, month, year });
            if (existing) {
                console.warn(`Payslip already exists for ${trainer.name} for ${period}`);
                continue;
            }
            
            const payslip = new Payslip({
                trainerId: trainerIdentifier,
                trainerName: trainer.name,
                email: trainer.email,
                department: trainer.department,
                month,
                year,
                amount,
                period,
                description: description || 'Monthly Salary',
                generatedBy
            });
            
            await payslip.save();
            payslips.push(payslip);
            
            // Create notification for trainer (use email as recipientId)
            await Notification.create({
                recipientId: trainer.email,
                recipientType: 'trainer',
                title: 'New Payslip Generated',
                message: `Your payslip for ${period} has been generated. Amount: KES ${amount.toLocaleString()}`,
                type: 'payment',
                relatedId: payslip._id.toString(),
                priority: 'medium'
            });
        }
        
        res.json({
            success: true,
            message: `Generated ${payslips.length} payslips`,
            payslips
        });
    } catch (error) {
        console.error('Error generating payslips:', error);
        res.status(500).json({ message: 'Error generating payslips', error: error.message });
    }
});

// Get trainer's payslips
app.get('/api/trainers/:trainerId/payslips', async (req, res) => {
    try {
        const { trainerId } = req.params;
        
        // Find trainer by _id to get their email
        const trainer = await Trainer.findById(trainerId);
        if (!trainer) {
            return res.status(404).json({ message: 'Trainer not found' });
        }
        
        // Fetch payslips using trainer's email (which is now the trainerId in payslips)
        const payslips = await Payslip.getTrainerPayslips(trainer.email);
        res.json({ payslips });
    } catch (error) {
        console.error('Error fetching trainer payslips:', error);
        res.status(500).json({ message: 'Error fetching payslips' });
    }
});

// Get all payslips (Finance admin)
app.get('/api/payslips', async (req, res) => {
    try {
        const { month, year } = req.query;
        
        let payslips;
        if (month && year) {
            payslips = await Payslip.getPayslipsByPeriod(month, parseInt(year));
        } else {
            payslips = await Payslip.find().sort({ createdAt: -1 });
        }
        
        res.json({ payslips });
    } catch (error) {
        console.error('Error fetching payslips:', error);
        res.status(500).json({ message: 'Error fetching payslips' });
    }
});

// Mark payslip as viewed
app.put('/api/payslips/:payslipId/view', async (req, res) => {
    try {
        const { payslipId } = req.params;
        
        const payslip = await Payslip.findById(payslipId);
        if (!payslip) {
            return res.status(404).json({ message: 'Payslip not found' });
        }
        
        payslip.isViewed = true;
        payslip.viewedAt = new Date();
        payslip.status = 'viewed';
        await payslip.save();
        
        res.json({ success: true, message: 'Payslip marked as viewed' });
    } catch (error) {
        console.error('Error marking payslip as viewed:', error);
        res.status(500).json({ message: 'Error updating payslip' });
    }
});

// Start server only in non-serverless environments
if (process.env.NODE_ENV !== 'production' || !process.env.VERCEL) {
    console.log('🚀 About to start listening on port', PORT);
    console.log('📍 Routes registered, starting server...');
    
    app.listen(PORT, () => {
        console.log(`✅ Server running on port ${PORT}`);
        console.log(`🔐 Admin Portal: http://localhost:${PORT}/admin/login`);
        console.log(`👨‍🎓 Student Portal: http://localhost:${PORT}/student/login`);
        console.log(`👨‍🏫 Trainer Portal: http://localhost:${PORT}/trainer/login`);
        console.log(`💰 Finance Portal: http://localhost:${PORT}/finance/dashboard`);
        console.log(`📝 Registrar Portal: http://localhost:${PORT}/registrar/dashboard`);
        console.log(`🎓 Dean Portal: http://localhost:${PORT}/dean/dashboard`);
        console.log(`👔 Deputy Portal: http://localhost:${PORT}/deputy/dashboard`);
        console.log(`🏢 HOD Portal: http://localhost:${PORT}/hod/dashboard`);
    });
    
    console.log('✅✅✅ SERVER FILE FULLY LOADED - AFTER APP.LISTEN() ✅✅✅');
} else {
    console.log('🌐 Running in serverless mode (Vercel)');
}

// Export the Express app for Vercel serverless functions
module.exports = app;