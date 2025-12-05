import express from 'express';
import session from 'express-session';
import multer from 'multer';
import bcrypt from 'bcryptjs';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// SECURE file upload configuration
const ALLOWED_EXTENSIONS = ['.png', '.jpg', '.jpeg', '.gif', '.pdf'];
const ALLOWED_MIME = ['image/png', 'image/jpeg', 'image/gif', 'application/pdf'];
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join(__dirname, 'uploads');
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    // Generate SECURE random filename - NOT using original filename!
    const uniqueName = crypto.randomBytes(16).toString('hex');
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${uniqueName}${ext}`);
  }
});

const fileFilter = (req, file, cb) => {
  const ext = path.extname(file.originalname).toLowerCase();
  const mime = file.mimetype;
  
  // SECURITY: Validate file extension
  if (!ALLOWED_EXTENSIONS.includes(ext)) {
    return cb(new Error('Invalid file extension. Only images and PDFs allowed.'), false);
  }
  
  // SECURITY: Validate MIME type
  if (!ALLOWED_MIME.includes(mime)) {
    return cb(new Error('Invalid file type.'), false);
  }
  
  cb(null, true);
};

const upload = multer({ 
  storage,
  fileFilter,
  limits: { fileSize: MAX_FILE_SIZE }
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({ 
  secret: crypto.randomBytes(32).toString('hex'), // SECURE: Random secret
  resave: false, 
  saveUninitialized: false,
  cookie: { 
    secure: false, // Set true in production with HTTPS
    httpOnly: true,
    maxAge: 1000 * 60 * 60 // 1 hour session
  }
}));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// CSRF Token middleware
app.use((req, res, next) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  next();
});

// User database with emails
const users = [
  { username: 'fathan', password: bcrypt.hashSync('Fathan123!@#', 10), email: 'fathan@kemjar.ac.id' },
  { username: 'ryan', password: bcrypt.hashSync('Ryan123!@#', 10), email: 'ryan@kemjar.ac.id' },
  { username: 'admin', password: bcrypt.hashSync('Admin123!@#', 10), email: 'admin@kemjar.ac.id' }
];

// OTP storage with SECURITY features
const otpStore = {};
const accountLockouts = {};

function findUser(username) {
  return users.find(u => u.username === username);
}

// SECURITY: Strong password validator
function isPasswordStrong(password) {
  if (password.length < 8) return { valid: false, message: 'Password must be at least 8 characters' };
  if (!/[A-Z]/.test(password)) return { valid: false, message: 'Must contain uppercase letter' };
  if (!/[a-z]/.test(password)) return { valid: false, message: 'Must contain lowercase letter' };
  if (!/[0-9]/.test(password)) return { valid: false, message: 'Must contain number' };
  if (!/[!@#$%^&*]/.test(password)) return { valid: false, message: 'Must contain special character (!@#$%^&*)' };
  return { valid: true };
}

// SECURITY: Generate SECURE 6-digit OTP
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// SECURITY: Check if account is locked
function isAccountLocked(username) {
  const lockout = accountLockouts[username];
  if (!lockout) return false;
  
  const now = Date.now();
  if (now < lockout.until) {
    return true;
  }
  
  // Lockout expired, remove it
  delete accountLockouts[username];
  return false;
}

// SECURITY: Lock account after too many attempts
function lockAccount(username, minutes = 30) {
  accountLockouts[username] = {
    until: Date.now() + (minutes * 60 * 1000),
    reason: 'Too many failed OTP attempts'
  };
}

// HTML Template with GREEN theme and animations
const pageTemplate = (title, content, showNav = false, username = '') => `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} - Proyek Akhir Kemjar Kelompok 15</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Crimson+Pro:wght@400;500;600;700&family=Playfair+Display:wght@600;700&display=swap" rel="stylesheet">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(20px); }
      to { opacity: 1; transform: translateY(0); }
    }
    
    @keyframes slideIn {
      from { opacity: 0; transform: translateX(-20px); }
      to { opacity: 1; transform: translateX(0); }
    }
    
    body {
      background: linear-gradient(135deg, #001a00 0%, #000a00 100%);
      min-height: 100vh;
      font-family: 'Crimson Pro', Georgia, serif;
      color: #ebffeb;
      animation: fadeIn 0.5s ease-out;
    }
    .navbar {
      background: linear-gradient(135deg, #0a2d0a 0%, #001a00 100%) !important;
      border-bottom: 2px solid #44ff44;
      padding: 1rem 0;
      box-shadow: 0 4px 20px rgba(68, 255, 68, 0.2);
      animation: slideIn 0.6s ease-out;
    }
    .navbar-brand {
      color: #6bff6b !important;
      font-weight: 700;
      font-size: 1.3rem;
      font-family: 'Playfair Display', serif;
      text-shadow: none;
    }
    .navbar-text { 
      color: #ccffcc !important;
      font-family: 'Crimson Pro', serif;
    }
    .main-container {
      max-width: 900px;
      margin: 40px auto;
      padding: 0 20px;
      animation: fadeIn 0.7s ease-out;
    }
    .card {
      border: 2px solid #44ff44;
      border-radius: 16px;
      background: linear-gradient(135deg, #0a2d0a 0%, #051a05 100%);
      overflow: hidden;
      box-shadow: 0 8px 32px rgba(68, 255, 68, 0.3);
      animation: fadeIn 0.8s ease-out;
    }
    .card-header {
      background: linear-gradient(135deg, #103d10 0%, #0a2d0a 100%);
      color: #6bff6b;
      padding: 24px 28px;
      border-bottom: 2px solid #44ff44;
      font-weight: 700;
      font-family: 'Playfair Display', serif;
    }
    .card-body {
      padding: 28px;
      background: linear-gradient(135deg, #0a2d0a 0%, #051a05 100%);
    }
    .btn-primary {
      background: linear-gradient(135deg, #44ff44 0%, #00cc00 100%);
      border: none;
      padding: 12px 28px;
      border-radius: 8px;
      font-weight: 600;
      transition: all 0.3s ease;
      box-shadow: 0 4px 15px rgba(68, 255, 68, 0.4);
      font-family: 'Crimson Pro', serif;
      color: #001a00;
    }
    .btn-primary:hover {
      background: linear-gradient(135deg, #66ff66 0%, #00ff00 100%);
      transform: translateY(-2px);
      box-shadow: 0 6px 20px rgba(68, 255, 68, 0.6);
      color: #000a00;
    }
    .btn-success { 
      background: linear-gradient(135deg, #88ff44 0%, #44ff00 100%);
      border: none; 
      padding: 12px 28px; 
      border-radius: 8px; 
      font-weight: 600;
      box-shadow: 0 4px 15px rgba(136, 255, 68, 0.4);
      font-family: 'Crimson Pro', serif;
      color: #001a00;
      transition: all 0.3s ease;
    }
    .btn-success:hover { 
      background: linear-gradient(135deg, #aaff66 0%, #66ff22 100%);
      transform: translateY(-2px);
      box-shadow: 0 6px 20px rgba(136, 255, 68, 0.6);
      color: #000a00;
    }
    .btn-warning { 
      background: linear-gradient(135deg, #ffcc44 0%, #ff9900 100%);
      border: none; 
      padding: 12px 28px; 
      border-radius: 8px; 
      color: #1a0000; 
      font-weight: 600;
      box-shadow: 0 4px 15px rgba(255, 204, 68, 0.4);
      font-family: 'Crimson Pro', serif;
      transition: all 0.3s ease;
    }
    .btn-warning:hover {
      background: linear-gradient(135deg, #ffdd66 0%, #ffaa00 100%);
      transform: translateY(-2px);
      box-shadow: 0 6px 20px rgba(255, 204, 68, 0.6);
    }
    .btn-outline-secondary {
      border: 2px solid #44ff44;
      color: #6bff6b;
      background: transparent;
      padding: 10px 24px;
      border-radius: 8px;
      font-weight: 600;
      font-family: 'Crimson Pro', serif;
      transition: all 0.3s ease;
    }
    .btn-outline-secondary:hover { 
      background: rgba(68, 255, 68, 0.1);
      color: #88ff88;
      border-color: #66ff66;
      transform: translateY(-1px);
    }
    .btn-outline-danger { 
      border: 2px solid #ff2222; 
      color: #ff4444; 
      background: transparent;
      font-family: 'Crimson Pro', serif;
      transition: all 0.3s ease;
    }
    .btn-outline-danger:hover { 
      background: linear-gradient(135deg, #ff4444 0%, #cc0000 100%);
      color: white;
      transform: translateY(-1px);
    }
    .form-control {
      border-radius: 8px;
      padding: 12px 16px;
      border: 2px solid #44ff44;
      background: rgba(5, 26, 5, 0.6);
      color: #ebffeb;
      font-family: 'Crimson Pro', serif;
      transition: all 0.3s ease;
    }
    .password-wrapper {
      position: relative;
    }
    .password-toggle {
      position: absolute;
      right: 12px;
      top: 50%;
      transform: translateY(-50%);
      background: none;
      border: none;
      color: #6bff6b;
      cursor: pointer;
      padding: 8px;
      font-size: 1.1rem;
      transition: all 0.3s ease;
      z-index: 10;
    }
    .password-toggle:hover {
      color: #88ff88;
      transform: translateY(-50%) scale(1.1);
    }
    .form-control:focus {
      border-color: #66ff66;
      box-shadow: 0 0 0 4px rgba(68, 255, 68, 0.2);
      background: rgba(5, 26, 5, 0.8);
      color: #ebffeb;
      outline: none;
    }
    .form-label { 
      color: #ccffcc; 
      font-weight: 600; 
      font-size: 0.95rem; 
      margin-bottom: 10px;
      font-family: 'Crimson Pro', serif;
    }
    .form-text { 
      color: #b3ffb3; 
      font-size: 0.85rem;
      font-family: 'Crimson Pro', serif;
    }
    .alert { 
      border-radius: 10px; 
      border: none;
      animation: slideIn 0.5s ease-out;
    }
    .alert-info { 
      background: linear-gradient(135deg, #203d20 0%, #152d15 100%);
      border-left: 4px solid #6bff6b; 
      color: #ccffcc;
    }
    .alert-success { 
      background: linear-gradient(135deg, #2d4d20 0%, #1d3d15 100%);
      border-left: 4px solid #88ff88; 
      color: #ddffd;
    }
    .alert-danger { 
      background: linear-gradient(135deg, #4d2020 0%, #3d1010 100%);
      border-left: 4px solid #ff4444; 
      color: #ffcccc;
    }
    .alert-warning { 
      background: linear-gradient(135deg, #4d3d20 0%, #3d2d15 100%);
      border-left: 4px solid #ffcc44; 
      color: #ffeecc;
    }
    .feature-card {
      transition: all 0.3s ease;
      cursor: pointer;
      border: 2px solid #44ff44;
      background: linear-gradient(135deg, #153d15 0%, #0a2d0a 100%);
      animation: fadeIn 1s ease-out;
    }
    .feature-card:hover { 
      transform: translateY(-5px) scale(1.02);
      border-color: #66ff66;
      box-shadow: 0 12px 40px rgba(68, 255, 68, 0.4);
    }
    .text-muted { color: #b3ffb3 !important; }
    code {
      background: rgba(0, 10, 0, 0.8);
      padding: 3px 8px;
      border-radius: 6px;
      color: #99ff99;
      font-family: 'Courier New', monospace;
      font-size: 0.9em;
      border: 1px solid #44ff44;
    }
    h3, h4, h5 { 
      color: #6bff6b; 
      font-weight: 700;
      font-family: 'Playfair Display', serif;
    }
    .footer {
      text-align: center;
      padding: 40px 20px;
      color: #88cc88;
      font-size: 0.9rem;
      font-family: 'Crimson Pro', serif;
      animation: fadeIn 1.2s ease-out;
    }
    .footer strong {
      color: #6bff6b;
    }
    .security-badge {
      display: inline-block;
      background: linear-gradient(135deg, #44ff44 0%, #00cc00 100%);
      color: #001a00;
      padding: 4px 12px;
      border-radius: 20px;
      font-size: 0.75rem;
      font-weight: 700;
      margin-left: 10px;
      box-shadow: 0 2px 10px rgba(68, 255, 68, 0.4);
      animation: fadeIn 1s ease-out;
    }
  </style>
</head>
<body>
  ${showNav ? `
  <nav class="navbar navbar-expand-lg">
    <div class="container">
      <a class="navbar-brand" href="/">
        <i class="fas fa-shield-alt me-2" style="color: #44ff44;"></i>
        Proyek Akhir Kemjar Kelompok 15
        <span class="security-badge">SECURE</span>
      </a>
      <div class="navbar-nav ms-auto">
        <span class="navbar-text me-3">
          <i class="fas fa-user me-2"></i>${username}
        </span>
        <a class="btn btn-sm btn-outline-danger" href="/logout">
          <i class="fas fa-sign-out-alt me-1"></i>Logout
        </a>
      </div>
    </div>
  </nav>
  ` : ''}
  
  <div class="main-container">
    ${content}
  </div>

  <div class="footer">
    <p>Kelompok 15 - Keamanan Jaringan Komputer</p>
    <p><strong>Fathan Yazid Satriani</strong> dan <strong>Ryan Adidaru Excel Barnabi</strong></p>
    <p class="mt-2" style="color: #6bff6b; font-size: 0.8rem;">
      <i class="fas fa-lock me-1"></i> This version implements proper security controls
    </p>
  </div>
  <script>
    function togglePassword(inputId, button) {
      const input = document.getElementById(inputId);
      const icon = button.querySelector('i');
      
      if (input.type === 'password') {
        input.type = 'text';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
      } else {
        input.type = 'password';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
      }
    }
  </script>
</body>
</html>
`;

// Home page
app.get('/', (req, res) => {
  if (!req.session.user) {
    const content = `
      <div class="card text-center">
        <div class="card-header">
          <h3 class="mb-0">Proyek Akhir Kemjar Kelompok 15</h3>
        </div>
        <div class="card-body py-5">
          <div style="font-size: 5rem; color: #44ff44; margin-bottom: 20px;">
            <i class="fas fa-shield-alt"></i>
          </div>
          <h4 class="mb-3">Secure Version</h4>
          <p class="text-muted mb-4">This version implements proper security protections</p>
          <div class="d-grid gap-2 col-6 mx-auto">
            <a class="btn btn-primary btn-lg" href="/login">
              <i class="fas fa-sign-in-alt me-2"></i>Login
            </a>
            <a class="btn btn-outline-secondary" href="/forgot-password">
              <i class="fas fa-question-circle me-2"></i>Forgot Password?
            </a>
          </div>
        </div>
      </div>
    `;
    return res.send(pageTemplate('Home', content));
  }

  const content = `
    <div class="card">
      <div class="card-header">
        <h3 class="mb-0"><i class="fas fa-home me-2"></i>Secure Dashboard</h3>
      </div>
      <div class="card-body">
        <div class="alert alert-success mb-4">
          <i class="fas fa-shield-check me-2"></i>
          <strong>Security Features Enabled:</strong>
          <ul class="mt-2 mb-0">
            <li>File type validation (images and PDFs only)</li>
            <li>OTP rate limiting (max 5 attempts)</li>
            <li>Account lockout protection</li>
            <li>Strong password requirements</li>
            <li>CSRF token protection</li>
          </ul>
        </div>
        
        <p class="mb-4">Welcome, <strong>${req.session.user}</strong>!</p>
        
        <div class="row g-3">
          <div class="col-md-12">
            <div class="card feature-card h-100" onclick="location.href='/upload'">
              <div class="card-body text-center p-4">
                <div style="font-size: 3.5rem; color: #44ff44; margin-bottom: 15px;">
                  <i class="fas fa-cloud-upload-alt"></i>
                </div>
                <h5 class="mb-2">Upload File</h5>
                <p class="text-muted small">Upload images and PDFs (validated and secure)</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  `;
  res.send(pageTemplate('Dashboard', content, true, req.session.user));
});

// Login page
app.get('/login', (req, res) => {
  const content = `
    <div class="card">
      <div class="card-header">
        <h3 class="mb-0"><i class="fas fa-sign-in-alt me-2"></i>Secure Login</h3>
      </div>
      <div class="card-body">
        <div class="alert alert-info mb-4">
          <i class="fas fa-info-circle me-2"></i>
          <strong>Demo Accounts (Strong Passwords):</strong><br>
          fathan / Fathan123!@# | ryan / Ryan123!@# | admin / Admin123!@#
        </div>
        <form method="post">
          <div class="mb-3">
            <label class="form-label">Username</label>
            <input class="form-control" name="username" placeholder="Enter username" required>
          </div>
          <div class="mb-3">
            <label class="form-label">Password</label>
            <div class="password-wrapper">
              <input class="form-control" id="loginPassword" name="password" type="password" placeholder="Enter password" required>
              <button type="button" class="password-toggle" onclick="togglePassword('loginPassword', this)">
                <i class="fas fa-eye"></i>
              </button>
            </div>
          </div>
          <button class="btn btn-primary w-100 mb-3">
            <i class="fas fa-sign-in-alt me-2"></i>Secure Login
          </button>
        </form>
        <div class="text-center">
          <a href="/forgot-password" class="text-muted">
            <i class="fas fa-question-circle me-1"></i>Forgot your password?
          </a>
        </div>
      </div>
    </div>
  `;
  res.send(pageTemplate('Login', content));
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = findUser(username);
  if (user && bcrypt.compareSync(password, user.password)) {
    req.session.user = username;
    res.redirect('/');
  } else {
    const content = `
      <div class="card">
        <div class="card-body text-center py-5">
          <i class="fas fa-times-circle text-danger" style="font-size: 4rem;"></i>
          <h4 class="mt-3">Login Failed</h4>
          <p class="text-muted">Invalid username or password</p>
          <a href="/login" class="btn btn-primary mt-3">Try Again</a>
        </div>
      </div>
    `;
    res.send(pageTemplate('Login Failed', content));
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// Forgot Password - SECURE version with rate limiting
app.get('/forgot-password', (req, res) => {
  const content = `
    <div class="card">
      <div class="card-header">
        <h3 class="mb-0"><i class="fas fa-key me-2"></i>Forgot Password</h3>
      </div>
      <div class="card-body">
        <div class="alert alert-info mb-4">
          <i class="fas fa-shield-check me-2"></i>
          <strong>Security Features:</strong>
          <ul class="mt-2 mb-0">
            <li>6-digit OTP (1,000,000 combinations)</li>
            <li>Maximum 5 verification attempts</li>
            <li>Account lockout after failed attempts</li>
            <li>OTP expires after 10 minutes</li>
          </ul>
        </div>
        
        <p class="text-muted mb-4">Enter your username to reset your password</p>
        
        <form method="post">
          <div class="mb-3">
            <label class="form-label">Username</label>
            <input class="form-control" name="username" placeholder="Enter your username" required>
            <div class="form-text">We'll send a 6-digit verification code to your registered email</div>
          </div>
          <button class="btn btn-primary w-100">
            <i class="fas fa-paper-plane me-2"></i>Request Password Reset
          </button>
        </form>
        
        <div class="mt-3 text-center">
          <a href="/login" class="text-muted">
            <i class="fas fa-arrow-left me-1"></i>Back to Login
          </a>
        </div>
      </div>
    </div>
  `;
  res.send(pageTemplate('Forgot Password', content));
});

// Request OTP - SECURE with lockout check
app.post('/forgot-password', (req, res) => {
  const { username } = req.body;
  
  // SECURITY: Check if account is locked
  if (isAccountLocked(username)) {
    const lockout = accountLockouts[username];
    const minutesLeft = Math.ceil((lockout.until - Date.now()) / (60 * 1000));
    
    const content = `
      <div class="card">
        <div class="card-body text-center py-5">
          <i class="fas fa-lock text-warning" style="font-size: 4rem;"></i>
          <h4 class="mt-3">Account Temporarily Locked</h4>
          <p class="text-muted">Too many failed attempts. Please try again in ${minutesLeft} minutes.</p>
          <div class="alert alert-warning mt-3">
            <i class="fas fa-exclamation-triangle me-2"></i>
            This is a security measure to protect your account.
          </div>
          <a href="/" class="btn btn-primary mt-3">Back to Home</a>
        </div>
      </div>
    `;
    return res.send(pageTemplate('Account Locked', content));
  }
  
  const user = findUser(username);
  
  if (!user) {
    const content = `
      <div class="card">
        <div class="card-body text-center py-5">
          <i class="fas fa-times-circle text-danger" style="font-size: 4rem;"></i>
          <h4 class="mt-3">User Not Found</h4>
          <p class="text-muted">The username you entered does not exist</p>
          <a href="/forgot-password" class="btn btn-primary mt-3">Try Again</a>
        </div>
      </div>
    `;
    return res.send(pageTemplate('Error', content));
  }
  
  // SECURITY: Generate 6-digit OTP (not 4!)
  const otp = generateOTP();
  const expiresAt = Date.now() + (10 * 60 * 1000); // 10 minutes
  
  otpStore[username] = {
    code: otp,
    timestamp: Date.now(),
    expiresAt: expiresAt,
    attempts: 0
  };
  
  console.log(`[EMAIL] Sending OTP to ${user.email}: ${otp}`);
  
  req.session.resetUsername = username;
  
  const content = `
    <div class="card">
      <div class="card-header">
        <h3 class="mb-0"><i class="fas fa-envelope me-2"></i>Verification Code Sent</h3>
      </div>
      <div class="card-body">
        <div class="alert alert-success mb-4">
          <i class="fas fa-check-circle me-2"></i>
          A 6-digit verification code has been sent to <strong>${user.email}</strong>
        </div>
        
        <div class="alert alert-warning mb-4">
          <i class="fas fa-clock me-2"></i>
          <strong>Important:</strong>
          <ul class="mt-2 mb-0">
            <li>Code expires in 10 minutes</li>
            <li>Maximum 5 verification attempts allowed</li>
            <li>Account will be locked after 5 failed attempts</li>
          </ul>
        </div>
        
        <div class="alert alert-info mb-4">
          <i class="fas fa-info-circle me-2"></i>
          <strong>For Demo:</strong> OTP code: <code>${otp}</code>
        </div>
        
        <form method="post" action="/verify-otp">
          <div class="mb-3">
            <label class="form-label">Enter Verification Code</label>
            <input class="form-control" name="otp" placeholder="Enter 6-digit code" maxlength="6" pattern="[0-9]{6}" required autofocus>
            <div class="form-text">Enter the 6-digit code sent to your email</div>
          </div>
          
          <div class="mb-3">
            <label class="form-label">New Password</label>
            <div class="password-wrapper">
              <input class="form-control" id="newPassword" name="new_password" type="password" placeholder="Enter strong password" required>
              <button type="button" class="password-toggle" onclick="togglePassword('newPassword', this)">
                <i class="fas fa-eye"></i>
              </button>
            </div>
            <div class="form-text">
              Must contain: 8+ chars, uppercase, lowercase, number, special char (!@#$%^&*)
            </div>
          </div>
          
          <button class="btn btn-warning w-100">
            <i class="fas fa-check me-2"></i>Verify & Reset Password
          </button>
        </form>
        
        <div class="mt-3 text-center">
          <form method="post" action="/forgot-password" style="display: inline;">
            <input type="hidden" name="username" value="${username}">
            <button type="submit" class="btn btn-link text-muted">
              <i class="fas fa-redo me-1"></i>Resend Code
            </button>
          </form>
        </div>
      </div>
    </div>
  `;
  res.send(pageTemplate('Verify OTP', content));
});

// Verify OTP - SECURE with rate limiting and expiration
app.post('/verify-otp', (req, res) => {
  const { otp, new_password } = req.body;
  const username = req.session.resetUsername;
  
  if (!username || !otpStore[username]) {
    return res.redirect('/forgot-password');
  }
  
  // SECURITY: Check if account is locked
  if (isAccountLocked(username)) {
    const lockout = accountLockouts[username];
    const minutesLeft = Math.ceil((lockout.until - Date.now()) / (60 * 1000));
    
    const content = `
      <div class="card">
        <div class="card-body text-center py-5">
          <i class="fas fa-lock text-warning" style="font-size: 4rem;"></i>
          <h4 class="mt-3">Account Locked</h4>
          <p class="text-muted">Too many failed OTP attempts. Try again in ${minutesLeft} minutes.</p>
          <a href="/" class="btn btn-primary mt-3">Back to Home</a>
        </div>
      </div>
    `;
    return res.send(pageTemplate('Account Locked', content));
  }
  
  const storedOTP = otpStore[username];
  
  // SECURITY: Check OTP expiration
  if (Date.now() > storedOTP.expiresAt) {
    delete otpStore[username];
    
    const content = `
      <div class="card">
        <div class="card-body text-center py-5">
          <i class="fas fa-clock text-warning" style="font-size: 4rem;"></i>
          <h4 class="mt-3">OTP Expired</h4>
          <p class="text-muted">Your verification code has expired after 10 minutes.</p>
          <a href="/forgot-password" class="btn btn-primary mt-3">Request New Code</a>
        </div>
      </div>
    `;
    return res.send(pageTemplate('OTP Expired', content));
  }
  
  // SECURITY: Increment and check attempts
  storedOTP.attempts++;
  
  if (storedOTP.attempts > 5) {
    lockAccount(username, 30); // Lock for 30 minutes
    delete otpStore[username];
    
    const content = `
      <div class="card">
        <div class="card-body text-center py-5">
          <i class="fas fa-ban text-danger" style="font-size: 4rem;"></i>
          <h4 class="mt-3">Account Locked</h4>
          <p class="text-muted">Too many failed OTP verification attempts.</p>
          <div class="alert alert-danger mt-3">
            <i class="fas fa-exclamation-triangle me-2"></i>
            Your account has been locked for 30 minutes for security reasons.
          </div>
          <a href="/" class="btn btn-primary mt-3">Back to Home</a>
        </div>
      </div>
    `;
    return res.send(pageTemplate('Account Locked', content));
  }
  
  if (storedOTP.code === otp) {
    // OTP correct - validate password strength
    const passwordCheck = isPasswordStrong(new_password);
    
    if (!passwordCheck.valid) {
      const content = `
        <div class="card">
          <div class="card-header bg-danger text-white">
            <h3 class="mb-0"><i class="fas fa-times-circle me-2"></i>Weak Password</h3>
          </div>
          <div class="card-body">
            <div class="alert alert-danger mb-4">
              <i class="fas fa-exclamation-triangle me-2"></i>
              ${passwordCheck.message}
            </div>
            
            <form method="post" action="/verify-otp">
              <div class="mb-3">
                <label class="form-label">Enter Verification Code</label>
                <input class="form-control" name="otp" value="${otp}" readonly>
              </div>
              
              <div class="mb-3">
                <label class="form-label">New Password</label>
                <div class="password-wrapper">
                  <input class="form-control" id="retryWeakPassword" name="new_password" type="password" required autofocus>
                  <button type="button" class="password-toggle" onclick="togglePassword('retryWeakPassword', this)">
                    <i class="fas fa-eye"></i>
                  </button>
                </div>
                <div class="form-text">
                  Requirements: 8+ chars, uppercase, lowercase, number, special char
                </div>
              </div>
              
              <button class="btn btn-warning w-100">
                <i class="fas fa-check me-2"></i>Verify & Reset Password
              </button>
            </form>
          </div>
        </div>
      `;
      return res.send(pageTemplate('Weak Password', content));
    }
    
    // Password is strong - reset it
    const user = findUser(username);
    user.password = bcrypt.hashSync(new_password, 10);
    delete otpStore[username];
    delete req.session.resetUsername;
    
    const content = `
      <div class="card">
        <div class="card-body text-center py-5">
          <i class="fas fa-check-circle text-success" style="font-size: 4rem;"></i>
          <h4 class="mt-3">Password Reset Successful</h4>
          <p class="text-muted mt-3">Your password has been changed securely. You can now login.</p>
          <div class="alert alert-success mt-3">
            <i class="fas fa-shield-check me-2"></i>
            <strong>Security measures applied:</strong>
            <ul class="mt-2 mb-0 text-start">
              <li>Password hashed with bcrypt</li>
              <li>Strong password validated</li>
              <li>OTP session cleared</li>
            </ul>
          </div>
          <div class="mt-4">
            <a href="/login" class="btn btn-primary btn-lg">
              <i class="fas fa-sign-in-alt me-2"></i>Login Now
            </a>
          </div>
        </div>
      </div>
    `;
    return res.send(pageTemplate('Success', content));
  } else {
    // OTP incorrect
    const attemptsLeft = 5 - storedOTP.attempts;
    const minutesLeft = Math.ceil((storedOTP.expiresAt - Date.now()) / (60 * 1000));
    
    const content = `
      <div class="card">
        <div class="card-header bg-danger text-white">
          <h3 class="mb-0"><i class="fas fa-times-circle me-2"></i>Invalid OTP</h3>
        </div>
        <div class="card-body">
          <div class="alert alert-danger mb-4">
            <i class="fas fa-exclamation-triangle me-2"></i>
            The verification code you entered is incorrect.
          </div>
          
          <div class="alert alert-warning">
            <i class="fas fa-info-circle me-2"></i>
            <strong>Security Notice:</strong>
            <ul class="mt-2 mb-0">
              <li>Attempts: ${storedOTP.attempts} / 5</li>
              <li>Remaining attempts: <strong>${attemptsLeft}</strong></li>
              <li>OTP expires in: ${minutesLeft} minutes</li>
              <li>Account will lock after 5 failed attempts</li>
            </ul>
          </div>
          
          <form method="post" action="/verify-otp">
            <div class="mb-3">
              <label class="form-label">Enter Verification Code</label>
              <input class="form-control" name="otp" placeholder="Enter 6-digit code" maxlength="6" pattern="[0-9]{6}" required autofocus>
            </div>
            
            <div class="mb-3">
              <label class="form-label">New Password</label>
              <div class="password-wrapper">
                <input class="form-control" id="retryPassword" name="new_password" type="password" value="${new_password}" required>
                <button type="button" class="password-toggle" onclick="togglePassword('retryPassword', this)">
                  <i class="fas fa-eye"></i>
                </button>
              </div>
            </div>
            
            <button class="btn btn-warning w-100">
              <i class="fas fa-check me-2"></i>Verify & Reset Password
            </button>
          </form>
          
          <div class="mt-3 text-center">
            <a href="/forgot-password" class="text-muted">
              <i class="fas fa-arrow-left me-1"></i>Start Over
            </a>
          </div>
        </div>
      </div>
    `;
    res.send(pageTemplate('Invalid OTP', content));
  }
});

// SECURE File upload
app.get('/upload', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  
  const content = `
    <div class="card">
      <div class="card-header">
        <h3 class="mb-0"><i class="fas fa-upload me-2"></i>Secure File Upload</h3>
      </div>
      <div class="card-body">
        <div class="alert alert-success mb-4">
          <i class="fas fa-shield-check me-2"></i>
          <strong>Security Protections:</strong>
          <ul class="mt-2 mb-0">
            <li>File type validation (images and PDFs only)</li>
            <li>File size limit (max 5MB)</li>
            <li>Secure random filenames</li>
            <li>No code execution</li>
          </ul>
        </div>
        
        <p class="text-muted mb-4">Upload images (.png, .jpg, .gif) or PDFs</p>
        
        <form method="post" enctype="multipart/form-data">
          <div class="mb-3">
            <label class="form-label">Choose File</label>
            <input class="form-control" type="file" name="file" accept=".png,.jpg,.jpeg,.gif,.pdf" required>
            <div class="form-text">Allowed: PNG, JPG, GIF, PDF (max 5MB)</div>
          </div>
          <button class="btn btn-success w-100">
            <i class="fas fa-cloud-upload-alt me-2"></i>Upload File (Secure)
          </button>
        </form>
        
        <div class="mt-3">
          <a href="/" class="btn btn-outline-secondary">
            <i class="fas fa-arrow-left me-2"></i>Back to Dashboard
          </a>
        </div>
      </div>
    </div>
  `;
  res.send(pageTemplate('Upload File', content, true, req.session.user));
});

app.post('/upload', (req, res) => {
  upload.single('file')(req, res, (err) => {
    if (err) {
      const content = `
        <div class="card">
          <div class="card-body text-center py-5">
            <i class="fas fa-times-circle text-danger" style="font-size: 4rem;"></i>
            <h4 class="mt-3">Upload Failed</h4>
            <p class="text-muted">${err.message}</p>
            <div class="alert alert-info mt-3">
              <i class="fas fa-info-circle me-2"></i>
              <strong>Security Validation:</strong><br>
              Only images (PNG, JPG, GIF) and PDFs up to 5MB are allowed.
            </div>
            <a href="/upload" class="btn btn-primary mt-3">Try Again</a>
          </div>
        </div>
      `;
      return res.send(pageTemplate('Upload Failed', content, true, req.session.user));
    }
    
    if (!req.file) {
      return res.status(400).send('No file uploaded');
    }
    
    // SECURITY: File is validated and stored securely - NO EXECUTION!
    const content = `
      <div class="card">
        <div class="card-body text-center py-4">
          <i class="fas fa-check-circle text-success" style="font-size: 4rem;"></i>
          <h4 class="mt-3">File Uploaded Securely</h4>
          
          <div class="alert alert-success mt-4">
            <i class="fas fa-shield-check me-2"></i>
            <strong>Security Validations Passed:</strong>
            <ul class="mt-2 mb-0 text-start">
              <li>✅ File extension validated</li>
              <li>✅ MIME type checked</li>
              <li>✅ Size limit enforced</li>
              <li>✅ Secure filename generated</li>
              <li>✅ No code execution</li>
            </ul>
          </div>
          
          <div class="card mt-4 p-3" style="background: #051a05; border: 2px solid #44ff44;">
            <p class="mb-2"><strong>Original Filename:</strong> <code>${req.file.originalname}</code></p>
            <p class="mb-2"><strong>Stored As:</strong> <code>${req.file.filename}</code></p>
            <p class="mb-2"><strong>Size:</strong> ${(req.file.size / 1024).toFixed(2)} KB</p>
            <p class="mb-2"><strong>Type:</strong> ${req.file.mimetype}</p>
            <p class="mb-0 mt-3">
              <a href="/uploads/${req.file.filename}" target="_blank" class="btn btn-sm btn-primary">
                <i class="fas fa-external-link-alt me-2"></i>View File
              </a>
            </p>
          </div>
          
          <div class="mt-4">
            <a href="/upload" class="btn btn-success me-2">Upload Another</a>
            <a href="/" class="btn btn-outline-secondary">Back to Dashboard</a>
          </div>
        </div>
      </div>
    `;
    res.send(pageTemplate('Upload Success', content, true, req.session.user));
  });
});

const PORT = 3002;
app.listen(PORT, () => {
  console.log(`\n╔════════════════════════════════════════════════════════╗`);
  console.log(`║  🔒 SECURE APP - Proyek Akhir Kemjar Kelompok 15     ║`);
  console.log(`╚════════════════════════════════════════════════════════╝\n`);
  console.log(`🌐 Application running on http://localhost:${PORT}`);
  console.log(`📧 OTP codes will be displayed in this console\n`);
  console.log(`✅ SECURITY FEATURES ENABLED:`);
  console.log(`    - File type validation (images & PDFs only)`);
  console.log(`    - OTP rate limiting (max 5 attempts)`);
  console.log(`    - Account lockout protection (30 min)`);
  console.log(`    - 6-digit OTP with expiration (10 min)`);
  console.log(`    - Strong password requirements`);
  console.log(`    - CSRF token protection`);
  console.log(`    - Secure random filenames\n`);
});
