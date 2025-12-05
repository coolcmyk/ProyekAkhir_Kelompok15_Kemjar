import express from 'express';
import session from 'express-session';
import multer from 'multer';
import bcrypt from 'bcryptjs';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Configure multer to save files with original extension
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    // Save with original filename - VULNERABILITY!
    cb(null, file.originalname);
  }
});

const upload = multer({ storage: storage });

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({ 
  secret: 'kemjar-vulnerable', 
  resave: false, 
  saveUninitialized: true,
  cookie: { secure: false }
}));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// User database - stored in memory
const users = [
  { username: 'fathan', password: bcrypt.hashSync('fathan123', 10), email: 'fathan@kemjar.ac.id' },
  { username: 'ryan', password: bcrypt.hashSync('ryan123', 10), email: 'ryan@kemjar.ac.id' },
  { username: 'admin', password: bcrypt.hashSync('admin123', 10), email: 'admin@kemjar.ac.id' }
];

// OTP storage - VULNERABILITY: No expiration, stored in plain text
const otpStore = {};

function findUser(username) {
  return users.find(u => u.username === username);
}

// Generate 4-digit OTP - VULNERABILITY: Too short!
function generateOTP() {
  return Math.floor(1000 + Math.random() * 9000).toString();
}

// HTML Template
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
      background: linear-gradient(135deg, #1a0000 0%, #0a0000 100%);
      min-height: 100vh;
      font-family: 'Crimson Pro', Georgia, serif;
      color: #ffebeb;
      animation: fadeIn 0.5s ease-out;
    }
    .navbar {
      background: linear-gradient(135deg, #2d0a0a 0%, #1a0000 100%) !important;
      border-bottom: 2px solid #ff4444;
      padding: 1rem 0;
      box-shadow: 0 4px 20px rgba(255, 68, 68, 0.2);
      animation: slideIn 0.6s ease-out;
    }
    .navbar-brand {
      color: #ff6b6b !important;
      font-weight: 700;
      font-size: 1.3rem;
      font-family: 'Playfair Display', serif;
      text-shadow: 0 0 10px rgba(255, 107, 107, 0.5);
    }
    .navbar-text { 
      color: #ffcccc !important;
      font-family: 'Crimson Pro', serif;
    }
    .main-container {
      max-width: 900px;
      margin: 40px auto;
      padding: 0 20px;
      animation: fadeIn 0.7s ease-out;
    }
    .card {
      border: 2px solid #ff4444;
      border-radius: 16px;
      background: linear-gradient(135deg, #2d0a0a 0%, #1a0505 100%);
      overflow: hidden;
      box-shadow: 0 8px 32px rgba(255, 68, 68, 0.3);
      animation: fadeIn 0.8s ease-out;
    }
    .card-header {
      background: linear-gradient(135deg, #3d1010 0%, #2d0a0a 100%);
      color: #ff6b6b;
      padding: 24px 28px;
      border-bottom: 2px solid #ff4444;
      font-weight: 700;
      font-family: 'Playfair Display', serif;
      text-shadow: 0 0 10px rgba(255, 107, 107, 0.3);
    }
    .card-body {
      padding: 28px;
      background: linear-gradient(135deg, #2d0a0a 0%, #1a0505 100%);
    }
    .btn-primary {
      background: linear-gradient(135deg, #ff4444 0%, #cc0000 100%);
      border: none;
      padding: 12px 28px;
      border-radius: 8px;
      font-weight: 600;
      transition: all 0.3s ease;
      box-shadow: 0 4px 15px rgba(255, 68, 68, 0.4);
      font-family: 'Crimson Pro', serif;
    }
    .btn-primary:hover {
      background: linear-gradient(135deg, #ff6666 0%, #ff0000 100%);
      transform: translateY(-2px);
      box-shadow: 0 6px 20px rgba(255, 68, 68, 0.6);
    }
    .btn-success { 
      background: linear-gradient(135deg, #ff8844 0%, #ff4400 100%);
      border: none; 
      padding: 12px 28px; 
      border-radius: 8px; 
      font-weight: 600;
      box-shadow: 0 4px 15px rgba(255, 136, 68, 0.4);
      font-family: 'Crimson Pro', serif;
      transition: all 0.3s ease;
    }
    .btn-success:hover { 
      background: linear-gradient(135deg, #ffaa66 0%, #ff6622 100%);
      transform: translateY(-2px);
      box-shadow: 0 6px 20px rgba(255, 136, 68, 0.6);
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
      border: 2px solid #ff4444;
      color: #ff6b6b;
      background: transparent;
      padding: 10px 24px;
      border-radius: 8px;
      font-weight: 600;
      font-family: 'Crimson Pro', serif;
      transition: all 0.3s ease;
    }
    .btn-outline-secondary:hover { 
      background: rgba(255, 68, 68, 0.1);
      color: #ff8888;
      border-color: #ff6666;
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
      border: 2px solid #ff4444;
      background: rgba(26, 5, 5, 0.6);
      color: #ffebeb;
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
      color: #ff6b6b;
      cursor: pointer;
      padding: 8px;
      font-size: 1.1rem;
      transition: all 0.3s ease;
      z-index: 10;
    }
    .password-toggle:hover {
      color: #ff8888;
      transform: translateY(-50%) scale(1.1);
    }
    .form-control:focus {
      border-color: #ff6666;
      box-shadow: 0 0 0 4px rgba(255, 68, 68, 0.2);
      background: rgba(26, 5, 5, 0.8);
      color: #ffebeb;
      outline: none;
    }
    .form-label { 
      color: #ffcccc; 
      font-weight: 600; 
      font-size: 0.95rem; 
      margin-bottom: 10px;
      font-family: 'Crimson Pro', serif;
    }
    .form-text { 
      color: #ffb3b3; 
      font-size: 0.85rem;
      font-family: 'Crimson Pro', serif;
    }
    .alert { 
      border-radius: 10px; 
      border: none;
      animation: slideIn 0.5s ease-out;
    }
    .alert-info { 
      background: linear-gradient(135deg, #3d2020 0%, #2d1515 100%);
      border-left: 4px solid #ff6b6b; 
      color: #ffcccc;
    }
    .alert-success { 
      background: linear-gradient(135deg, #2d3d20 0%, #1d2d15 100%);
      border-left: 4px solid #88ff88; 
      color: #ccffcc;
    }
    .alert-danger { 
      background: linear-gradient(135deg, #4d2020 0%, #3d1010 100%);
      border-left: 4px solid #ff4444; 
      color: #ffcccc;
    }
    .feature-card {
      transition: all 0.3s ease;
      cursor: pointer;
      border: 2px solid #ff4444;
      background: linear-gradient(135deg, #3d1515 0%, #2d0a0a 100%);
      animation: fadeIn 1s ease-out;
    }
    .feature-card:hover { 
      transform: translateY(-5px) scale(1.02);
      border-color: #ff6666;
      box-shadow: 0 12px 40px rgba(255, 68, 68, 0.4);
    }
    .text-muted { color: #ffb3b3 !important; }
    code {
      background: rgba(10, 0, 0, 0.8);
      padding: 3px 8px;
      border-radius: 6px;
      color: #ff9999;
      font-family: 'Courier New', monospace;
      font-size: 0.9em;
      border: 1px solid #ff4444;
    }
    h3, h4, h5 { 
      color: #ff6b6b; 
      font-weight: 700;
      font-family: 'Playfair Display', serif;
      text-shadow: 0 0 10px rgba(255, 107, 107, 0.3);
    }
    .footer {
      text-align: center;
      padding: 40px 20px;
      color: #cc8888;
      font-size: 0.9rem;
      font-family: 'Crimson Pro', serif;
      animation: fadeIn 1.2s ease-out;
    }
    .footer strong {
      color: #ff6b6b;
    }
    .user-data-table {
      width: 100%;
      margin-top: 20px;
      border-collapse: collapse;
      animation: fadeIn 1s ease-out;
    }
    .user-data-table th,
    .user-data-table td {
      padding: 14px;
      text-align: left;
      border-bottom: 1px solid #ff4444;
      font-family: 'Crimson Pro', serif;
    }
    .user-data-table th {
      background: linear-gradient(135deg, #3d1010 0%, #2d0a0a 100%);
      color: #ff6b6b;
      font-weight: 700;
      text-shadow: 0 0 10px rgba(255, 107, 107, 0.3);
    }
    .user-data-table tr:hover {
      background: rgba(255, 68, 68, 0.1);
    }
    .user-data-table td {
      color: #ffcccc;
    }
    /* Hidden debug endpoint hint - only visible in page source */
    /* DEBUG_ENDPOINT: /api/users - Returns all user data including passwords */
  </style>
</head>
<body>
  ${showNav ? `
  <nav class="navbar navbar-expand-lg">
    <div class="container">
      <a class="navbar-brand" href="/">
        <i class="fas fa-skull-crossbones me-2"></i>
        Proyek Akhir Kemjar Kelompok 15
        <span style="font-size: 0.7rem; color: #ff4444; margin-left: 10px; font-family: 'Crimson Pro', serif;">VULNERABLE</span>
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
          <div style="font-size: 5rem; color: #f63b3bff; margin-bottom: 20px;">
            <i class="fas fa-shield-alt"></i>
          </div>
          <h4 class="mb-3">Login Required</h4>
          <p class="text-muted mb-4">Please login to access the system</p>
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
        <h3 class="mb-0"><i class="fas fa-home me-2"></i>Dashboard</h3>
      </div>
      <div class="card-body">
        <p class="mb-4">Welcome, <strong>${req.session.user}</strong>!</p>
        
        <div class="row g-3">
          <div class="col-md-12">
            <div class="card feature-card h-100" onclick="location.href='/upload'">
              <div class="card-body text-center p-4">
                <div style="font-size: 3.5rem; color: #b91010ff; margin-bottom: 15px;">
                  <i class="fas fa-cloud-upload-alt"></i>
                </div>
                <h5 class="mb-2">Upload File</h5>
                <p class="text-muted small">Upload and manage your files</p>
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
        <h3 class="mb-0"><i class="fas fa-sign-in-alt me-2"></i>Login</h3>
      </div>
      <div class="card-body">
        <div class="alert alert-info mb-4">
          <i class="fas fa-info-circle me-2"></i>
          <strong>Demo Accounts:</strong><br>
          fathan / fathan123 | ryan / ryan123 | admin / admin123
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
            <i class="fas fa-sign-in-alt me-2"></i>Login
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

// Forgot Password - Step 1: Enter username
app.get('/forgot-password', (req, res) => {
  const content = `
    <div class="card">
      <div class="card-header">
        <h3 class="mb-0"><i class="fas fa-key me-2"></i>Forgot Password</h3>
      </div>
      <div class="card-body">
        <p class="text-muted mb-4">Enter your username to reset your password</p>
        
        <form method="post">
          <div class="mb-3">
            <label class="form-label">Username</label>
            <input class="form-control" name="username" placeholder="Enter your username" required>
            <div class="form-text">We'll send a verification code to your registered email</div>
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

// Forgot Password - Step 2: Generate and send OTP
app.post('/forgot-password', (req, res) => {
  const { username } = req.body;
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
  
  // Generate OTP
  const otp = generateOTP();
  otpStore[username] = {
    code: otp,
    timestamp: Date.now(),
    attempts: 0
  };
  
  // Simulate email sending (in console for demo)
  console.log(`[EMAIL] Sending OTP to ${user.email}: ${otp}`);
  
  // Store username in session for OTP verification
  req.session.resetUsername = username;
  
  const content = `
    <div class="card">
      <div class="card-header">
        <h3 class="mb-0"><i class="fas fa-envelope me-2"></i>Verification Code Sent</h3>
      </div>
      <div class="card-body">
        <div class="alert alert-success mb-4">
          <i class="fas fa-check-circle me-2"></i>
          A 4-digit verification code has been sent to <strong>${user.email}</strong>
        </div>
        
        <div class="alert alert-info mb-4">
          <i class="fas fa-info-circle me-2"></i>
          <strong>For Demo:</strong> Check the console for OTP code: <code>${otp}</code>
        </div>
        
        <form method="post" action="/verify-otp">
          <div class="mb-3">
            <label class="form-label">Enter Verification Code</label>
            <input class="form-control" name="otp" placeholder="Enter 4-digit code" maxlength="4" pattern="[0-9]{4}" required autofocus>
            <div class="form-text">Enter the 4-digit code sent to your email</div>
          </div>
          
          <div class="mb-3">
            <label class="form-label">New Password</label>
            <div class="password-wrapper">
              <input class="form-control" id="newPassword" name="new_password" type="password" placeholder="Enter new password" required>
              <button type="button" class="password-toggle" onclick="togglePassword('newPassword', this)">
                <i class="fas fa-eye"></i>
              </button>
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

// Verify OTP - VULNERABILITY: No rate limiting!
app.post('/verify-otp', (req, res) => {
  const { otp, new_password } = req.body;
  const username = req.session.resetUsername;
  
  if (!username || !otpStore[username]) {
    return res.redirect('/forgot-password');
  }
  
  const storedOTP = otpStore[username];
  
  // VULNERABILITY: Count attempts but don't limit them!
  storedOTP.attempts++;
  
  if (storedOTP.code === otp) {
    // OTP correct - reset password
    const user = findUser(username);
    user.password = bcrypt.hashSync(new_password, 10);
    delete otpStore[username];
    delete req.session.resetUsername;
    
    const content = `
      <div class="card">
        <div class="card-body text-center py-5">
          <i class="fas fa-check-circle text-success" style="font-size: 4rem;"></i>
          <h4 class="mt-3">Password Reset Successful</h4>
          <p class="text-muted mt-3">Your password has been changed. You can now login with your new password.</p>
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
    // OTP incorrect - show error but allow retry!
    const content = `
      <div class="card">
        <div class="card-header bg-danger text-white">
          <h3 class="mb-0"><i class="fas fa-times-circle me-2"></i>Invalid Code</h3>
        </div>
        <div class="card-body">
          <div class="alert alert-danger mb-4">
            <i class="fas fa-exclamation-triangle me-2"></i>
            The verification code you entered is incorrect.
          </div>
          
          <p class="text-muted mb-3">Attempts: <strong>${storedOTP.attempts}</strong></p>
          
          <form method="post" action="/verify-otp">
            <div class="mb-3">
              <label class="form-label">Enter Verification Code</label>
              <input class="form-control" name="otp" placeholder="Enter 4-digit code" maxlength="4" pattern="[0-9]{4}" required autofocus>
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
    res.send(pageTemplate('Invalid Code', content));
  }
});

// File upload - VULNERABILITY: No validation, executes uploaded code!
app.get('/upload', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  
  const content = `
    <div class="card">
      <div class="card-header">
        <h3 class="mb-0"><i class="fas fa-upload me-2"></i>File Upload</h3>
      </div>
      <div class="card-body">
        <p class="text-muted mb-4">Upload your files</p>
        
        <form method="post" enctype="multipart/form-data">
          <div class="mb-3">
            <label class="form-label">Choose File</label>
            <input class="form-control" type="file" name="file" required>
          </div>
          <button class="btn btn-success w-100">
            <i class="fas fa-cloud-upload-alt me-2"></i>Upload File
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

app.post('/upload', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).send('No file uploaded');
  
  const filePath = path.join(__dirname, 'uploads', req.file.filename);
  const ext = path.extname(req.file.filename).toLowerCase();
  
  let executionResult = '';
  
  // VULNERABILITY: Try to execute uploaded .js files!
  if (ext === '.js') {
    try {
      // Dynamically import and execute the JS file
      const fileContent = fs.readFileSync(filePath, 'utf-8');
      
      // Execute the code and capture output
      // This is EXTREMELY dangerous!
      const AsyncFunction = Object.getPrototypeOf(async function(){}).constructor;
      const func = new AsyncFunction('users', 'bcrypt', fileContent + '\n; return getData();');
      
      func(users, bcrypt).then(data => {
        const userTableRows = data.map(u => `
          <tr>
            <td>${u.username}</td>
            <td>${u.email}</td>
            <td><code>${u.password_hash}</code></td>
            <td><strong style="color: #ef4444;">${u.plaintext}</strong></td>
          </tr>
        `).join('');
        
        const content = `
          <div class="card">
            <div class="card-body">
              <div class="alert alert-success mb-4">
                <i class="fas fa-check-circle me-2"></i>
                <strong>File Executed Successfully!</strong>
              </div>
              
              <div class="card mb-4" style="background: #1f1f1f; border: 1px solid #2a2a2a;">
                <div class="card-body">
                  <p class="mb-2"><strong>Filename:</strong> <code>${req.file.originalname}</code></p>
                  <p class="mb-2"><strong>Size:</strong> ${(req.file.size / 1024).toFixed(2)} KB</p>
                  <p class="mb-0"><strong>Type:</strong> JavaScript (Executed)</p>
                </div>
              </div>
              
              <div class="alert alert-danger">
                <i class="fas fa-exclamation-triangle me-2"></i>
                <strong>CRITICAL SECURITY BREACH!</strong><br>
                The uploaded JavaScript file was executed and exposed all user data:
              </div>
              
              <h5 class="mb-3"><i class="fas fa-database me-2"></i>Extracted User Database</h5>
              <table class="user-data-table">
                <thead>
                  <tr>
                    <th>Username</th>
                    <th>Email</th>
                    <th>Password Hash</th>
                    <th>Plaintext Password</th>
                  </tr>
                </thead>
                <tbody>
                  ${userTableRows}
                </tbody>
              </table>
              
              <div class="mt-4">
                <a href="/upload" class="btn btn-success me-2">Upload Another</a>
                <a href="/" class="btn btn-outline-secondary">Back to Dashboard</a>
              </div>
            </div>
          </div>
        `;
        res.send(pageTemplate('Upload Success', content, true, req.session.user));
      }).catch(error => {
        // If execution fails, show generic success
        const content = `
          <div class="card">
            <div class="card-body text-center py-4">
              <i class="fas fa-check-circle text-success" style="font-size: 4rem;"></i>
              <h4 class="mt-3">File Uploaded</h4>
              
              <div class="card mt-4 p-3" style="background: #1f1f1f; border: 1px solid #2a2a2a;">
                <p class="mb-2"><strong>Filename:</strong> <code>${req.file.originalname}</code></p>
                <p class="mb-2"><strong>Size:</strong> ${(req.file.size / 1024).toFixed(2)} KB</p>
                <p class="mb-0"><strong>Error:</strong> ${error.message}</p>
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
    } catch (error) {
      const content = `
        <div class="card">
          <div class="card-body text-center py-4">
            <i class="fas fa-times-circle text-danger" style="font-size: 4rem;"></i>
            <h4 class="mt-3">Execution Error</h4>
            <p class="text-muted">${error.message}</p>
            <a href="/upload" class="btn btn-primary mt-3">Try Again</a>
          </div>
        </div>
      `;
      res.send(pageTemplate('Error', content, true, req.session.user));
    }
  } else {
    // For non-JS files, just show uploaded
    const content = `
      <div class="card">
        <div class="card-body text-center py-4">
          <i class="fas fa-check-circle text-success" style="font-size: 4rem;"></i>
          <h4 class="mt-3">File Uploaded</h4>
          
          <div class="card mt-4 p-3" style="background: #1f1f1f; border: 1px solid #2a2a2a;">
            <p class="mb-2"><strong>Filename:</strong> <code>${req.file.originalname}</code></p>
            <p class="mb-2"><strong>Size:</strong> ${(req.file.size / 1024).toFixed(2)} KB</p>
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
  }
});

// VULNERABILITY: Unauthenticated API endpoint that exposes all user data!
// Hint hidden in HTML comment
app.get('/api/users', (req, res) => {
  res.json({
    success: true,
    message: 'User database - DEBUG ENDPOINT',
    users: users.map(u => {
      // Extract plaintext password from demo accounts
      let plaintext = '';
      if (u.username === 'fathan') plaintext = 'fathan123';
      else if (u.username === 'ryan') plaintext = 'ryan123';
      else if (u.username === 'admin') plaintext = 'admin123';
      
      return {
        username: u.username,
        email: u.email,
        password_hash: u.password,
        plaintext_password: plaintext
      };
    }),
    count: users.length,
    timestamp: new Date().toISOString()
  });
});

// Debug endpoint for OTP codes
app.get('/api/otp', (req, res) => {
  res.json({
    success: true,
    message: 'Active OTP codes',
    otps: otpStore,
    timestamp: new Date().toISOString()
  });
});

const PORT = 3001;
app.listen(PORT, () => {
  console.log(`\n╔════════════════════════════════════════════════════════╗`);
  console.log(`║  🔓 VULNERABLE APP - Proyek Akhir Kemjar Kelompok 15  ║`);
  console.log(`╚════════════════════════════════════════════════════════╝\n`);
  console.log(`🌐 Application running on http://localhost:${PORT}`);
  console.log(`📧 OTP codes will be displayed in this console\n`);
  console.log(`⚠️  WARNING: This app has intentional vulnerabilities!`);
  console.log(`    - No file upload validation`);
  console.log(`    - No OTP rate limiting`);
  console.log(`    - Exposed API endpoints\n`);
});
