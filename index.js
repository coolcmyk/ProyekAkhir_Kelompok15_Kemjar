import express from 'express';
import session from 'express-session';
import multer from 'multer';
import bcrypt from 'bcryptjs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const upload = multer({ dest: 'uploads/' });
const ALLOWED_EXTENSIONS = ['.png', '.jpg', '.jpeg', '.gif'];
const ALLOWED_MIME = ['image/png', 'image/jpeg', 'image/gif'];

app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: 'kemjar', resave: false, saveUninitialized: true }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Dummy user DB (pre-hashed passwords)
const users = [
  { username: 'alice', password: bcrypt.hashSync('alice123', 10) },
  { username: 'bob', password: bcrypt.hashSync('bob123', 10) }
];

function findUser(username) {
  return users.find(u => u.username === username);
}

app.get('/', (req, res) => {
  if (!req.session.user) return res.send(`
    <html><head><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css"></head><body class="container py-5">
    <div class="text-center"><h2>Welcome to Kemjar ProyekAkhir_15</h2><a class="btn btn-primary" href="/login">Login</a></div>
    </body></html>
  `);
  res.send(`
    <html><head><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css"></head><body class="container py-5">
    <div class="mb-3">Hello, <b>${req.session.user}</b>!</div>
    <a class="btn btn-success me-2" href="/upload">Upload File</a>
    <a class="btn btn-warning me-2" href="/change-password">Change Password</a>
    <a class="btn btn-danger" href="/logout">Logout</a>
    </body></html>
  `);
});

app.get('/login', (req, res) => {
  res.send(`
    <html><head><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css"></head><body class="container py-5">
    <h3>Login</h3>
    <form method="post" class="w-25 mx-auto">
      <div class="mb-3"><input class="form-control" name="username" placeholder="Username" required></div>
      <div class="mb-3"><input class="form-control" name="password" type="password" placeholder="Password" required></div>
      <button class="btn btn-primary w-100">Login</button>
    </form>
    </body></html>
  `);
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = findUser(username);
  if (user && bcrypt.compareSync(password, user.password)) {
    req.session.user = username;
    res.redirect('/');
  } else {
    res.send(`
      <html><head><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css"></head><body class="container py-5">
      <div class="alert alert-danger">Login failed</div>
      <a href="/login" class="btn btn-secondary">Try Again</a>
      </body></html>
    `);
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// Insecure file upload (no type check)
app.get('/upload', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.send(`
    <html><head><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css"></head><body class="container py-5">
    <h3>Upload File</h3>
    <form method="post" enctype="multipart/form-data" class="w-50 mx-auto">
      <div class="mb-3"><input class="form-control" type="file" name="file" required></div>
      <button class="btn btn-success w-100">Upload</button>
    </form>
    <a href="/" class="btn btn-link mt-3">Back</a>
    </body></html>
  `);
});
app.post('/upload', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).send('No file uploaded');
  const ext = path.extname(req.file.originalname).toLowerCase();
  if (!ALLOWED_EXTENSIONS.includes(ext) || !ALLOWED_MIME.includes(req.file.mimetype)) {
    return res.status(400).send(`
      <html><head><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css"></head><body class="container py-5">
      <div class="alert alert-danger">File type not allowed</div>
      <a href="/upload" class="btn btn-secondary">Try Again</a>
      </body></html>
    `);
  }
  res.send(`
    <html><head><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css"></head><body class="container py-5">
    <div class="alert alert-success">File uploaded: <a href="/uploads/${req.file.filename}" target="_blank">${req.file.originalname}</a></div>
    <a href="/upload" class="btn btn-secondary">Upload Another</a>
    <a href="/" class="btn btn-link">Back</a>
    </body></html>
  `);
});

// Insecure change password (no old password check)
app.get('/change-password', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.send(`
    <html><head><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css"></head><body class="container py-5">
    <h3>Change Password</h3>
    <form method="post" class="w-50 mx-auto">
      <div class="mb-3"><input class="form-control" name="old_password" type="password" placeholder="Current Password" required></div>
      <div class="mb-3"><input class="form-control" name="new_password" type="password" placeholder="New Password" required></div>
      <button class="btn btn-warning w-100">Change</button>
    </form>
    <a href="/" class="btn btn-link mt-3">Back</a>
    </body></html>
  `);
});
app.post('/change-password', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const user = findUser(req.session.user);
  if (!bcrypt.compareSync(req.body.old_password, user.password)) {
    return res.send(`
      <html><head><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css"></head><body class="container py-5">
      <div class="alert alert-danger">Incorrect current password</div>
      <a href="/change-password" class="btn btn-secondary">Try Again</a>
      </body></html>
    `);
  }
  user.password = bcrypt.hashSync(req.body.new_password, 10);
  res.send(`
    <html><head><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css"></head><body class="container py-5">
    <div class="alert alert-success">Password changed!</div>
    <a href="/" class="btn btn-link">Back</a>
    </body></html>
  `);
});

app.listen(3000, () => console.log('Vulnerable app running on http://localhost:3000'));
