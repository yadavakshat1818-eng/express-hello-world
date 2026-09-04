index.js
const express = require('express');
const cors = require('cors');
const { OpenAI } = require('openai');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

const app = express();
app.set('trust proxy', 1);
app.use(cors());
app.use(express.json());

// ========== ENVIRONMENT VARIABLES ==========
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
if (!ENCRYPTION_KEY) throw new Error('ENCRYPTION_KEY required');

const SUPABASE_URL = process.env.SUPABASE_URL;
if (!SUPABASE_URL) throw new Error('SUPABASE_URL required');

const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
if (!SUPABASE_SERVICE_ROLE_KEY) throw new Error('SUPABASE_SERVICE_ROLE_KEY required');

const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const PORT = process.env.PORT || 3000;

// ========== INIT ==========
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
const openai = OPENAI_API_KEY ? new OpenAI({ apiKey: OPENAI_API_KEY }) : null;

// ========== RATE LIMITERS ==========
const signupLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many signup attempts. Try again in 15 minutes.'
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many login attempts. Try again in 15 minutes.'
});

// ========== AUTH ==========
async function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  
  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('id, email, api_token, token_expires_at')
      .eq('api_token', token)
      .single();
    
    if (error || !user) return res.status(401).json({ error: 'Invalid token' });
    if (user.token_expires_at && new Date(user.token_expires_at) < new Date()) {
      return res.status(401).json({ error: 'Token expired' });
    }
    
    req.userId = user.id;
    req.userEmail = user.email;
    next();
  } catch(e) {
    res.status(401).json({ error: 'Auth failed' });
  }
}

// ========== ROUTES ==========
app.post('/api/signup', signupLimiter, async (req, res) => {
  try {
    const { email, password, company } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    
    const { data: existing } = await supabase
      .from('users')
      .select('email')
      .eq('email', email)
      .maybeSingle();
    
    if (existing) return res.status(400).json({ error: 'Email already exists' });
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const token = crypto.randomBytes(32).toString('hex');
    const tokenExpiresAt = new Date();
    tokenExpiresAt.setDate(tokenExpiresAt.getDate() + 30);
    
    const { data, error } = await supabase
      .from('users')
      .insert([{ email, password: hashedPassword, company, api_token: token, token_expires_at: tokenExpiresAt.toISOString() }])
      .select();
    
    if (error) throw error;
    res.json({ token, user: { id: data[0].id, email: data[0].email, company: data[0].company } });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();
    
    if (error || !user) return res.status(401).json({ error: 'Invalid credentials' });
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });
    
    const token = crypto.randomBytes(32).toString('hex');
    const tokenExpiresAt = new Date();
    tokenExpiresAt.setDate(tokenExpiresAt.getDate() + 30);
    
    await supabase
      .from('users')
      .update({ api_token: token, token_expires_at: tokenExpiresAt.toISOString() })
      .eq('id', user.id);
    
    res.json({ token, user: { id: user.id, email: user.email, company: user.company } });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/logout', authMiddleware, async (req, res) => {
  await supabase.from('users').update({ api_token: null, token_expires_at: null }).eq('id', req.userId);
  res.json({ success: true });
});

app.get('/api/dashboard', authMiddleware, async (req, res) => {
  const { data } = await supabase.from('customers').select('*').eq('user_id', req.userId);
  const total = data?.length || 0;
  const atRisk = data?.filter(c => (c.risk || 0) > 70).length || 0;
  res.json({ total, atRisk, saved: atRisk * 99, riskPct: total ? Math.round((atRisk/total)*100) : 0 });
});

app.get('/api/customers', authMiddleware, async (req, res) => {
  const { data } = await supabase.from('customers').select('*').eq('user_id', req.userId).order('created_at', { ascending: false });
  res.json(data || []);
});

app.post('/api/demo-import', authMiddleware, async (req, res) => {
  const sampleCustomers = [
    { name: 'Acme Corp', email: 'billing@acme.com', risk: 20, last_login: '2 days ago' },
    { name: 'TechStart Inc', email: 'finance@techstart.com', risk: 85, last_login: '30 days ago' },
    { name: 'GrowthLabs', email: 'team@growthlabs.com', risk: 45, last_login: '10 days ago' },
    { name: 'CloudSync', email: 'admin@cloudsync.io', risk: 92, last_login: '45 days ago' },
  ];
  
  let imported = 0;
  for (const c of sampleCustomers) {
    const { data: existing } = await supabase
      .from('customers')
      .select('id')
      .eq('user_id', req.userId)
      .eq('email', c.email)
      .maybeSingle();
    
    if (existing) {
      await supabase.from('customers').update(c).eq('id', existing.id).eq('user_id', req.userId);
    } else {
      await supabase.from('customers').insert({ user_id: req.userId, ...c });
    }
    imported++;
  }
  res.json({ success: true, count: imported });
});

// ========== FRONTEND ==========
app.get('/', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html>
<head><title>RetentionGuard</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; font-family:system-ui; }
body { background:#0f0f1a; color:white; padding:2rem; }
.container { max-width:1200px; margin:0 auto; }
h1 { color:#6c63ff; }
.card { background:#1a1a2e; padding:1.5rem; border-radius:16px; border:1px solid #2a2a4a; margin:1rem 0; }
input { width:100%; padding:0.8rem; background:#1a1a2e; border:1px solid #2a2a4a; color:white; border-radius:8px; margin:0.5rem 0; }
button { background:#6c63ff; color:white; border:none; padding:0.8rem 2rem; border-radius:8px; cursor:pointer; }
button:hover { background:#7b73ff; }
.stats { display:grid; grid-template-columns:repeat(4,1fr); gap:1rem; }
.stat { background:#1a1a2e; padding:1.5rem; border-radius:16px; border:1px solid #2a2a4a; text-align:center; }
.stat h3 { color:#888; font-size:0.9rem; }
.stat p { font-size:2rem; font-weight:bold; color:#6c63ff; }
.nav a { color:#aaa; text-decoration:none; padding:0.5rem 1rem; border-radius:8px; cursor:pointer; }
.nav a:hover { background:#6c63ff; color:white; }
.page { display:none; }
.page.active { display:block; }
.login-box { max-width:400px; margin:2rem auto; }
.error { color:#ff4757; }
</style>
</head>
<body>
<div class="container">
  <h1>🛡️ RetentionGuard</h1>
  <div id="loginScreen">
    <div class="login-box card">
      <h2 id="authTitle">Login</h2>
      <input type="email" id="loginEmail" placeholder="Email" />
      <input type="password" id="loginPassword" placeholder="Password" />
      <input type="text" id="loginCompany" placeholder="Company Name" style="display:none;" />
      <button onclick="handleAuth()" id="authBtn">Login</button>
      <p><span id="toggleAuthText">Don't have an account?</span> <a onclick="toggleAuthMode()" style="color:#6c63ff;cursor:pointer;">Sign up</a></p>
      <div id="loginError" class="error"></div>
    </div>
  </div>
  <div id="mainApp" style="display:none;">
    <div class="nav">
      <a onclick="showPage('dashboard')">Dashboard</a>
      <a onclick="showPage('customers')">Customers</a>
      <a onclick="showPage('integrations')">Integrations</a>
    </div>
    <div id="dashboard" class="page active">
      <div class="stats">
        <div class="stat"><h3>Total Customers</h3><p id="total">0</p></div>
        <div class="stat"><h3>At Risk</h3><p id="atRisk">0</p></div>
        <div class="stat"><h3>Revenue Saved</h3><p id="saved">$0</p></div>
        <div class="stat"><h3>Risk %</h3><p id="riskPct">0%</p></div>
      </div>
    </div>
    <div id="customers" class="page"><div id="customerList" class="card">No customers yet.</div></div>
    <div id="integrations" class="page">
      <div class="card">
        <h3>Import Demo Data</h3>
        <button onclick="importDemo()">Import Sample Customers</button>
        <div id="importStatus"></div>
      </div>
    </div>
  </div>
</div>
<script>
const API = window.location.origin;
let token = localStorage.getItem('token');
let isLoginMode = true;

function toggleAuthMode() {
  isLoginMode = !isLoginMode;
  document.getElementById('authTitle').textContent = isLoginMode ? 'Login' : 'Sign Up';
  document.getElementById('authBtn').textContent = isLoginMode ? 'Login' : 'Sign Up';
  document.getElementById('toggleAuthText').textContent = isLoginMode ? "Don't have an account?" : 'Already have an account?';
  document.getElementById('loginCompany').style.display = isLoginMode ? 'none' : 'block';
}

async function handleAuth() {
  const email = document.getElementById('loginEmail').value;
  const password = document.getElementById('loginPassword').value;
  const company = document.getElementById('loginCompany').value;
  if (!email || !password) { document.getElementById('loginError').textContent = 'Email and password required'; return; }
  const endpoint = isLoginMode ? '/api/login' : '/api/signup';
  const body = isLoginMode ? { email, password } : { email, password, company };
  try {
    const res = await fetch(API + endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const data = await res.json();
    if (data.error) { document.getElementById('loginError').textContent = data.error; return; }
    localStorage.setItem('token', data.token);
    token = data.token;
    document.getElementById('loginScreen').style.display = 'none';
    document.getElementById('mainApp').style.display = 'block';
    loadDashboard();
    loadCustomers();
  } catch(e) { document.getElementById('loginError').textContent = 'Error: ' + e.message; }
}

async function logout() {
  if (token) { await fetch(API + '/api/logout', { method: 'POST', headers: { 'Authorization': 'Bearer ' + token } }); }
  localStorage.removeItem('token');
  token = null;
  document.getElementById('loginScreen').style.display = 'block';
  document.getElementById('mainApp').style.display = 'none';
}

function showPage(id) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  if (id === 'dashboard') loadDashboard();
  if (id === 'customers') loadCustomers();
}

async function loadDashboard() {
  try {
    const res = await fetch(API + '/api/dashboard', { headers: { 'Authorization': 'Bearer ' + token } });
    const data = await res.json();
    document.getElementById('total').textContent = data.total || 0;
    document.getElementById('atRisk').textContent = data.atRisk || 0;
    document.getElementById('saved').textContent = '$' + (data.saved || 0);
    document.getElementById('riskPct').textContent = (data.riskPct || 0) + '%';
  } catch(e) { if (e.message === 'Unauthorized') logout(); }
}

async function loadCustomers() {
  try {
    const res = await fetch(API + '/api/customers', { headers: { 'Authorization': 'Bearer ' + token } });
    const customers = await res.json();
    const list = document.getElementById('customerList');
    if (!customers || !customers.length) { list.innerHTML = '<p>No customers. Import demo data!</p>'; return; }
    list.innerHTML = customers.map(c => \`<div class="card">\${c.name} - \${c.email} (Risk: \${c.risk}%)</div>\`).join('');
  } catch(e) { console.error(e); }
}

async function importDemo() {
  document.getElementById('importStatus').textContent = 'Importing...';
  try {
    const res = await fetch(API + '/api/demo-import', { method: 'POST', headers: { 'Authorization': 'Bearer ' + token } });
    const data = await res.json();
    document.getElementById('importStatus').textContent = '✅ Imported ' + data.count + ' customers!';
    loadDashboard();
    loadCustomers();
  } catch(e) { document.getElementById('importStatus').textContent = '❌ Error: ' + e.message; }
}

if (token) {
  document.getElementById('loginScreen').style.display = 'none';
  document.getElementById('mainApp').style.display = 'block';
  loadDashboard();
  loadCustomers();
}
</script>
</body>
</html>
  `);
});

// ========== START ==========
app.listen(PORT, () => console.log(`✅ RetentionGuard running on port ${PORT}`));
