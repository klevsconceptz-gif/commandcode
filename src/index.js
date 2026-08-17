import { Hono } from 'hono';
import { cors } from 'hono/cors';
import bcrypt from 'bcryptjs';

const app = new Hono();
app.use('/*', cors({ origin: '*', allowMethods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'], allowHeaders: ['Content-Type','Authorization'] }));

// --- Helpers ---
// Simple JWT implementation for Workers runtime
const JWT_SECRET_STR = 'quantum-spacex-jwt-secret-key-2024-production';

function base64url(str) {
  return btoa(str).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}

async function hmacSign(data) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(JWT_SECRET_STR), {name:'HMAC', hash:'SHA-256'}, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return base64url(String.fromCharCode.apply(null, new Uint8Array(sig)));
}

async function signToken(payload, env) {
  const p = Object.assign({}, payload, {exp: Math.floor(Date.now()/1000) + 86400});
  const header = base64url(JSON.stringify({alg:'HS256',typ:'JWT'}));
  const body = base64url(JSON.stringify(p));
  const sig = await hmacSign(header + '.' + body);
  return header + '.' + body + '.' + sig;
}

async function verifyToken(token, env) {
  var parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid token format');
  var sig = await hmacSign(parts[0] + '.' + parts[1]);
  if (sig !== parts[2]) throw new Error('Invalid signature');
  var payload = JSON.parse(atob(parts[1].replace(/-/g,'+').replace(/_/g,'/')));
  if (payload.exp && payload.exp < Math.floor(Date.now()/1000)) throw new Error('Token expired');
  return payload;
}

function getInvestmentStage(totalDeposit) {
  if (totalDeposit >= 100000) return 'Stage 4';
  if (totalDeposit >= 10000) return 'Stage 3';
  if (totalDeposit >= 1000) return 'Stage 2';
  return 'Stage 1';
}
function getStageROI(stage) {
  if (stage === 'Stage 4') return 70;
  if (stage === 'Stage 3') return 80;
  if (stage === 'Stage 2') return 90;
  return 100;
}
function genRef() { return 'QS-' + Math.random().toString(36).substr(2, 5).toUpperCase(); }
function now() { return new Date().toISOString(); }

// --- Auth Middleware ---
const authMiddleware = async (c, next) => {
  const auth = c.req.header('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) return c.json({error:'Unauthorized'}, 401);
  try {
    const payload = await verifyToken(auth.slice(7), c.env);
    const db = c.env.DB;
    const user = await db.prepare('SELECT id,username,email,phone,full_name,balance,total_deposit,total_profit,investment_plan,is_active,is_admin FROM users WHERE id=?').bind(payload.userId).first();
    if (!user || !user.is_active) return c.json({error:'Account inactive'}, 403);
    c.set('user', user);
    await next();
  } catch(e) { return c.json({error:'Invalid token'}, 401); }
};

const adminMiddleware = async (c, next) => {
  const auth = c.req.header('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) return c.json({error:'Unauthorized'}, 401);
  try {
    const payload = await verifyToken(auth.slice(7), c.env);
    const db = c.env.DB;
    const user = await db.prepare('SELECT id,username,email,phone,full_name,balance,total_deposit,total_profit,investment_plan,is_active,is_admin FROM users WHERE id=?').bind(payload.userId).first();
    if (!user || !user.is_active) return c.json({error:'Account inactive'}, 403);
    if (!user.is_admin) return c.json({error:'Admin access required'}, 403);
    c.set('user', user);
    await next();
  } catch(e) { return c.json({error:'Invalid token'}, 401); }
};

// --- Static Asset Serving ---
// Static assets are served automatically by Workers Sites [site] config
// No manual static serving needed - the platform handles it before the worker runs

// ===================== PUBLIC ROUTES =====================

app.get('/api/health', c => c.json({status:'ok',service:'Quantum Space X',version:'1.0.0',timestamp:now()}));

app.get('/api/investment-stages', c => c.json([
  {stage:'Stage 1',min:100,max:1000,roi:100},
  {stage:'Stage 2',min:1000,max:10000,roi:90},
  {stage:'Stage 3',min:10000,max:100000,roi:80},
  {stage:'Stage 4',min:100000,max:1000000,roi:70}
]));

app.get('/api/payment-methods', async c => {
  const methods = await c.env.DB.prepare('SELECT method,display_name,logo,details FROM payment_settings WHERE is_active=1').all();
  return c.json(methods.results.map(m => ({...m, details: JSON.parse(m.details||'[]')})));
});

app.get('/api/announcements', async c => {
  const anns = await c.env.DB.prepare('SELECT id,title,message,type FROM announcements WHERE is_active=1 ORDER BY created_at DESC').all();
  return c.json(anns.results);
});

app.post('/api/support/ticket', async c => {
  const {user_id, subject, message} = await c.req.json();
  if (!subject || !message) return c.json({error:'Subject and message required'}, 400);
  const r = await c.env.DB.prepare('INSERT INTO support_tickets (user_id,subject,message) VALUES (?,?,?)').bind(user_id||0, subject, message).run();
  return c.json({id:r.meta.last_row_id, message:'Ticket submitted'}, 201);
});

app.post('/api/shop/order', async c => {
  const data = await c.req.json();
  if (!data.product_name || !data.product_price) return c.json({error:'Product info required'}, 400);
  const ref = genRef();
  const r = await c.env.DB.prepare('INSERT INTO product_orders (user_id,product_name,product_price,quantity,payment_method,shipping_address,status,reference) VALUES (?,?,?,?,?,?,?,?)').bind(data.user_id||0, data.product_name, data.product_price, data.quantity||1, data.payment_method||'', data.shipping_address||'', 'pending', ref).run();
  return c.json({id:r.meta.last_row_id, reference:ref, message:'Order placed'}, 201);
});

// ===================== AUTH ROUTES =====================

app.post('/api/auth/register', async c => {
  const {username, email, phone, full_name, password, confirm_password, reset_phrase} = await c.req.json();
  if (!username||!email||!phone||!full_name||!password||!reset_phrase) return c.json({error:'All fields required'}, 400);
  if (password.length < 8) return c.json({error:'Password must be 8+ chars'}, 400);
  if (reset_phrase.length < 4) return c.json({error:'Reset phrase must be 4+ chars'}, 400);
  if (password !== confirm_password) return c.json({error:'Passwords do not match'}, 400);
  if (!/^[a-zA-Z0-9_]{3,30}$/.test(username)) return c.json({error:'Invalid username'}, 400);
  const db = c.env.DB;
  const existing = await db.prepare('SELECT id FROM users WHERE username=? OR email=? OR phone=?').bind(username, email, phone).first();
  if (existing) return c.json({error:'Username, email, or phone already exists'}, 400);
  const pwHash = bcrypt.hashSync(password, 12);
  const rpHash = bcrypt.hashSync(reset_phrase.trim().toLowerCase(), 12);
  try {
    const r = await db.prepare('INSERT INTO users (username,email,phone,full_name,password_hash,reset_phrase_hash) VALUES (?,?,?,?,?,?)').bind(username, email, phone, full_name, pwHash, rpHash).run();
    const userId = r.meta.last_row_id;
    await db.prepare('INSERT INTO user_wallets (user_id) VALUES (?)').bind(userId).run();
    const token = await signToken({userId, isAdmin:false}, c.env);
    return c.json({token, user:{id:userId, username, email, full_name, isAdmin:false, investment_plan:'Stage 1', balance:0, total_deposit:0}}, 201);
  } catch(e) { return c.json({error:'Registration failed: '+e.message}, 400); }
});

app.post('/api/auth/login', async c => {
  const {identifier, password} = await c.req.json();
  if (!identifier || !password) return c.json({error:'Identifier and password required'}, 400);
  const db = c.env.DB;
  const user = await db.prepare('SELECT * FROM users WHERE username=? OR email=? OR phone=?').bind(identifier, identifier, identifier).first();
  if (!user) return c.json({error:'Invalid credentials'}, 401);
  if (!user.is_active) return c.json({error:'Account deactivated'}, 403);
  if (user.locked_until && new Date(user.locked_until) > new Date()) return c.json({error:`Account locked until ${user.locked_until}`}, 403);
  if (!bcrypt.compareSync(password, user.password_hash)) {
    const attempts = (user.login_attempts||0) + 1;
    if (attempts >= 5) { const lockUntil = new Date(Date.now()+30*60000).toISOString(); await db.prepare('UPDATE users SET login_attempts=?, locked_until=? WHERE id=?').bind(attempts, lockUntil, user.id).run(); return c.json({error:'Account locked for 30 minutes'}, 403); }
    await db.prepare('UPDATE users SET login_attempts=? WHERE id=?').bind(attempts, user.id).run();
    return c.json({error:'Invalid credentials'}, 401);
  }
  await db.prepare('UPDATE users SET login_attempts=0, locked_until=NULL, last_login=? WHERE id=?').bind(now(), user.id).run();
  const token = await signToken({userId:user.id, isAdmin:user.is_admin}, c.env);
  return c.json({token, user:{id:user.id, username:user.username, email:user.email, full_name:user.full_name, isAdmin:Boolean(user.is_admin), investment_plan:user.investment_plan, balance:user.balance, total_deposit:user.total_deposit}});
});

app.post('/api/auth/logout', c => c.json({message:'Logged out'}));

app.post('/api/auth/forgot-password/verify', async c => {
  const {identifier} = await c.req.json();
  if (!identifier) return c.json({error:'Identifier required'}, 400);
  const user = await c.env.DB.prepare('SELECT id,email FROM users WHERE username=? OR email=? OR phone=?').bind(identifier, identifier, identifier).first();
  if (!user) return c.json({error:'Account not found'}, 404);
  const masked = user.email.replace(/(.{2})(.*)(@.*)/, '$1***$3');
  return c.json({userId:user.id, email:masked, message:'Identity verified'});
});

app.post('/api/auth/forgot-password/reset', async c => {
  const {user_id, reset_phrase, new_password} = await c.req.json();
  if (!user_id||!reset_phrase||!new_password) return c.json({error:'All fields required'}, 400);
  const user = await c.env.DB.prepare('SELECT id,password_hash,reset_phrase_hash FROM users WHERE id=?').bind(user_id).first();
  if (!user) return c.json({error:'User not found'}, 404);
  if (!bcrypt.compareSync(reset_phrase.trim().toLowerCase(), user.reset_phrase_hash)) return c.json({error:'Invalid reset phrase'}, 401);
  const hash = bcrypt.hashSync(new_password, 12);
  await c.env.DB.prepare('UPDATE users SET password_hash=?, login_attempts=0, locked_until=NULL WHERE id=?').bind(hash, user_id).run();
  return c.json({message:'Password reset successfully'});
});

app.post('/api/auth/change-password', authMiddleware, async c => {
  const {current_password, new_password} = await c.req.json();
  if (!current_password || !new_password) return c.json({error:'Both passwords required'}, 400);
  if (new_password.length < 8) return c.json({error:'New password must be 8+ chars'}, 400);
  const user = c.get('user');
  const full = await c.env.DB.prepare('SELECT password_hash FROM users WHERE id=?').bind(user.id).first();
  if (!bcrypt.compareSync(current_password, full.password_hash)) return c.json({error:'Current password incorrect'}, 401);
  const hash = bcrypt.hashSync(new_password, 12);
  await c.env.DB.prepare('UPDATE users SET password_hash=? WHERE id=?').bind(hash, user.id).run();
  return c.json({message:'Password changed'});
});

// ===================== USER ROUTES =====================

app.get('/api/user/profile', authMiddleware, async c => {
  const u = c.get('user');
  return c.json({id:u.id, username:u.username, email:u.email, phone:u.phone, full_name:u.full_name, balance:u.balance, total_deposit:u.total_deposit, total_profit:u.total_profit, investment_plan:u.investment_plan, is_active:u.is_active, isAdmin:u.is_admin});
});

app.get('/api/user/transactions', authMiddleware, async c => {
  const txs = await c.env.DB.prepare('SELECT * FROM transactions WHERE user_id=? ORDER BY created_at DESC LIMIT 100').bind(c.get('user').id).all();
  return c.json(txs.results);
});

app.get('/api/user/stage', authMiddleware, c => {
  const u = c.get('user');
  return c.json({stage:u.investment_plan, roi:getStageROI(u.investment_plan), totalDeposit:u.total_deposit});
});

app.post('/api/user/deposit', authMiddleware, async c => {
  const data = await c.req.json();
  const amount = Number(data.amount);
  const payment_method = data.payment_method;
  const u = c.get('user');
  if (!amount || isNaN(amount) || amount < 100 || amount > 1000000) return c.json({error:'Amount must be $100-$1,000,000'}, 400);
  const methodRow = await c.env.DB.prepare("SELECT method, details FROM payment_settings WHERE method=? AND is_active=1").bind(payment_method).first();
  if (!methodRow) return c.json({error:'Invalid payment method'}, 400);
  const ref = genRef();
  const r = await c.env.DB.prepare('INSERT INTO transactions (user_id,type,amount,status,payment_method,reference,description) VALUES (?,?,?,?,?,?,?)').bind(u.id,'deposit',amount,'pending',payment_method,ref,'Deposit request').run();
  // For non-Bitcoin methods with no details, send inbox message telling user admin will provide payment info
  if (payment_method !== 'bitcoin') {
    let details = [];
    try { details = JSON.parse(methodRow.details || '[]'); } catch(e) {}
    if (!details.length) {
      try {
        await c.env.DB.prepare('INSERT INTO user_messages (user_id,title,body,type,from_admin,reference) VALUES (?,?,?,?,?,?)').bind(u.id,
          '📩 Payment Details Pending',
          'Your deposit of $' + amount.toFixed(2) + ' via ' + payment_method + ' has been submitted (Ref: ' + ref + '). Admin will provide payment details shortly. Please check back or wait for a follow-up message.',
          'deposit', 1, ref
        ).run();
      } catch(e) {}
    }
  }
  return c.json({id:r.meta.last_row_id, reference:ref, message:'Deposit submitted — await admin approval'});
});

app.post('/api/user/withdraw', authMiddleware, async c => {
  const data = await c.req.json();
  const amount = Number(data.amount);
  const payment_method = data.payment_method || '';
  const wallet_address = data.wallet_address || '';
  const u = c.get('user');
  if (!amount || isNaN(amount) || amount <= 0) return c.json({error:'Invalid amount'}, 400);
  if (amount > (u.balance || 0)) return c.json({error:'Insufficient balance. Your balance: $' + (u.balance||0).toFixed(2)}, 400);
  const ref = genRef();
  const r = await c.env.DB.prepare('INSERT INTO transactions (user_id,type,amount,status,payment_method,wallet_address,reference,description) VALUES (?,?,?,?,?,?,?,?)').bind(u.id,'withdrawal',amount,'pending',payment_method||'',wallet_address||'',ref,'Withdrawal request').run();
  return c.json({id:r.meta.last_row_id, reference:ref, message:'Withdrawal submitted — await admin approval'});
});

app.get('/api/user/wallet', authMiddleware, async c => {
  const u = c.get('user');
  let wallet = await c.env.DB.prepare('SELECT * FROM user_wallets WHERE user_id=?').bind(u.id).first();
  if (!wallet) { await c.env.DB.prepare('INSERT INTO user_wallets (user_id) VALUES (?)').bind(u.id).run(); wallet = {user_id:u.id, deposit_balance:0, roi_balance:0, bonus_balance:0, total_roi_earned:0, last_roi_at:null}; }
  return c.json({...wallet, stage:u.investment_plan, roi:getStageROI(u.investment_plan)});
});

// ===================== USER INBOX / MESSAGES =====================

app.get('/api/user/messages', authMiddleware, async c => {
  const u = c.get('user');
  const msgs = await c.env.DB.prepare('SELECT id,title,body,type,is_read,from_admin,sender_id,parent_id,reference,created_at FROM user_messages WHERE user_id=? ORDER BY created_at DESC LIMIT 50').bind(u.id).all();
  return c.json(msgs.results);
});

// User sends message to admin
app.post('/api/user/messages', authMiddleware, async c => {
  const u = c.get('user');
  const {title, body, parent_id} = await c.req.json();
  if (!title || !body) return c.json({error:'Title and body required'}, 400);
  if (title.length > 200) return c.json({error:'Title too long (max 200 chars)'}, 400);
  if (body.length > 5000) return c.json({error:'Message too long (max 5000 chars)'}, 400);
  const r = await c.env.DB.prepare('INSERT INTO user_messages (user_id,title,body,type,from_admin,sender_id,parent_id) VALUES (?,?,?,?,0,?,?)').bind(u.id, title, body, 'chat', u.id, parent_id||null).run();
  return c.json({id:r.meta.last_row_id, message:'Message sent to admin'}, 201);
});

app.get('/api/user/messages/unread-count', authMiddleware, async c => {
  const u = c.get('user');
  const r = await c.env.DB.prepare('SELECT COUNT(*) as c FROM user_messages WHERE user_id=? AND is_read=0').bind(u.id).first();
  return c.json({count: r.c});
});

app.post('/api/user/messages/:id/read', authMiddleware, async c => {
  const u = c.get('user');
  await c.env.DB.prepare('UPDATE user_messages SET is_read=1 WHERE id=? AND user_id=?').bind(c.req.param('id'), u.id).run();
  return c.json({message:'Marked as read'});
});

app.post('/api/user/messages/mark-all-read', authMiddleware, async c => {
  const u = c.get('user');
  await c.env.DB.prepare('UPDATE user_messages SET is_read=1 WHERE user_id=? AND is_read=0').bind(u.id).run();
  return c.json({message:'All marked as read'});
});

app.delete('/api/user/messages/:id', authMiddleware, async c => {
  const u = c.get('user');
  await c.env.DB.prepare('DELETE FROM user_messages WHERE id=? AND user_id=?').bind(c.req.param('id'), u.id).run();
  return c.json({message:'Message deleted'});
});

// ===================== ADMIN ROUTES =====================

// Admin send message to user
app.post('/api/admin/user/:id/message', adminMiddleware, async c => {
  const {title, body, type} = await c.req.json();
  if (!title || !body) return c.json({error:'Title and body required'}, 400);
  const userId = c.req.param('id');
  const admin = c.get('user');
  const r = await c.env.DB.prepare('INSERT INTO user_messages (user_id,title,body,type,from_admin,sender_id) VALUES (?,?,?,?,1,?)').bind(userId, title, body, type||'info', admin.id).run();
  return c.json({id:r.meta.last_row_id, message:'Message sent'}, 201);
});

// Admin view all messages for a user (conversation)
app.get('/api/admin/user/:id/messages', adminMiddleware, async c => {
  const msgs = await c.env.DB.prepare('SELECT id,title,body,type,is_read,from_admin,sender_id,parent_id,reference,created_at FROM user_messages WHERE user_id=? ORDER BY created_at DESC LIMIT 100').bind(c.req.param('id')).all();
  return c.json(msgs.results);
});

// Admin: list all conversations (grouped by user, latest message per user)
app.get('/api/admin/messages', adminMiddleware, async c => {
  const db = c.env.DB;
  const conversations = await db.prepare(
    "SELECT m.user_id, u.username, u.email, m.title, m.body, m.from_admin, m.is_read, m.type, m.created_at, " +
    "(SELECT COUNT(*) FROM user_messages WHERE user_id=m.user_id AND is_read=0 AND from_admin=0) as unread_from_user, " +
    "(SELECT COUNT(*) FROM user_messages WHERE user_id=m.user_id) as total_messages " +
    "FROM user_messages m " +
    "JOIN users u ON u.id = m.user_id " +
    "WHERE m.id IN (SELECT MAX(id) FROM user_messages GROUP BY user_id) " +
    "ORDER BY m.created_at DESC"
  ).all();
  return c.json(conversations.results);
});

// Admin mark message as read
app.post('/api/admin/message/:id/read', adminMiddleware, async c => {
  await c.env.DB.prepare('UPDATE user_messages SET is_read=1 WHERE id=?').bind(c.req.param('id')).run();
  return c.json({message:'Marked as read'});
});

// Admin delete a message
app.delete('/api/admin/message/:id', adminMiddleware, async c => {
  await c.env.DB.prepare('DELETE FROM user_messages WHERE id=?').bind(c.req.param('id')).run();
  return c.json({message:'Message deleted'});
});

app.get('/api/admin/stats', adminMiddleware, async c => {
  const db = c.env.DB;
  try {
    const totalUsers = (await db.prepare('SELECT COUNT(*) as c FROM users WHERE is_admin=0').first()).c;
    const activeUsers = (await db.prepare('SELECT COUNT(*) as c FROM users WHERE is_active=1 AND is_admin=0').first()).c;
    let totalDeposits = 0, totalWithdrawals = 0, totalBalance = 0;
    try { totalDeposits = Number((await db.prepare("SELECT COALESCE(SUM(amount),0) as s FROM transactions WHERE type='deposit' AND status IN ('approved','completed')").first()).s); } catch(e) {}
    try { totalWithdrawals = Number((await db.prepare("SELECT COALESCE(SUM(amount),0) as s FROM transactions WHERE type='withdrawal' AND status IN ('approved','completed')").first()).s); } catch(e) {}
    try { totalBalance = Number((await db.prepare('SELECT COALESCE(SUM(balance),0) as s FROM users').first()).s); } catch(e) {}
    const pendingDeposits = (await db.prepare("SELECT COUNT(*) as c FROM transactions WHERE type='deposit' AND status='pending'").first()).c;
    const pendingWithdrawals = (await db.prepare("SELECT COUNT(*) as c FROM transactions WHERE type='withdrawal' AND status='pending'").first()).c;
    return c.json({totalUsers, activeUsers, totalDeposits, totalWithdrawals, pendingDeposits, pendingWithdrawals, totalBalance});
  } catch(e) { return c.json({error: e.message}, 500); }
});

app.get('/api/admin/system-info', adminMiddleware, async c => {
  const db = c.env.DB;
  const usersLocked = (await db.prepare('SELECT COUNT(*) as c FROM users WHERE is_active=0').first()).c;
  const recentSignups = (await db.prepare("SELECT COUNT(*) as c FROM users WHERE created_at > datetime('now','-7 days')").first()).c;
  const openTickets = (await db.prepare("SELECT COUNT(*) as c FROM support_tickets WHERE status='open'").first()).c;
  const totalLogs = (await db.prepare('SELECT COUNT(*) as c FROM admin_logs').first()).c;
  return c.json({users:{locked:usersLocked, recent_signups:recentSignups}, financial:{pending_deposits:0, pending_withdrawals:0}, system:{active_sessions:0, open_tickets:openTickets, total_logs:totalLogs}, server:{uptime:0, memory_usage:{heapUsed:0}}});
});

app.get('/api/admin/users', adminMiddleware, async c => {
  const users = await c.env.DB.prepare('SELECT id,username,email,phone,full_name,balance,total_deposit,total_profit,investment_plan,is_active,is_admin,last_login,created_at FROM users ORDER BY id DESC').all();
  return c.json(users.results);
});

app.post('/api/admin/create-user', adminMiddleware, async c => {
  const {username, email, phone, full_name, password} = await c.req.json();
  if (!username||!email||!phone||!full_name||!password) return c.json({error:'All fields required'}, 400);
  const hash = bcrypt.hashSync(password, 12);
  const rpHash = bcrypt.hashSync('defaultreset', 12);
  try {
    const r = await c.env.DB.prepare('INSERT INTO users (username,email,phone,full_name,password_hash,reset_phrase_hash) VALUES (?,?,?,?,?,?)').bind(username,email,phone,full_name,hash,rpHash).run();
    const userId = r.meta.last_row_id;
    await c.env.DB.prepare('INSERT INTO user_wallets (user_id) VALUES (?)').bind(userId).run();
    return c.json({id:userId, message:'User created'}, 201);
  } catch(e) { return c.json({error:e.message}, 400); }
});

app.get('/api/admin/user/:id', adminMiddleware, async c => {
  const user = await c.env.DB.prepare('SELECT * FROM users WHERE id=?').bind(c.req.param('id')).first();
  if (!user) return c.json({error:'User not found'}, 404);
  return c.json(user);
});

app.put('/api/admin/user/:id', adminMiddleware, async c => {
  const data = await c.req.json();
  const id = c.req.param('id');
  const db = c.env.DB;
  const fields = []; const vals = [];
  for (const k of ['full_name','email','phone','username','is_active','is_admin','investment_plan','balance','total_deposit','total_profit']) {
    if (data[k] !== undefined) { fields.push(k+'=?'); vals.push(data[k]); }
  }
  if (!fields.length) return c.json({error:'No fields to update'}, 400);
  vals.push(now(), id);
  await db.prepare('UPDATE users SET '+fields.join(',')+', updated_at=? WHERE id=?').bind(...vals).run();
  // Log admin action
  const admin = c.get('user');
  await db.prepare('INSERT INTO admin_logs (admin_id,action,target,details) VALUES (?,?,?,?)').bind(admin.id, 'update_user', 'user:'+id, JSON.stringify(data)).run();
  return c.json({message:'User updated'});
});

app.delete('/api/admin/user/:id', adminMiddleware, async c => {
  const id = c.req.param('id');
  const db = c.env.DB;
  // Prevent deleting self
  const admin = c.get('user');
  if (Number(id) === admin.id) return c.json({error:'Cannot delete your own account'}, 400);
  // Clean up related records
  await db.prepare('DELETE FROM user_wallets WHERE user_id=?').bind(id).run();
  await db.prepare('DELETE FROM stock_positions WHERE user_id=?').bind(id).run();
  await db.prepare('DELETE FROM transactions WHERE user_id=?').bind(id).run();
  await db.prepare('DELETE FROM support_tickets WHERE user_id=?').bind(id).run();
  await db.prepare('DELETE FROM roi_cycles WHERE user_id=?').bind(id).run();
  await db.prepare('DELETE FROM users WHERE id=?').bind(id).run();
  // Log
  await db.prepare('INSERT INTO admin_logs (admin_id,action,target,details) VALUES (?,?,?,?)').bind(admin.id, 'delete_user', 'user:'+id, '').run();
  return c.json({message:'User deleted with all related data'});
});

app.post('/api/admin/user/:id/unlock', adminMiddleware, async c => {
  await c.env.DB.prepare('UPDATE users SET login_attempts=0, locked_until=NULL, is_active=1 WHERE id=?').bind(c.req.param('id')).run();
  return c.json({message:'Account unlocked'});
});

app.post('/api/admin/user/:id/reset-password', adminMiddleware, async c => {
  const {new_password} = await c.req.json();
  const hash = bcrypt.hashSync(new_password||'TempPass123!', 12);
  await c.env.DB.prepare('UPDATE users SET password_hash=?, login_attempts=0, locked_until=NULL WHERE id=?').bind(hash, c.req.param('id')).run();
  return c.json({message:'Password reset'});
});

app.post('/api/admin/user/:id/stage', adminMiddleware, async c => {
  const {stage} = await c.req.json();
  await c.env.DB.prepare('UPDATE users SET investment_plan=? WHERE id=?').bind(stage, c.req.param('id')).run();
  return c.json({message:'Stage updated'});
});

app.post('/api/admin/toggle-user/:id', adminMiddleware, async c => {
  const admin = c.get('user');
  const id = Number(c.req.param('id'));
  if (id === admin.id) return c.json({error:'Cannot toggle your own account'}, 400);
  await c.env.DB.prepare('UPDATE users SET is_active = CASE WHEN is_active=1 THEN 0 ELSE 1 END WHERE id=?').bind(id).run();
  return c.json({message:'User toggled'});
});

// --- Transactions ---
app.get('/api/admin/transactions', adminMiddleware, async c => {
  const txs = await c.env.DB.prepare('SELECT t.*, u.username FROM transactions t LEFT JOIN users u ON t.user_id=u.id ORDER BY t.created_at DESC LIMIT 200').all();
  return c.json(txs.results);
});

app.post('/api/admin/transaction/:id', adminMiddleware, async c => {
  const {status} = await c.req.json();
  const id = c.req.param('id');
  const db = c.env.DB;
  const tx = await db.prepare('SELECT * FROM transactions WHERE id=?').bind(id).first();
  if (!tx) return c.json({error:'Transaction not found'}, 404);
  
  if (status === 'approved') {
    if (tx.type === 'deposit') {
      const user = await db.prepare('SELECT total_deposit FROM users WHERE id=?').bind(tx.user_id).first();
      const newDeposit = (user.total_deposit||0) + tx.amount;
      const newStage = getInvestmentStage(newDeposit);
      await db.prepare('UPDATE users SET balance=balance+?, total_deposit=?, investment_plan=?, updated_at=? WHERE id=?').bind(tx.amount, newDeposit, newStage, now(), tx.user_id).run();
      await db.prepare('UPDATE user_wallets SET deposit_balance=deposit_balance+? WHERE user_id=?').bind(tx.amount, tx.user_id).run();
    } else if (tx.type === 'withdrawal') {
      const user = await db.prepare('SELECT balance FROM users WHERE id=?').bind(tx.user_id).first();
      if (user.balance < tx.amount) { await db.prepare('UPDATE transactions SET status=? WHERE id=?').bind('rejected', id).run(); return c.json({error:'Insufficient balance — auto-rejected'}); }
      await db.prepare('UPDATE users SET balance=balance-?, updated_at=? WHERE id=?').bind(tx.amount, now(), tx.user_id).run();
      // Deduct from wallet: prefer deposit_balance first, then roi_balance
      const wallet = await db.prepare('SELECT deposit_balance, roi_balance, bonus_balance FROM user_wallets WHERE user_id=?').bind(tx.user_id).first();
      if (wallet) {
        let remaining = tx.amount;
        if (wallet.deposit_balance >= remaining) {
          await db.prepare('UPDATE user_wallets SET deposit_balance=deposit_balance-? WHERE user_id=?').bind(remaining, tx.user_id).run();
          remaining = 0;
        } else if (wallet.deposit_balance > 0) {
          remaining -= wallet.deposit_balance;
          await db.prepare('UPDATE user_wallets SET deposit_balance=0 WHERE user_id=?').bind(tx.user_id).run();
        }
        if (remaining > 0 && wallet.roi_balance >= remaining) {
          await db.prepare('UPDATE user_wallets SET roi_balance=roi_balance-? WHERE user_id=?').bind(remaining, tx.user_id).run();
          remaining = 0;
        } else if (remaining > 0 && wallet.roi_balance > 0) {
          remaining -= wallet.roi_balance;
          await db.prepare('UPDATE user_wallets SET roi_balance=0 WHERE user_id=?').bind(tx.user_id).run();
        }
        if (remaining > 0) {
          await db.prepare('UPDATE user_wallets SET bonus_balance=GREATEST(0, bonus_balance-?) WHERE user_id=?').bind(remaining, tx.user_id).run();
        }
      }
    }
  }
  await db.prepare('UPDATE transactions SET status=?, updated_at=? WHERE id=?').bind(status, now(), id).run();
  
  // Send inbox message to user about transaction status change
  const txTypeLabel = tx.type === 'deposit' ? 'Deposit' : tx.type === 'withdrawal' ? 'Withdrawal' : tx.type;
  const txStatusEmoji = status === 'approved' ? '✅' : '❌';
  const txMsgTitle = `${txStatusEmoji} ${txTypeLabel} ${status}`;
  const txMsgBody = `Your ${txTypeLabel.toLowerCase()} of $${Number(tx.amount).toFixed(2)} has been ${status}. Reference: ${tx.reference||'N/A'}`;
  await db.prepare('INSERT INTO user_messages (user_id,title,body,type,from_admin,reference) VALUES (?,?,?,?,1,?)').bind(tx.user_id, txMsgTitle, txMsgBody, tx.type, tx.reference||'').run();
  
  // Auto-link purchase requests / stock trades
  if (tx.linked_type && tx.linked_id && status === 'approved') {
    if (tx.linked_type === 'purchase_request') await db.prepare('UPDATE purchase_requests SET status=? WHERE id=?').bind('deposit_approved', tx.linked_id).run();
    if (tx.linked_type === 'stock_trade') {
      // Re-route through stock trade approval logic for proper position updates
      const trade = await db.prepare('SELECT * FROM stock_trades WHERE id=?').bind(tx.linked_id).first();
      if (trade && trade.type === 'buy') {
        // Credit balance + deposit wallet (already done by deposit approval above)
        // Just update stock_positions
        const existing = await db.prepare('SELECT id, shares, avg_price FROM stock_positions WHERE user_id=? AND symbol=?').bind(trade.user_id, trade.symbol).first();
        if (existing) {
          const newShares = Number(existing.shares) + Number(trade.shares);
          const newAvg = ((Number(existing.shares) * Number(existing.avg_price)) + (Number(trade.shares) * Number(trade.price))) / newShares;
          await db.prepare('UPDATE stock_positions SET shares=?, avg_price=?, current_price=?, updated_at=? WHERE id=?').bind(newShares, newAvg, trade.price, now(), existing.id).run();
        } else {
          await db.prepare('INSERT INTO stock_positions (user_id,symbol,shares,avg_price,current_price) VALUES (?,?,?,?,?)').bind(trade.user_id, trade.symbol, trade.shares, trade.price, trade.price).run();
        }
      }
      await db.prepare('UPDATE stock_trades SET status=?, updated_at=? WHERE id=?').bind('completed', now(), tx.linked_id).run();
    }
  }
  return c.json({message:'Transaction '+status});
});

app.delete('/api/admin/transaction/:id', adminMiddleware, async c => {
  await c.env.DB.prepare('DELETE FROM transactions WHERE id=?').bind(c.req.param('id')).run();
  return c.json({message:'Transaction deleted'});
});

app.post('/api/admin/bulk-transactions', adminMiddleware, async c => {
  const {ids, status} = await c.req.json();
  const results = [];
  for (const id of ids) {
    try {
      const res = await fetch(new Request(c.req.url.replace('bulk-transactions', 'transaction/'+id), {method:'POST', headers:Object.fromEntries(c.req.raw.headers.entries()), body:JSON.stringify({status})}));
      results.push({id, ok:res.ok});
    } catch(e) { results.push({id, ok:false, error:e.message}); }
  }
  return c.json({results});
});

// --- Wallet Manipulation ---
app.get('/api/admin/user/:id/wallet', adminMiddleware, async c => {
  const db = c.env.DB;
  const userId = c.req.param('id');
  const user = await db.prepare('SELECT id,username,balance,total_deposit,total_profit,investment_plan FROM users WHERE id=?').bind(userId).first();
  if (!user) return c.json({error:'User not found'}, 404);
  let wallet = await db.prepare('SELECT deposit_balance,roi_balance,bonus_balance,total_roi_earned,last_roi_at FROM user_wallets WHERE user_id=?').bind(userId).first();
  if (!wallet) {
    await db.prepare('INSERT INTO user_wallets (user_id) VALUES (?)').bind(userId).run();
    wallet = {deposit_balance:0,roi_balance:0,bonus_balance:0,total_roi_earned:0,last_roi_at:null};
  }
  return c.json({user, wallet});
});

app.patch('/api/admin/user/:id/wallet', adminMiddleware, async c => {
  const db = c.env.DB;
  const userId = c.req.param('id');
  try {
    const data = await c.req.json();
    const {field, operation, amount} = data;
    const validFields = ['deposit_balance','roi_balance','bonus_balance','balance','total_deposit','total_profit','total_roi_earned'];
    if (!validFields.includes(field)) return c.json({error:`Invalid field. Valid: ${validFields.join(', ')}`}, 400);
    if (!['add','subtract','set'].includes(operation)) return c.json({error:'Invalid operation. Use: add, subtract, set'}, 400);
    const amt = Number(amount);
    if (isNaN(amt)) return c.json({error:'Amount must be a number'}, 400);

    const user = await db.prepare('SELECT id,username,balance FROM users WHERE id=?').bind(userId).first();
    if (!user) return c.json({error:'User not found'}, 404);

    let oldVal = 0;
    let newVal = 0;

    if (field === 'balance' || field === 'total_deposit' || field === 'total_profit') {
      const row = await db.prepare(`SELECT ${field} as val FROM users WHERE id=?`).bind(userId).first();
      oldVal = Number(row?.val || 0);
      if (operation === 'add') newVal = oldVal + amt;
      else if (operation === 'subtract') newVal = Math.max(0, oldVal - amt);
      else newVal = Math.max(0, amt);
      await db.prepare(`UPDATE users SET ${field}=?, updated_at=? WHERE id=?`).bind(newVal, now(), userId).run();
      if (field === 'balance') {
        const wallet = await db.prepare('SELECT deposit_balance,roi_balance,bonus_balance FROM user_wallets WHERE user_id=?').bind(userId).first();
        if (wallet) {
          const walletTotal = Number(wallet.deposit_balance||0) + Number(wallet.roi_balance||0) + Number(wallet.bonus_balance||0);
          const diff = newVal - walletTotal;
          const newDeposit = Math.max(0, Number(wallet.deposit_balance||0) + diff);
          await db.prepare('UPDATE user_wallets SET deposit_balance=? WHERE user_id=?').bind(newDeposit, userId).run();
        }
      }
    } else {
      const row = await db.prepare(`SELECT ${field} as val FROM user_wallets WHERE user_id=?`).bind(userId).first();
      oldVal = Number(row?.val || 0);
      if (operation === 'add') newVal = oldVal + amt;
      else if (operation === 'subtract') newVal = Math.max(0, oldVal - amt);
      else newVal = Math.max(0, amt);
      await db.prepare(`UPDATE user_wallets SET ${field}=? WHERE user_id=?`).bind(newVal, userId).run();
      const wallet = await db.prepare('SELECT deposit_balance,roi_balance,bonus_balance FROM user_wallets WHERE user_id=?').bind(userId).first();
      if (wallet) {
        const walletTotal = Number(wallet.deposit_balance||0) + Number(wallet.roi_balance||0) + Number(wallet.bonus_balance||0);
        await db.prepare('UPDATE users SET balance=?, updated_at=? WHERE id=?').bind(walletTotal, now(), userId).run();
      }
    }

    const description = data.description || '';
    const ref = genRef();
    const opLabel = operation === 'add' ? '+' : operation === 'subtract' ? '-' : '=';
    const desc = `Admin wallet: ${field} ${opLabel} ${amt} (was ${oldVal.toFixed(2)}, now ${newVal.toFixed(2)})` + (description ? ` | Description: ${description}` : '');
    await db.prepare('INSERT INTO transactions (user_id,type,amount,status,reference,description) VALUES (?,?,?,?,?,?)').bind(userId, 'admin_adjust', amt, 'approved', ref, desc).run();

    // Log to admin_logs
    const admin = c.get('user');
    await db.prepare('INSERT INTO admin_logs (admin_id,action,target,details) VALUES (?,?,?,?)').bind(admin.id, 'wallet_adjust', 'user:'+userId, desc).run();

    // Send inbox message to user with the description
    const msgTitle = `Wallet Update: ${field} ${opLabel} $${amt.toFixed(2)}`;
    const msgBody = `Your ${field} has been updated: ${opLabel}$${amt.toFixed(2)} (was $${oldVal.toFixed(2)}, now $${newVal.toFixed(2)})` + (description ? `\n\n${description}` : '');
    await db.prepare('INSERT INTO user_messages (user_id,title,body,type,from_admin,reference) VALUES (?,?,?,?,1,?)').bind(userId, msgTitle, msgBody, 'wallet', ref).run();

    const updatedUser = await db.prepare('SELECT id,username,balance,total_deposit,total_profit,investment_plan FROM users WHERE id=?').bind(userId).first();
    const updatedWallet = await db.prepare('SELECT deposit_balance,roi_balance,bonus_balance,total_roi_earned,last_roi_at FROM user_wallets WHERE user_id=?').bind(userId).first();
    return c.json({message:`${field} ${operation} ${amt}`, field, operation, amount:amt, oldValue:oldVal, newValue:newVal, reference:ref, description, user:updatedUser, wallet:updatedWallet});
  } catch(e) {
    return c.json({error:'Wallet update failed: ' + e.message}, 500);
  }
});

app.post('/api/admin/update-balance', adminMiddleware, async c => {
  const {user_id, amount, type} = await c.req.json();
  const db = c.env.DB;
  if (type === 'deposit') {
    await db.prepare('UPDATE users SET balance=balance+?, total_deposit=total_deposit+?, updated_at=? WHERE id=?').bind(amount, amount, now(), user_id).run();
    await db.prepare('UPDATE user_wallets SET deposit_balance=deposit_balance+? WHERE user_id=?').bind(amount, user_id).run();
  } else if (type === 'profit') {
    await db.prepare('UPDATE users SET balance=balance+?, total_profit=total_profit+?, updated_at=? WHERE id=?').bind(amount, amount, now(), user_id).run();
    await db.prepare('UPDATE user_wallets SET roi_balance=roi_balance+? WHERE user_id=?').bind(amount, user_id).run();
  } else if (type === 'bonus') {
    await db.prepare('UPDATE users SET balance=balance+?, updated_at=? WHERE id=?').bind(amount, now(), user_id).run();
    await db.prepare('UPDATE user_wallets SET bonus_balance=bonus_balance+? WHERE user_id=?').bind(amount, user_id).run();
  } else if (type === 'withdrawal') {
    await db.prepare('UPDATE users SET balance=balance-?, updated_at=? WHERE id=?').bind(amount, now(), user_id).run();
    await db.prepare('UPDATE user_wallets SET deposit_balance=GREATEST(0, deposit_balance-?) WHERE user_id=?').bind(amount, user_id).run();
  }
  const ref = genRef();
  await db.prepare('INSERT INTO transactions (user_id,type,amount,status,reference,description) VALUES (?,?,?,?,?,?)').bind(user_id, type, amount, 'approved', ref, 'Admin balance update').run();
  return c.json({message:'Balance updated', reference:ref});
});

// --- Sessions ---
app.get('/api/admin/sessions', adminMiddleware, async c => c.json([]));
app.delete('/api/admin/sessions/:id', adminMiddleware, async c => c.json({message:'Sessions invalidated'}));

// --- Payment Settings ---
app.get('/api/admin/payment-methods', adminMiddleware, async c => {
  const methods = await c.env.DB.prepare('SELECT * FROM payment_settings ORDER BY id').all();
  return c.json(methods.results.map(m => ({...m, details:JSON.parse(m.details||'[]')})));
});

app.post('/api/admin/payment-methods', adminMiddleware, async c => {
  const {method, display_name, logo, details} = await c.req.json();
  await c.env.DB.prepare('INSERT INTO payment_settings (method,display_name,logo,details) VALUES (?,?,?,?)').bind(method, display_name, logo||'', JSON.stringify(details||[])).run();
  return c.json({message:'Payment method added'}, 201);
});

app.post('/api/admin/payment-methods/:method', adminMiddleware, async c => {
  const {display_name, is_active, details} = await c.req.json();
  const method = c.req.param('method');
  if (display_name) await c.env.DB.prepare('UPDATE payment_settings SET display_name=? WHERE method=?').bind(display_name, method).run();
  if (is_active !== undefined) await c.env.DB.prepare('UPDATE payment_settings SET is_active=? WHERE method=?').bind(is_active, method).run();
  if (details) await c.env.DB.prepare('UPDATE payment_settings SET details=? WHERE method=?').bind(JSON.stringify(details), method).run();
  return c.json({message:'Payment method updated'});
});

app.delete('/api/admin/payment-methods/:method', adminMiddleware, async c => {
  await c.env.DB.prepare('DELETE FROM payment_settings WHERE method=?').bind(c.req.param('method')).run();
  return c.json({message:'Payment method deleted'});
});

// --- Support ---
app.get('/api/admin/support-tickets', adminMiddleware, async c => {
  const tix = await c.env.DB.prepare('SELECT t.*, u.username FROM support_tickets t LEFT JOIN users u ON t.user_id=u.id ORDER BY t.created_at DESC').all();
  return c.json(tix.results);
});

app.post('/api/admin/support-ticket/:id/status', adminMiddleware, async c => {
  const {status} = await c.req.json();
  await c.env.DB.prepare('UPDATE support_tickets SET status=?, updated_at=? WHERE id=?').bind(status, now(), c.req.param('id')).run();
  return c.json({message:'Ticket updated'});
});

app.delete('/api/admin/support-ticket/:id', adminMiddleware, async c => {
  await c.env.DB.prepare('DELETE FROM support_tickets WHERE id=?').bind(c.req.param('id')).run();
  return c.json({message:'Ticket deleted'});
});

// --- Product Orders ---
app.get('/api/admin/product-orders', adminMiddleware, async c => {
  const orders = await c.env.DB.prepare('SELECT o.*, u.username FROM product_orders o LEFT JOIN users u ON o.user_id=u.id ORDER BY o.created_at DESC').all();
  return c.json(orders.results);
});

app.post('/api/admin/product-orders/:id/status', adminMiddleware, async c => {
  const {status} = await c.req.json();
  const db = c.env.DB;
  const id = c.req.param('id');
  await db.prepare('UPDATE product_orders SET status=?, updated_at=? WHERE id=?').bind(status, now(), id).run();
  // Send inbox message to user
  const order = await db.prepare('SELECT user_id, product_name, product_price FROM product_orders WHERE id=?').bind(id).first();
  if (order) {
    const emoji = status === 'approved' ? '✅' : status === 'rejected' ? '❌' : '📦';
    await db.prepare('INSERT INTO user_messages (user_id,title,body,type,from_admin) VALUES (?,?,?,?,1)').bind(order.user_id, `${emoji} Order ${status}`, `Your order for ${order.product_name} ($${Number(order.product_price).toFixed(2)}) has been ${status}.`, 'order').run();
  }
  return c.json({message:'Order updated'});
});

app.delete('/api/admin/product-order/:id', adminMiddleware, async c => {
  await c.env.DB.prepare('DELETE FROM product_orders WHERE id=?').bind(c.req.param('id')).run();
  return c.json({message:'Order deleted'});
});

// --- Announcements ---
app.get('/api/admin/announcements', adminMiddleware, async c => {
  const anns = await c.env.DB.prepare('SELECT * FROM announcements ORDER BY created_at DESC').all();
  return c.json(anns.results);
});

app.post('/api/admin/announcements', adminMiddleware, async c => {
  const {title, message, type} = await c.req.json();
  const r = await c.env.DB.prepare('INSERT INTO announcements (title,message,type) VALUES (?,?,?)').bind(title, message, type||'info').run();
  return c.json({id:r.meta.last_row_id}, 201);
});

app.put('/api/admin/announcements/:id', adminMiddleware, async c => {
  const {title, message, is_active} = await c.req.json();
  const id = c.req.param('id');
  if (title) await c.env.DB.prepare('UPDATE announcements SET title=? WHERE id=?').bind(title, id).run();
  if (message) await c.env.DB.prepare('UPDATE announcements SET message=? WHERE id=?').bind(message, id).run();
  if (is_active !== undefined) await c.env.DB.prepare('UPDATE announcements SET is_active=? WHERE id=?').bind(is_active, id).run();
  return c.json({message:'Announcement updated'});
});

app.delete('/api/admin/announcements/:id', adminMiddleware, async c => {
  await c.env.DB.prepare('DELETE FROM announcements WHERE id=?').bind(c.req.param('id')).run();
  return c.json({message:'Announcement deleted'});
});

// --- Settings ---
app.get('/api/admin/settings', adminMiddleware, async c => {
  const settings = await c.env.DB.prepare('SELECT key, value FROM admin_settings').all();
  return c.json(Object.fromEntries(settings.results.map(s => [s.key, s.value])));
});

app.post('/api/admin/settings', adminMiddleware, async c => {
  const data = await c.req.json();
  for (const [k,v] of Object.entries(data)) { await c.env.DB.prepare('INSERT OR REPLACE INTO admin_settings (key,value,updated_at) VALUES (?,?,?)').bind(k, v, now()).run(); }
  return c.json({message:'Settings updated'});
});

// --- Logs ---
app.get('/api/admin/logs', adminMiddleware, async c => {
  const logs = await c.env.DB.prepare('SELECT l.*, u.username FROM admin_logs l LEFT JOIN users u ON l.admin_id=u.id ORDER BY l.created_at DESC LIMIT 100').all();
  return c.json(logs.results);
});

// --- ROI Processing ---
app.post('/api/admin/process-roi', adminMiddleware, async c => {
  const db = c.env.DB;
  const users = await db.prepare('SELECT u.id, u.investment_plan, w.deposit_balance FROM users u JOIN user_wallets w ON u.id=w.user_id WHERE w.deposit_balance > 0 AND u.is_active=1 AND u.is_admin=0').all();
  let processed = 0;
  for (const u of users.results) {
    const roiPercent = getStageROI(u.investment_plan);
    const dailyROI = (roiPercent / 365) * u.deposit_balance;
    if (dailyROI < 0.01) continue;
    await db.prepare('UPDATE users SET balance=balance+?, total_profit=total_profit+?, updated_at=? WHERE id=?').bind(dailyROI, dailyROI, now(), u.id).run();
    await db.prepare('UPDATE user_wallets SET roi_balance=roi_balance+?, total_roi_earned=total_roi_earned+?, last_roi_at=? WHERE user_id=?').bind(dailyROI, dailyROI, now(), u.id).run();
    await db.prepare('INSERT INTO roi_cycles (user_id,stage,roi_percent,deposit_base,roi_amount) VALUES (?,?,?,?,?)').bind(u.id, u.investment_plan, roiPercent, u.deposit_balance, dailyROI).run();
    processed++;
  }
  return c.json({message:`ROI processed for ${processed} users`, processed});
});

app.get('/api/admin/roi-cycles', adminMiddleware, async c => {
  const cycles = await c.env.DB.prepare('SELECT r.*, u.username FROM roi_cycles r LEFT JOIN users u ON r.user_id=u.id ORDER BY r.cycle_date DESC LIMIT 100').all();
  return c.json(cycles.results);
});

// --- Purchase Requests ---
app.get('/api/admin/purchase-requests', adminMiddleware, async c => {
  const reqs = await c.env.DB.prepare('SELECT p.*, u.username FROM purchase_requests p LEFT JOIN users u ON p.user_id=u.id ORDER BY p.created_at DESC').all();
  return c.json(reqs.results);
});

app.post('/api/admin/purchase-request/:id/approve', adminMiddleware, async c => {
  await c.env.DB.prepare('UPDATE purchase_requests SET status=?, updated_at=? WHERE id=?').bind('approved', now(), c.req.param('id')).run();
  return c.json({message:'Purchase request approved'});
});

app.post('/api/admin/purchase-request/:id/reject', adminMiddleware, async c => {
  await c.env.DB.prepare('UPDATE purchase_requests SET status=?, updated_at=? WHERE id=?').bind('rejected', now(), c.req.param('id')).run();
  return c.json({message:'Purchase request rejected'});
});

// --- Stock Trades ---
app.get('/api/admin/stock-trades', adminMiddleware, async c => {
  const trades = await c.env.DB.prepare('SELECT s.*, u.username FROM stock_trades s LEFT JOIN users u ON s.user_id=u.id ORDER BY s.created_at DESC').all();
  return c.json(trades.results);
});

app.post('/api/admin/stock-trade/:id/approve', adminMiddleware, async c => {
  const db = c.env.DB;
  const id = c.req.param('id');
  const trade = await db.prepare('SELECT * FROM stock_trades WHERE id=?').bind(id).first();
  if (!trade) return c.json({error:'Trade not found'}, 404);
  if (trade.status === 'completed') return c.json({error:'Trade already completed'}, 400);

  if (trade.type === 'buy') {
    // Credit user balance + deposit wallet
    await db.prepare('UPDATE users SET balance=balance+?, total_deposit=total_deposit+?, updated_at=? WHERE id=?').bind(trade.total, trade.total, now(), trade.user_id).run();
    await db.prepare('UPDATE user_wallets SET deposit_balance=deposit_balance+? WHERE user_id=?').bind(trade.total, trade.user_id).run();
    // Update stock_positions (upsert)
    const existing = await db.prepare('SELECT id, shares, avg_price FROM stock_positions WHERE user_id=? AND symbol=?').bind(trade.user_id, trade.symbol).first();
    if (existing) {
      const newShares = Number(existing.shares) + Number(trade.shares);
      const newAvg = ((Number(existing.shares) * Number(existing.avg_price)) + (Number(trade.shares) * Number(trade.price))) / newShares;
      await db.prepare('UPDATE stock_positions SET shares=?, avg_price=?, current_price=?, updated_at=? WHERE id=?').bind(newShares, newAvg, trade.price, now(), existing.id).run();
    } else {
      await db.prepare('INSERT INTO stock_positions (user_id,symbol,shares,avg_price,current_price) VALUES (?,?,?,?,?)').bind(trade.user_id, trade.symbol, trade.shares, trade.price, trade.price).run();
    }
  } else if (trade.type === 'sell') {
    // Credit ROI wallet + user balance + profit
    await db.prepare('UPDATE user_wallets SET roi_balance=roi_balance+? WHERE user_id=?').bind(trade.total, trade.user_id).run();
    await db.prepare('UPDATE users SET balance=balance+?, total_profit=total_profit+?, updated_at=? WHERE id=?').bind(trade.total, trade.total, now(), trade.user_id).run();
    // Deduct from stock_positions
    const pos = await db.prepare('SELECT id, shares, avg_price FROM stock_positions WHERE user_id=? AND symbol=?').bind(trade.user_id, trade.symbol).first();
    if (pos) {
      const newShares = Number(pos.shares) - Number(trade.shares);
      if (newShares <= 0) {
        await db.prepare('DELETE FROM stock_positions WHERE id=?').bind(pos.id).run();
      } else {
        await db.prepare('UPDATE stock_positions SET shares=?, current_price=?, updated_at=? WHERE id=?').bind(newShares, trade.price, now(), pos.id).run();
      }
    }
  }

  await db.prepare('UPDATE stock_trades SET status=?, updated_at=? WHERE id=?').bind('completed', now(), id).run();
  // Send inbox message
  const tradeLabel = trade.type === 'buy' ? 'Stock Buy' : 'Stock Sell';
  await db.prepare('INSERT INTO user_messages (user_id,title,body,type,from_admin) VALUES (?,?,?,?,1)').bind(trade.user_id, `✅ ${tradeLabel} Approved`, `Your ${tradeLabel.toLowerCase()} order for ${Number(trade.shares).toFixed(2)} shares of ${trade.symbol} at $${Number(trade.price).toFixed(2)} has been approved and executed.`, 'stock').run();
  return c.json({message:'Stock trade approved'});
});

app.post('/api/admin/stock-trade/:id/reject', adminMiddleware, async c => {
  const db = c.env.DB;
  const id = c.req.param('id');
  await db.prepare('UPDATE stock_trades SET status=?, updated_at=? WHERE id=?').bind('rejected', now(), id).run();
  // Also reject linked transaction if any
  const trade = await db.prepare('SELECT * FROM stock_trades WHERE id=?').bind(id).first();
  if (trade && trade.transaction_id) {
    await db.prepare('UPDATE transactions SET status=?, updated_at=? WHERE id=?').bind('rejected', now(), trade.transaction_id).run();
  }
  // Send inbox message
  if (trade) {
    const tradeLabel = trade.type === 'buy' ? 'Stock Buy' : 'Stock Sell';
    await db.prepare('INSERT INTO user_messages (user_id,title,body,type,from_admin) VALUES (?,?,?,?,1)').bind(trade.user_id, `❌ ${tradeLabel} Rejected`, `Your ${tradeLabel.toLowerCase()} order for ${Number(trade.shares).toFixed(2)} shares of ${trade.symbol} at $${Number(trade.price).toFixed(2)} has been rejected.`, 'stock').run();
  }
  return c.json({message:'Stock trade rejected'});
});

// --- Extended Admin CRUD Routes ---

// Stock Trades: Edit
app.put('/api/admin/stock-trade/:id', adminMiddleware, async c => {
  const data = await c.req.json();
  const id = c.req.param('id');
  const db = c.env.DB;
  const fields = []; const vals = [];
  for (const k of ['status','shares','price','symbol','type']) { if (data[k] !== undefined) { fields.push(k+'=?'); vals.push(data[k]); } }
  if (!fields.length) return c.json({error:'No fields to update'}, 400);
  vals.push(now(), id);
  await db.prepare('UPDATE stock_trades SET '+fields.join(',')+', updated_at=? WHERE id=?').bind(...vals).run();
  return c.json({message:'Stock trade updated'});
});

// Stock Trades: Delete
app.delete('/api/admin/stock-trade/:id', adminMiddleware, async c => {
  const id = c.req.param('id');
  await c.env.DB.prepare('DELETE FROM stock_trades WHERE id=?').bind(id).run();
  return c.json({message:'Stock trade deleted'});
});

// Transactions: Create manual
app.post('/api/admin/transaction-create', adminMiddleware, async c => {
  const data = await c.req.json();
  if (!data.user_id || !data.type || !data.amount) return c.json({error:'user_id, type, and amount required'}, 400);
  const amt = Number(data.amount);
  if (isNaN(amt) || amt <= 0) return c.json({error:'Amount must be positive'}, 400);
  const ref = genRef();
  const r = await c.env.DB.prepare('INSERT INTO transactions (user_id,type,amount,status,payment_method,wallet_address,description,reference,linked_type,linked_id) VALUES (?,?,?,?,?,?,?,?,?,?)').bind(data.user_id, data.type, amt, data.status||'pending', data.payment_method||'', data.wallet_address||'', data.description||'Admin manual transaction', ref, data.linked_type||null, data.linked_id||null).run();
  const admin = c.get('user');
  await c.env.DB.prepare('INSERT INTO admin_logs (admin_id,action,target,details) VALUES (?,?,?,?)').bind(admin.id, 'create_transaction', 'transaction:'+r.meta.last_row_id, JSON.stringify(data)).run();
  return c.json({id:r.meta.last_row_id, reference:ref, message:'Transaction created'}, 201);
});

// Transactions: Edit
app.put('/api/admin/transaction/:id', adminMiddleware, async c => {
  const data = await c.req.json();
  const id = c.req.param('id');
  const db = c.env.DB;
  const fields = []; const vals = [];
  for (const k of ['status','amount','payment_method','wallet_address','description','type']) { if (data[k] !== undefined) { fields.push(k+'=?'); vals.push(data[k]); } }
  if (!fields.length) return c.json({error:'No fields to update'}, 400);
  vals.push(now(), id);
  await db.prepare('UPDATE transactions SET '+fields.join(',')+', updated_at=? WHERE id=?').bind(...vals).run();
  const admin = c.get('user');
  await db.prepare('INSERT INTO admin_logs (admin_id,action,target,details) VALUES (?,?,?,?)').bind(admin.id, 'update_transaction', 'transaction:'+id, JSON.stringify(data)).run();
  return c.json({message:'Transaction updated'});
});

// Support Tickets: Edit
app.put('/api/admin/support-ticket/:id', adminMiddleware, async c => {
  const data = await c.req.json();
  const id = c.req.param('id');
  const db = c.env.DB;
  const fields = []; const vals = [];
  for (const k of ['subject','message','status','priority']) { if (data[k] !== undefined) { fields.push(k+'=?'); vals.push(data[k]); } }
  if (!fields.length) return c.json({error:'No fields to update'}, 400);
  vals.push(now(), id);
  await db.prepare('UPDATE support_tickets SET '+fields.join(',')+', updated_at=? WHERE id=?').bind(...vals).run();
  return c.json({message:'Ticket updated'});
});

// Support Tickets: Create (admin can create ticket for any user)
app.post('/api/admin/support-ticket', adminMiddleware, async c => {
  const {user_id, subject, message, priority} = await c.req.json();
  if (!subject || !message) return c.json({error:'Subject and message required'}, 400);
  const r = await c.env.DB.prepare('INSERT INTO support_tickets (user_id,subject,message,priority) VALUES (?,?,?,?)').bind(user_id||0, subject, message, priority||'medium').run();
  return c.json({id:r.meta.last_row_id, message:'Ticket created'}, 201);
});

// Product Orders: Edit
app.put('/api/admin/product-order/:id', adminMiddleware, async c => {
  const data = await c.req.json();
  const id = c.req.param('id');
  const db = c.env.DB;
  const fields = []; const vals = [];
  for (const k of ['status','product_name','product_price','quantity','shipping_address','payment_method']) { if (data[k] !== undefined) { fields.push(k+'=?'); vals.push(data[k]); } }
  if (!fields.length) return c.json({error:'No fields to update'}, 400);
  vals.push(now(), id);
  await db.prepare('UPDATE product_orders SET '+fields.join(',')+', updated_at=? WHERE id=?').bind(...vals).run();
  return c.json({message:'Order updated'});
});

// Purchase Requests: Delete
app.delete('/api/admin/purchase-request/:id', adminMiddleware, async c => {
  await c.env.DB.prepare('DELETE FROM purchase_requests WHERE id=?').bind(c.req.param('id')).run();
  return c.json({message:'Purchase request deleted'});
});

// Purchase Requests: Edit
app.put('/api/admin/purchase-request/:id', adminMiddleware, async c => {
  const data = await c.req.json();
  const id = c.req.param('id');
  const db = c.env.DB;
  const fields = []; const vals = [];
  for (const k of ['status','product_name','product_price','quantity','shipping_address']) { if (data[k] !== undefined) { fields.push(k+'=?'); vals.push(data[k]); } }
  if (!fields.length) return c.json({error:'No fields to update'}, 400);
  vals.push(now(), id);
  await db.prepare('UPDATE purchase_requests SET '+fields.join(',')+', updated_at=? WHERE id=?').bind(...vals).run();
  return c.json({message:'Purchase request updated'});
});

// ROI Cycles: Delete
app.delete('/api/admin/roi-cycle/:id', adminMiddleware, async c => {
  await c.env.DB.prepare('DELETE FROM roi_cycles WHERE id=?').bind(c.req.param('id')).run();
  return c.json({message:'ROI cycle deleted'});
});

// Bulk approve all pending transactions
app.post('/api/admin/bulk-approve', adminMiddleware, async c => {
  const db = c.env.DB;
  const pending = await db.prepare("SELECT id FROM transactions WHERE status='pending'").all();
  let approved = 0;
  for (const tx of pending.results) {
    // Re-process each through the approval endpoint logic
    const txData = await db.prepare('SELECT * FROM transactions WHERE id=?').bind(tx.id).first();
    if (!txData) continue;
    if (txData.type === 'deposit') {
      const user = await db.prepare('SELECT total_deposit FROM users WHERE id=?').bind(txData.user_id).first();
      if (!user) continue;
      const newDeposit = (user.total_deposit||0) + txData.amount;
      const newStage = getInvestmentStage(newDeposit);
      await db.prepare('UPDATE users SET balance=balance+?, total_deposit=?, investment_plan=?, updated_at=? WHERE id=?').bind(txData.amount, newDeposit, newStage, now(), txData.user_id).run();
      await db.prepare('UPDATE user_wallets SET deposit_balance=deposit_balance+? WHERE user_id=?').bind(txData.amount, txData.user_id).run();
    } else if (txData.type === 'withdrawal') {
      const user = await db.prepare('SELECT balance FROM users WHERE id=?').bind(txData.user_id).first();
      if (!user || user.balance < txData.amount) { await db.prepare('UPDATE transactions SET status=? WHERE id=?').bind('rejected', tx.id).run(); continue; }
      await db.prepare('UPDATE users SET balance=balance-?, updated_at=? WHERE id=?').bind(txData.amount, now(), txData.user_id).run();
      const wallet = await db.prepare('SELECT deposit_balance, roi_balance, bonus_balance FROM user_wallets WHERE user_id=?').bind(txData.user_id).first();
      if (wallet) {
        let remaining = txData.amount;
        if (wallet.deposit_balance >= remaining) { await db.prepare('UPDATE user_wallets SET deposit_balance=deposit_balance-? WHERE user_id=?').bind(remaining, txData.user_id).run(); remaining = 0; }
        else if (wallet.deposit_balance > 0) { remaining -= wallet.deposit_balance; await db.prepare('UPDATE user_wallets SET deposit_balance=0 WHERE user_id=?').bind(txData.user_id).run(); }
        if (remaining > 0 && wallet.roi_balance >= remaining) { await db.prepare('UPDATE user_wallets SET roi_balance=roi_balance-? WHERE user_id=?').bind(remaining, txData.user_id).run(); remaining = 0; }
        else if (remaining > 0 && wallet.roi_balance > 0) { remaining -= wallet.roi_balance; await db.prepare('UPDATE user_wallets SET roi_balance=0 WHERE user_id=?').bind(txData.user_id).run(); }
        if (remaining > 0) { await db.prepare('UPDATE user_wallets SET bonus_balance=GREATEST(0, bonus_balance-?) WHERE user_id=?').bind(remaining, txData.user_id).run(); }
      }
    }
    await db.prepare('UPDATE transactions SET status=?, updated_at=? WHERE id=?').bind('approved', now(), tx.id).run();
    approved++;
  }
  return c.json({message:`Bulk approved ${approved} transactions`, approved});
});

// Bulk reject all pending transactions
app.post('/api/admin/bulk-reject', adminMiddleware, async c => {
  const db = c.env.DB;
  const r = await db.prepare("UPDATE transactions SET status='rejected', updated_at=? WHERE status='pending'").bind(now()).run();
  return c.json({message:`Bulk rejected ${r.meta.changes} transactions`, rejected: r.meta.changes});
});

// Admin logs: Create (for manual notes)
app.post('/api/admin/logs', adminMiddleware, async c => {
  const {action, target, details} = await c.req.json();
  const admin = c.get('user');
  const r = await c.env.DB.prepare('INSERT INTO admin_logs (admin_id,action,target,details) VALUES (?,?,?,?)').bind(admin.id, action||'note', target||'', details||'').run();
  return c.json({id:r.meta.last_row_id, message:'Log entry created'}, 201);
});

// Admin logs: Delete
app.delete('/api/admin/logs/:id', adminMiddleware, async c => {
  await c.env.DB.prepare('DELETE FROM admin_logs WHERE id=?').bind(c.req.param('id')).run();
  return c.json({message:'Log entry deleted'});
});

// Stock positions: Admin view all
app.get('/api/admin/stock-positions', adminMiddleware, async c => {
  const positions = await c.env.DB.prepare('SELECT p.*, u.username FROM stock_positions p LEFT JOIN users u ON p.user_id=u.id ORDER BY p.updated_at DESC').all();
  return c.json(positions.results);
});

// Stock positions: Admin update
app.put('/api/admin/stock-position/:id', adminMiddleware, async c => {
  const data = await c.req.json();
  const id = c.req.param('id');
  const db = c.env.DB;
  const fields = []; const vals = [];
  for (const k of ['shares','avg_price','current_price','symbol']) { if (data[k] !== undefined) { fields.push(k+'=?'); vals.push(data[k]); } }
  if (!fields.length) return c.json({error:'No fields to update'}, 400);
  vals.push(now(), id);
  await db.prepare('UPDATE stock_positions SET '+fields.join(',')+', updated_at=? WHERE id=?').bind(...vals).run();
  return c.json({message:'Stock position updated'});
});

// Stock positions: Admin delete
app.delete('/api/admin/stock-position/:id', adminMiddleware, async c => {
  await c.env.DB.prepare('DELETE FROM stock_positions WHERE id=?').bind(c.req.param('id')).run();
  return c.json({message:'Stock position deleted'});
});

// User wallets: Admin view all wallets summary
app.get('/api/admin/wallets', adminMiddleware, async c => {
  const wallets = await c.env.DB.prepare('SELECT w.*, u.username, u.balance, u.total_deposit, u.total_profit, u.investment_plan FROM user_wallets w LEFT JOIN users u ON w.user_id=u.id ORDER BY u.id DESC').all();
  return c.json(wallets.results);
});

// Settings: Delete a key
app.delete('/api/admin/settings/:key', adminMiddleware, async c => {
  await c.env.DB.prepare('DELETE FROM admin_settings WHERE key=?').bind(c.req.param('key')).run();
  return c.json({message:'Setting deleted'});
});

// Announcements: Toggle active
app.post('/api/admin/announcements/:id/toggle', adminMiddleware, async c => {
  await c.env.DB.prepare('UPDATE announcements SET is_active = CASE WHEN is_active=1 THEN 0 ELSE 1 END WHERE id=?').bind(c.req.param('id')).run();
  return c.json({message:'Announcement toggled'});
});

// Database stats endpoint for admin dashboard
app.get('/api/admin/db-stats', adminMiddleware, async c => {
  const db = c.env.DB;
  const tables = ['users','transactions','payment_settings','support_tickets','announcements','admin_settings','product_orders','admin_logs','user_wallets','roi_cycles','purchase_requests','stock_positions','stock_trades'];
  const counts = {};
  for (const t of tables) {
    try { counts[t] = (await db.prepare('SELECT COUNT(*) as c FROM '+t).first()).c; } catch(e) { counts[t] = -1; }
  }
  return c.json(counts);
});

// --- User Stock Routes ---
app.post('/api/user/stock/buy', authMiddleware, async c => {
  const {symbol, shares, price} = await c.req.json();
  const u = c.get('user');
  if (!symbol || !shares || !price) return c.json({error:'Symbol, shares, and price required'}, 400);
  const nShares = Number(shares);
  const nPrice = Number(price);
  if (isNaN(nShares) || nShares <= 0) return c.json({error:'Shares must be positive'}, 400);
  if (isNaN(nPrice) || nPrice <= 0) return c.json({error:'Price must be positive'}, 400);
  if (!/^[A-Z]{1,10}$/.test(symbol)) return c.json({error:'Invalid stock symbol'}, 400);
  const total = nShares * nPrice;
  const ref = genRef();
  const r = await c.env.DB.prepare('INSERT INTO stock_trades (user_id,symbol,type,shares,price,total,status) VALUES (?,?,?,?,?,?,?)').bind(u.id, symbol, 'buy', nShares, nPrice, total, 'pending').run();
  const txR = await c.env.DB.prepare('INSERT INTO transactions (user_id,type,amount,status,payment_method,reference,description,linked_type,linked_id) VALUES (?,?,?,?,?,?,?,?,?)').bind(u.id, 'deposit', total, 'pending', 'wallet', ref, 'Stock buy: '+symbol+' x'+nShares, 'stock_trade', r.meta.last_row_id).run();
  // Link transaction back to trade
  await c.env.DB.prepare('UPDATE stock_trades SET transaction_id=? WHERE id=?').bind(txR.meta.last_row_id, r.meta.last_row_id).run();
  return c.json({tradeId:r.meta.last_row_id, txId:txR.meta.last_row_id, reference:ref, total:total, message:'Stock buy submitted — await admin approval'});
});

app.post('/api/user/stock/sell', authMiddleware, async c => {
  const {symbol, shares, price} = await c.req.json();
  const u = c.get('user');
  if (!symbol || !shares || !price) return c.json({error:'Symbol, shares, and price required'}, 400);
  const nShares = Number(shares);
  const nPrice = Number(price);
  if (isNaN(nShares) || nShares <= 0) return c.json({error:'Shares must be positive'}, 400);
  if (isNaN(nPrice) || nPrice <= 0) return c.json({error:'Price must be positive'}, 400);
  if (!/^[A-Z]{1,10}$/.test(symbol)) return c.json({error:'Invalid stock symbol'}, 400);
  // Validate user holds enough shares
  const pos = await c.env.DB.prepare('SELECT shares FROM stock_positions WHERE user_id=? AND symbol=?').bind(u.id, symbol).first();
  if (!pos || Number(pos.shares) < nShares) {
    const held = pos ? Number(pos.shares) : 0;
    return c.json({error:`Insufficient shares. You hold ${held} shares of ${symbol}`}, 400);
  }
  const total = nShares * nPrice;
  const ref = genRef();
  const r = await c.env.DB.prepare('INSERT INTO stock_trades (user_id,symbol,type,shares,price,total,status) VALUES (?,?,?,?,?,?,?)').bind(u.id, symbol, 'sell', nShares, nPrice, total, 'pending').run();
  const txR = await c.env.DB.prepare('INSERT INTO transactions (user_id,type,amount,status,payment_method,reference,description,linked_type,linked_id) VALUES (?,?,?,?,?,?,?,?,?)').bind(u.id, 'withdrawal', total, 'pending', 'wallet', ref, 'Stock sell: '+symbol+' x'+nShares, 'stock_trade', r.meta.last_row_id).run();
  // Link transaction back to trade
  await c.env.DB.prepare('UPDATE stock_trades SET transaction_id=? WHERE id=?').bind(txR.meta.last_row_id, r.meta.last_row_id).run();
  return c.json({tradeId:r.meta.last_row_id, txId:txR.meta.last_row_id, reference:ref, total:total, message:'Stock sell submitted — await admin approval'});
});

app.get('/api/user/stock/positions', authMiddleware, async c => {
  const positions = await c.env.DB.prepare('SELECT * FROM stock_positions WHERE user_id=? ORDER BY symbol').bind(c.get('user').id).all();
  return c.json(positions.results);
});

app.get('/api/user/stock/trades', authMiddleware, async c => {
  const trades = await c.env.DB.prepare('SELECT * FROM stock_trades WHERE user_id=? ORDER BY created_at DESC').bind(c.get('user').id).all();
  return c.json(trades.results);
});

// Market data with simulated price changes
// S&P 500 sector data with representative stocks and market cap weights
const SP_SECTORS = {
  'Information Technology': {color:'#00d4ff', stocks:[
    {symbol:'AAPL',name:'Apple',price:192.50,change:1.8,weight:28},
    {symbol:'MSFT',name:'Microsoft',price:415.20,change:2.1,weight:22},
    {symbol:'NVDA',name:'NVIDIA',price:875.30,change:4.5,weight:15},
    {symbol:'AVGO',name:'Broadcom',price:1320.00,change:3.2,weight:5},
    {symbol:'META',name:'Meta',price:505.00,change:1.5,weight:8},
    {symbol:'AMD',name:'AMD',price:158.40,change:3.8,weight:4},
    {symbol:'CRM',name:'Salesforce',price:272.80,change:0.9,weight:3},
    {symbol:'INTC',name:'Intel',price:31.20,change:-2.3,weight:2},
    {symbol:'QCOM',name:'Qualcomm',price:178.50,change:1.1,weight:3},
    {symbol:'TXN',name:'Texas Instr.',price:178.30,change:0.6,weight:3}
  ]},
  'Healthcare': {color:'#22c55e', stocks:[
    {symbol:'UNH',name:'UnitedHealth',price:528.40,change:0.5,weight:25},
    {symbol:'JNJ',name:'Johnson&Johnson',price:155.80,change:-0.3,weight:12},
    {symbol:'PFE',name:'Pfizer',price:28.50,change:-1.2,weight:5},
    {symbol:'ABBV',name:'AbbVie',price:171.20,change:1.1,weight:10},
    {symbol:'MRK',name:'Merck',price:126.40,change:0.8,weight:8},
    {symbol:'LLY',name:'Eli Lilly',price:785.00,change:2.8,weight:15},
    {symbol:'TMO',name:'Thermo Fisher',price:572.30,change:0.4,weight:6}
  ]},
  'Financials': {color:'#f59e0b', stocks:[
    {symbol:'BRK.B',name:'Berkshire',price:415.20,change:0.7,weight:20},
    {symbol:'JPM',name:'JPMorgan',price:198.50,change:1.3,weight:15},
    {symbol:'V',name:'Visa',price:278.40,change:0.9,weight:15},
    {symbol:'MA',name:'Mastercard',price:462.30,change:1.1,weight:12},
    {symbol:'BAC',name:'Bank of America',price:37.80,change:0.4,weight:8},
    {symbol:'GS',name:'Goldman Sachs',price:425.60,change:1.8,weight:6},
    {symbol:'MS',name:'Morgan Stanley',price:92.30,change:1.5,weight:5}
  ]},
  'Consumer Discretionary': {color:'#e879f9', stocks:[
    {symbol:'AMZN',name:'Amazon',price:185.60,change:2.2,weight:35},
    {symbol:'TSLA',name:'Tesla',price:248.50,change:3.2,weight:20},
    {symbol:'HD',name:'Home Depot',price:345.20,change:-0.5,weight:12},
    {symbol:'MCD',name:'McDonalds',price:278.40,change:0.2,weight:8},
    {symbol:'NKE',name:'Nike',price:94.50,change:-1.8,weight:5},
    {symbol:'SBUX',name:'Starbucks',price:78.30,change:0.6,weight:5}
  ]},
  'Communication Services': {color:'#8b5cf6', stocks:[
    {symbol:'GOOGL',name:'Alphabet',price:172.50,change:1.6,weight:35},
    {symbol:'META',name:'Meta',price:505.00,change:1.5,weight:30},
    {symbol:'DIS',name:'Disney',price:112.30,change:-0.8,weight:8},
    {symbol:'NFLX',name:'Netflix',price:628.40,change:2.4,weight:12},
    {symbol:'T',name:'AT&T',price:17.80,change:0.3,weight:5},
    {symbol:'VZ',name:'Verizon',price:42.10,change:-0.4,weight:6}
  ]},
  'Industrials': {color:'#06b6d4', stocks:[
    {symbol:'GE',name:'GE Aero',price:162.40,change:1.4,weight:15},
    {symbol:'CAT',name:'Caterpillar',price:342.50,change:0.8,weight:15},
    {symbol:'BA',name:'Boeing',price:178.30,change:0.8,weight:12},
    {symbol:'UNP',name:'Union Pacific',price:238.40,change:0.6,weight:12},
    {symbol:'HON',name:'Honeywell',price:205.30,change:0.5,weight:10},
    {symbol:'UPS',name:'UPS',price:142.60,change:-0.9,weight:8}
  ]},
  'Consumer Staples': {color:'#84cc16', stocks:[
    {symbol:'WMT',name:'Walmart',price:168.40,change:0.3,weight:25},
    {symbol:'PG',name:'Procter&Gamble',price:162.50,change:-0.2,weight:18},
    {symbol:'KO',name:'Coca-Cola',price:62.30,change:0.1,weight:15},
    {symbol:'PEP',name:'PepsiCo',price:172.80,change:0.4,weight:14},
    {symbol:'COST',name:'Costco',price:825.00,change:0.7,weight:12},
    {symbol:'PM',name:'Philip Morris',price:92.40,change:0.9,weight:10}
  ]},
  'Energy': {color:'#ef4444', stocks:[
    {symbol:'XOM',name:'ExxonMobil',price:112.50,change:-1.2,weight:30},
    {symbol:'CVX',name:'Chevron',price:158.30,change:-0.8,weight:25},
    {symbol:'COP',name:'ConocoPhillips',price:112.80,change:-0.5,weight:12},
    {symbol:'SLB',name:'Schlumberger',price:48.60,change:0.4,weight:8},
    {symbol:'EOG',name:'EOG Resources',price:128.40,change:-0.3,weight:8},
    {symbol:'OXY',name:'Occidental',price:62.10,change:0.8,weight:7}
  ]},
  'Utilities': {color:'#14b8a6', stocks:[
    {symbol:'NEE',name:'NextEra',price:72.40,change:0.2,weight:25},
    {symbol:'DUK',name:'Duke Energy',price:94.30,change:-0.1,weight:18},
    {symbol:'SO',name:'Southern Co',price:82.60,change:0.3,weight:15},
    {symbol:'D',name:'Dominion',price:52.80,change:-0.4,weight:12},
    {symbol:'EXC',name:'Exelon',price:38.20,change:0.1,weight:10}
  ]},
  'Real Estate': {color:'#f97316', stocks:[
    {symbol:'PLD',name:'Prologis',price:118.40,change:-0.6,weight:20},
    {symbol:'AMT',name:'AmTower',price:185.30,change:0.3,weight:18},
    {symbol:'CCI',name:'Crown Castle',price:92.50,change:-0.9,weight:15},
    {symbol:'EQIX',name:'Equinix',price:782.00,change:0.7,weight:15},
    {symbol:'O',name:'Realty Income',price:55.20,change:-0.2,weight:10},
    {symbol:'SPG',name:'Simon Prop',price:182.60,change:0.5,weight:12}
  ]},
  'Materials': {color:'#a78bfa', stocks:[
    {symbol:'LIN',name:'Linde',price:442.50,change:0.6,weight:22},
    {symbol:'APD',name:'Air Products',price:235.40,change:-0.3,weight:15},
    {symbol:'SHW',name:'Sherwin-Williams',price:285.30,change:0.4,weight:15},
    {symbol:'NEM',name:'Newmont',price:42.80,change:1.8,weight:8},
    {symbol:'FCX',name:'Freeport-McMoRan',price:42.60,change:2.1,weight:10},
    {symbol:'DD',name:'DuPont',price:78.30,change:0.2,weight:8}
  ]}
};

// Random walk state for streaming (persists per-instance)
let _quoteState = {};
let _quoteTick = 0;

function streamQuotes(allStocks) {
  _quoteTick++;
  const t = _quoteTick;
  return allStocks.map((s, i) => {
    // Initialize state
    if (!_quoteState[s.symbol]) {
      _quoteState[s.symbol] = { price: s.price, change: s.change, vol: (Math.random()*5+1).toFixed(1) };
    }
    const st = _quoteState[s.symbol];
    // Random walk: small Brownian motion step
    const drift = (Math.random()-0.48) * 0.003; // slight upward bias
    const shock = (Math.random()-0.5) * 0.008 * Math.sqrt(1); // volatility
    st.price = st.price * (1 + drift + shock);
    st.price = Math.round(st.price * 100) / 100;
    // Update change % from base
    st.change = Math.round(((st.price / s.price - 1) * 100 + s.change) * 100) / 100;
    // Volume tick
    if (t % 3 === 0) st.vol = (Number(st.vol) + (Math.random()-0.5)*0.4).toFixed(1);
    return {
      symbol: s.symbol,
      name: s.name,
      price: st.price,
      change: st.change,
      sector: s.sector || '',
      volume: st.vol + 'M',
      tick: t,
      ts: Date.now()
    };
  });
}

app.get('/api/market/stocks', async c => {
  // Merge all stocks from SP sectors + platform-specific stocks
  const allStocks = [];
  for (const [sector, data] of Object.entries(SP_SECTORS)) {
    for (const s of data.stocks) {
      allStocks.push({...s, sector});
    }
  }
  // Add platform-specific stocks
  allStocks.push(
    {symbol:'SPCE',name:'Virgin Galactic',price:12.80,change:-1.5,sector:'Space'},
    {symbol:'LMT',name:'Lockheed Martin',price:475.20,change:1.1,sector:'Defense'},
    {symbol:'RKLB',name:'Rocket Lab',price:8.45,change:5.3,sector:'Space'},
    {symbol:'ASTR',name:'Astra Space',price:3.20,change:-2.1,sector:'Space'},
    {symbol:'JOBY',name:'Joby Aviation',price:6.75,change:2.8,sector:'eVTOL'},
    {symbol:'RIVN',name:'Rivian Auto.',price:18.90,change:4.1,sector:'EV'},
    {symbol:'LCID',name:'Lucid Motors',price:5.40,change:-1.8,sector:'EV'},
    {symbol:'NIO',name:'NIO Inc.',price:7.80,change:2.5,sector:'EV'},
    {symbol:'MSTR',name:'MicroStrategy',price:1650.00,change:6.2,sector:'Crypto'}
  );
  return c.json(streamQuotes(allStocks));
});

// Sector performance endpoint for heatmap
app.get('/api/market/sectors', async c => {
  const result = [];
  for (const [name, data] of Object.entries(SP_SECTORS)) {
    const quotes = data.stocks.map(s => {
      if (!_quoteState[s.symbol]) {
        _quoteState[s.symbol] = { price: s.price, change: s.change, vol: (Math.random()*5+1).toFixed(1) };
      }
      return _quoteState[s.symbol];
    });
    // Weighted average change
    const totalWeight = data.stocks.reduce((a,s) => a + s.weight, 0);
    const avgChange = quotes.reduce((a,q,i) => a + q.change * data.stocks[i].weight, 0) / totalWeight;
    result.push({
      name,
      color: data.color,
      change: Math.round(avgChange * 100) / 100,
      stocks: quotes.map((q,i) => ({
        symbol: data.stocks[i].symbol,
        name: data.stocks[i].name,
        price: q.price,
        change: q.change,
        weight: data.stocks[i].weight,
        volume: q.vol + 'M'
      }))
    });
  }
  return c.json({sectors: result, tick: _quoteTick, ts: Date.now()});
});

// ===================== EXTERNAL API (Consignment / Partner Integration) =====================
// API key middleware for external access
const externalApiKeyMiddleware = async (c, next) => {
  const apiKey = c.req.header('X-API-Key') || (await c.req.json().catch(() => ({}))).api_key;
  const storedKey = await c.env.DB.prepare("SELECT value FROM admin_settings WHERE key='external_api_key'").first();
  if (!storedKey || !apiKey || apiKey !== storedKey.value) {
    return c.json({error: 'Invalid or missing API key. Provide X-API-Key header.'}, 401);
  }
  await next();
};

// List available products for external checkout
app.get('/api/external/products', externalApiKeyMiddleware, async c => {
  const products = [
    {id: 'tesla-model-s', name: 'Tesla Model S', price: 79990, image: 'https://quantumx.win/images/tesla-model-s.jpg'},
    {id: 'tesla-model-y', name: 'Tesla Model Y', price: 49990, image: 'https://quantumx.win/images/tesla-model-y.jpg'},
    {id: 'tesla-model-3', name: 'Tesla Model 3', price: 42990, image: 'https://quantumx.win/images/tesla-model-3.jpg'},
    {id: 'tesla-model-x', name: 'Tesla Model X', price: 89990, image: 'https://quantumx.win/images/tesla-model-x.jpg'},
    {id: 'tesla-cybertruck', name: 'Tesla Cybertruck', price: 69990, image: 'https://quantumx.win/images/tesla-cybertruck.jpg'},
    {id: 'optimus-bot', name: 'Optimus Bot', price: 25000, image: 'https://quantumx.win/images/optimus-bot.jpg'}
  ];
  // Also get payment methods (Bitcoin wallet for immediate payment)
  const methods = await c.env.DB.prepare('SELECT method, display_name, details FROM payment_settings WHERE is_active=1').all();
  return c.json({products, payment_methods: methods.results, site: 'https://quantumx.win'});
});

// Create checkout order from external site
app.post('/api/external/checkout', externalApiKeyMiddleware, async c => {
  const data = await c.req.json();
  const productMap = {
    'tesla-model-s': {name: 'Tesla Model S', price: 79990},
    'tesla-model-y': {name: 'Tesla Model Y', price: 49990},
    'tesla-model-3': {name: 'Tesla Model 3', price: 42990},
    'tesla-model-x': {name: 'Tesla Model X', price: 89990},
    'tesla-cybertruck': {name: 'Tesla Cybertruck', price: 69990},
    'optimus-bot': {name: 'Optimus Bot', price: 25000}
  };
  const product = productMap[data.product_id];
  if (!product) return c.json({error: 'Invalid product_id. Valid: ' + Object.keys(productMap).join(', ')}, 400);

  const payment_method = data.payment_method || 'bitcoin';
  const methodRow = await c.env.DB.prepare("SELECT method, display_name, details FROM payment_settings WHERE method=? AND is_active=1").bind(payment_method).first();
  if (!methodRow) return c.json({error: 'Invalid payment method'}, 400);

  // Find or create user by email (from consignment site)
  const email = data.customer_email;
  if (!email) return c.json({error: 'customer_email required'}, 400);
  let user = await c.env.DB.prepare('SELECT id FROM users WHERE email=?').bind(email).first();
  if (!user) {
    // Auto-create a user account for the consignment customer
    const bcrypt = (await import('bcryptjs')).default;
    const tempPw = bcrypt.hashSync('Qsx' + Math.random().toString(36).slice(2) + '!1', 10);
    const username = (data.customer_name || email.split('@')[0]).replace(/[^a-zA-Z0-9_]/g,'').slice(0,30);
    const resetHash = bcrypt.hashSync('consignment-' + Math.random().toString(36).slice(2,10), 10);
    try {
      const r = await c.env.DB.prepare('INSERT INTO users (username,email,full_name,phone,password_hash,reset_phrase_hash,is_active) VALUES (?,?,?,?,?,?,1)').bind(username, email, data.customer_name||username, data.customer_phone||'', tempPw, resetHash).run();
      user = {id: r.meta.last_row_id};
      // Create wallet
      await c.env.DB.prepare('INSERT INTO user_wallets (user_id) VALUES (?)').bind(user.id).run();
    } catch(e) {
      return c.json({error: 'Failed to create user: ' + e.message}, 400);
    }
  }

  // Create deposit transaction
  const ref = genRef();
  const txRef = await c.env.DB.prepare('INSERT INTO transactions (user_id,type,amount,status,payment_method,reference,description) VALUES (?,?,?,?,?,?,?)').bind(user.id,'deposit',product.price,'pending',payment_method,ref,'Consignment order: '+product.name).run();

  // Create product order
  const orderRef = 'QSX-' + Math.random().toString(36).slice(2,8).toUpperCase();
  const orderR = await c.env.DB.prepare('INSERT INTO product_orders (user_id,product_name,product_price,quantity,payment_method,shipping_address,status,reference) VALUES (?,?,?,?,?,?,?,?)').bind(user.id, product.name, product.price, 1, payment_method, data.shipping_address||'Pending', 'pending', orderRef).run();

  // Get payment details for response
  let paymentDetails = {};
  try { paymentDetails = JSON.parse(methodRow.details || '{}'); } catch(e) {}
  if (payment_method === 'bitcoin') {
    paymentDetails = {wallet_address: 'bc1q04k3fuas4eratzmv9padu9zjf7dwh4xv0s23k6', network: 'Bitcoin'};
  }

  // Send inbox message to user
  try {
    await c.env.DB.prepare('INSERT INTO user_messages (user_id,title,body,type,from_admin,reference) VALUES (?,?,?,?,1,?)').bind(user.id,
      '🛍️ Consignment Order Placed',
      'Your order for ' + product.name + ' ($' + product.price.toLocaleString() + ') has been placed from our partner store.\n\nOrder Ref: ' + orderRef + '\nDeposit Ref: ' + ref + '\n\nPlease complete payment and admin will confirm your order.',
      'order', orderRef
    ).run();
  } catch(e) {}

  return c.json({
    success: true,
    order: {
      id: orderR.meta.last_row_id,
      reference: orderRef,
      product: product.name,
      price: product.price,
      status: 'pending'
    },
    deposit: {
      reference: ref,
      amount: product.price,
      payment_method,
      payment_details: paymentDetails
    },
    checkout_url: 'https://quantumx.win/#/dashboard',
    message: 'Order created. Customer should complete payment on Quantum Space X.'
  }, 201);
});

// Check order status (external)
app.get('/api/external/order/:ref', externalApiKeyMiddleware, async c => {
  const ref = c.req.param('ref');
  const order = await c.env.DB.prepare('SELECT po.*, u.username, u.email FROM product_orders po JOIN users u ON u.id=po.user_id WHERE po.reference=?').bind(ref).first();
  if (!order) return c.json({error: 'Order not found'}, 404);
  return c.json({
    reference: order.reference,
    product: order.product_name,
    price: Number(order.product_price),
    quantity: order.quantity,
    status: order.status,
    payment_method: order.payment_method,
    shipping_address: order.shipping_address,
    customer: {username: order.username, email: order.email},
    created_at: order.created_at,
    updated_at: order.updated_at
  });
});

// Admin: manage API key
app.get('/api/admin/external-api-key', adminMiddleware, async c => {
  const r = await c.env.DB.prepare("SELECT value FROM admin_settings WHERE key='external_api_key'").first();
  return c.json({api_key: r ? r.value : null});
});

app.post('/api/admin/external-api-key/regenerate', adminMiddleware, async c => {
  const newKey = 'qsx_' + Array.from(crypto.getRandomValues(new Uint8Array(24))).map(b => b.toString(16).padStart(2,'0')).join('');
  await c.env.DB.prepare("INSERT OR REPLACE INTO admin_settings (key, value) VALUES ('external_api_key', ?)").bind(newKey).run();
  return c.json({api_key: newKey, message: 'API key regenerated'});
});

// ===================== DELIVERY MANAGEMENT =====================
// Get deliveries for a user
app.get('/api/user/deliveries', authMiddleware, async c => {
  const u = c.get('user');
  const deliveries = await c.env.DB.prepare('SELECT * FROM deliveries WHERE user_id=? ORDER BY created_at DESC').bind(u.id).all();
  return c.json(deliveries.results);
});

// Admin: list all deliveries
app.get('/api/admin/deliveries', adminMiddleware, async c => {
  const deliveries = await c.env.DB.prepare('SELECT d.*, u.username, u.email FROM deliveries d JOIN users u ON u.id=d.user_id ORDER BY d.created_at DESC LIMIT 100').all();
  return c.json(deliveries.results);
});

// Admin: create delivery for an order
app.post('/api/admin/deliveries', adminMiddleware, async c => {
  const data = await c.req.json();
  if (!data.user_id) return c.json({error:'user_id required'}, 400);
  const r = await c.env.DB.prepare(
    'INSERT INTO deliveries (order_id,user_id,product_name,product_price,shipping_fee,status,origin_location,destination,dispatch_date,estimated_delivery,carrier,tracking_number,driver_name,driver_phone,notes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
  ).bind(
    data.order_id||null, data.user_id, data.product_name||'', Number(data.product_price)||0, Number(data.shipping_fee)||0,
    data.status||'preparing', data.origin_location||'', data.destination||'',
    data.dispatch_date||null, data.estimated_delivery||null, data.carrier||'', data.tracking_number||'',
    data.driver_name||'', data.driver_phone||'', data.notes||''
  ).run();
  // Send inbox notification
  await c.env.DB.prepare('INSERT INTO user_messages (user_id,title,body,type,from_admin) VALUES (?,?,?,?,1)').bind(
    data.user_id, '🚚 Delivery Created',
    `Your delivery for ${data.product_name||'order'} has been created. Status: Preparing. ${data.origin_location ? 'Origin: '+data.origin_location : ''}`,
    'order'
  ).run();
  return c.json({id:r.meta.last_row_id, message:'Delivery created'}, 201);
});

// Admin: update delivery status
app.patch('/api/admin/deliveries/:id', adminMiddleware, async c => {
  const id = c.req.param('id');
  const data = await c.req.json();
  const fields = [];
  const vals = [];
  for (const k of ['status','origin_location','current_location','destination','dispatch_date','estimated_delivery','delivered_date','carrier','tracking_number','driver_name','driver_phone','notes','receipt_generated']) {
    if (data[k] !== undefined) { fields.push(k+'=?'); vals.push(data[k]); }
  }
  if (!fields.length) return c.json({error:'No fields to update'}, 400);
  fields.push('updated_at=?'); vals.push(now());
  await c.env.DB.prepare('UPDATE deliveries SET '+fields.join(',')+' WHERE id=?').bind(...vals, id).run();

  // Send inbox notification on status change
  if (data.status) {
    const d = await c.env.DB.prepare('SELECT * FROM deliveries WHERE id=?').bind(id).first();
    if (d) {
      const statusLabels = {
        preparing: '📦 Preparing your order',
        dispatched: '🚀 Order dispatched',
        in_transit: '🚛 In transit',
        out_for_delivery: '🚗 Out for delivery',
        delivered: '✅ Delivered!'
      };
      const statusDescs = {
        preparing: 'Your order is being prepared for shipping.',
        dispatched: `Your order has been dispatched${d.origin_location?' from '+d.origin_location:''}.`,
        in_transit: `Your order is in transit${d.current_location?'. Current location: '+d.current_location:''}.`,
        out_for_delivery: 'Your order is out for delivery! Expect it soon.',
        delivered: `Your order has been delivered${d.delivered_date?' on '+d.delivered_date:''}!`
      };
      await c.env.DB.prepare('INSERT INTO user_messages (user_id,title,body,type,from_admin) VALUES (?,?,?,?,1)').bind(
        d.user_id, statusLabels[data.status]||'📦 Delivery Update', statusDescs[data.status]||'Your delivery status has been updated.', 'order'
      ).run();
    }
  }
  return c.json({message:'Delivery updated'});
});

// Admin: generate receipt
app.post('/api/admin/deliveries/:id/receipt', adminMiddleware, async c => {
  const id = c.req.param('id');
  const d = await c.env.DB.prepare('SELECT d.*, u.username, u.email, u.full_name FROM deliveries d JOIN users u ON u.id=d.user_id WHERE d.id=?').bind(id).first();
  if (!d) return c.json({error:'Delivery not found'}, 404);
  await c.env.DB.prepare('UPDATE deliveries SET receipt_generated=1, updated_at=? WHERE id=?').bind(now(), id).run();
  // Send inbox with receipt
  const receiptNo = 'RCP-' + String(id).padStart(6,'0');
  const receiptBody = `Receipt #${receiptNo}\n\nProduct: ${d.product_name}\nProduct Price: $${Number(d.product_price).toFixed(2)}\nShipping Fee: $${Number(d.shipping_fee).toFixed(2)}\nTotal: $${(Number(d.product_price)+Number(d.shipping_fee)).toFixed(2)}\n\nStatus: ${d.status}\nOrigin: ${d.origin_location||'N/A'}\nDestination: ${d.destination||'N/A'}\nCarrier: ${d.carrier||'N/A'}\nTracking #: ${d.tracking_number||'N/A'}\n${d.delivered_date ? 'Delivered: '+d.delivered_date : ''}\n\nThank you for your order!`;
  await c.env.DB.prepare('INSERT INTO user_messages (user_id,title,body,type,from_admin) VALUES (?,?,?,?,1)').bind(
    d.user_id, `🧾 Receipt #${receiptNo}`, receiptBody, 'order'
  ).run();
  return c.json({receipt_no: receiptNo, delivery: d, message:'Receipt generated and sent to user'});
});

// Admin: authenticate sale (confirm and send to user)
app.post('/api/admin/deliveries/:id/authenticate-sale', adminMiddleware, async c => {
  const id = c.req.param('id');
  const d = await c.env.DB.prepare('SELECT d.*, u.username, u.email, u.full_name FROM deliveries d JOIN users u ON u.id=d.user_id WHERE d.id=?').bind(id).first();
  if (!d) return c.json({error:'Delivery not found'}, 404);
  // Mark as delivered
  await c.env.DB.prepare('UPDATE deliveries SET status=?, delivered_date=?, updated_at=? WHERE id=?').bind('delivered', now(), now(), id).run();
  // Send authenticated sale notification with receipt
  const receiptNo = 'RCP-' + String(id).padStart(6,'0');
  const total = Number(d.product_price) + Number(d.shipping_fee);
  const saleBody = `✅ Sale Authenticated & Confirmed\n\nReceipt #${receiptNo}\nProduct: ${d.product_name}\nAmount: $${total.toFixed(2)}\nStatus: Delivered ✓\nDelivered: ${now()}\n\nThis sale has been verified and authenticated by Quantum Space X admin.\n\nThank you for your purchase!`;
  await c.env.DB.prepare('INSERT INTO user_messages (user_id,title,body,type,from_admin) VALUES (?,?,?,?,1)').bind(
    d.user_id, '✅ Sale Authenticated — ' + d.product_name, saleBody, 'order'
  ).run();
  return c.json({message:'Sale authenticated, delivery marked as delivered, receipt sent to user', receipt_no: receiptNo});
});

// Admin: delete delivery
app.delete('/api/admin/deliveries/:id', adminMiddleware, async c => {
  await c.env.DB.prepare('DELETE FROM deliveries WHERE id=?').bind(c.req.param('id')).run();
  return c.json({message:'Delivery deleted'});
});

// ===================== STATIC ASSETS + SPA FALLBACK =====================
// [assets] binding serves static files. For non-API routes, serve via ASSETS binding.
export default {
  fetch: async (request, env, ctx) => {
    const url = new URL(request.url);
    // API routes: let Hono handle
    if (url.pathname.startsWith('/api/')) {
      return app.fetch(request, env, ctx);
    }
    // Static files: use ASSETS binding (from [assets] config)
    if (env.ASSETS) {
      const assetResp = await env.ASSETS.fetch(request);
      if (assetResp.status === 200) return assetResp;
    }
    // SPA fallback: serve index.html (app.html) for any unmatched route
    if (env.ASSETS) {
      const spaReq = new Request(new URL('/index.html', url.origin));
      const spaResp = await env.ASSETS.fetch(spaReq);
      if (spaResp.status === 200) return spaResp;
    }
    return new Response('Not Found', {status: 404});
  }
};
