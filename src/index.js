import { Hono } from 'hono';
import { cors } from 'hono/cors';
import bcrypt from 'bcryptjs';

const app = new Hono();
app.use('/*', cors({ origin: '*', allowMethods: ['GET','POST','PUT','DELETE','OPTIONS'], allowHeaders: ['Content-Type','Authorization'] }));

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
  return c.json({token, user:{id:user.id, username:user.username, email:user.email, full_name:user.full_name, isAdmin:user.is_admin, investment_plan:user.investment_plan, balance:user.balance, total_deposit:user.total_deposit}});
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
  const methods = await c.env.DB.prepare("SELECT method FROM payment_settings WHERE method=? AND is_active=1").bind(payment_method).first();
  if (!methods) return c.json({error:'Invalid payment method'}, 400);
  const ref = genRef();
  const r = await c.env.DB.prepare('INSERT INTO transactions (user_id,type,amount,status,payment_method,reference,description) VALUES (?,?,?,?,?,?,?)').bind(u.id,'deposit',amount,'pending',payment_method,ref,'Deposit request').run();
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

// ===================== ADMIN ROUTES =====================

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
  const fields = []; const vals = [];
  for (const k of ['full_name','email','phone','is_active','investment_plan']) { if (data[k] !== undefined) { fields.push(k+'=?'); vals.push(data[k]); } }
  if (!fields.length) return c.json({error:'No fields to update'}, 400);
  vals.push(id);
  await c.env.DB.prepare('UPDATE users SET '+fields.join(',')+', updated_at=? WHERE id=?').bind(...vals, now(), id).run();
  return c.json({message:'User updated'});
});

app.delete('/api/admin/user/:id', adminMiddleware, async c => {
  await c.env.DB.prepare('DELETE FROM users WHERE id=?').bind(c.req.param('id')).run();
  return c.json({message:'User deleted'});
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
  await c.env.DB.prepare('UPDATE users SET is_active = CASE WHEN is_active=1 THEN 0 ELSE 1 END WHERE id=?').bind(c.req.param('id')).run();
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
  await c.env.DB.prepare('UPDATE product_orders SET status=?, updated_at=? WHERE id=?').bind(status, now(), c.req.param('id')).run();
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
  return c.json({message:'Stock trade rejected'});
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
app.get('/api/market/stocks', async c => {
  const baseStocks = [
    {symbol:'TSLA',name:'Tesla Inc.',price:248.50,change:3.2,sector:'EV'},
    {symbol:'SPCE',name:'Virgin Galactic',price:12.80,change:-1.5,sector:'Space'},
    {symbol:'BA',name:'Boeing Co.',price:178.30,change:0.8,sector:'Aero'},
    {symbol:'LMT',name:'Lockheed Martin',price:475.20,change:1.1,sector:'Defense'},
    {symbol:'RKLB',name:'Rocket Lab',price:8.45,change:5.3,sector:'Space'},
    {symbol:'ASTR',name:'Astra Space',price:3.20,change:-2.1,sector:'Space'},
    {symbol:'JOBY',name:'Joby Aviation',price:6.75,change:2.8,sector:'eVTOL'},
    {symbol:'PCAR',name:'Paccar Inc.',price:102.40,change:0.5,sector:'EV'},
    {symbol:'GM',name:'General Motors',price:45.60,change:1.2,sector:'Auto'},
    {symbol:'F',name:'Ford Motor',price:14.30,change:-0.3,sector:'Auto'},
    {symbol:'RIVN',name:'Rivian Auto.',price:18.90,change:4.1,sector:'EV'},
    {symbol:'LCID',name:'Lucid Motors',price:5.40,change:-1.8,sector:'EV'},
    {symbol:'NIO',name:'NIO Inc.',price:7.80,change:2.5,sector:'EV'},
    {symbol:'MSTR',name:'MicroStrategy',price:1650.00,change:6.2,sector:'Crypto'}
  ];
  // Add small random fluctuation for realism
  const seeded = Date.now() % 1000;
  const result = baseStocks.map((s, i) => {
    const fluctuation = Math.sin(seeded * (i+1) * 0.001) * 0.02;
    return {...s, price: Math.round(s.price * (1 + fluctuation) * 100) / 100};
  });
  return c.json(result);
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
