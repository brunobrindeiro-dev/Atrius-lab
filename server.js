const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');

const app = express();
app.use(cors());
app.use(express.json());

// ── CREDENCIAIS SUPABASE ──
const SUPABASE_URL = 'https://jlalaewkilfhhkpmxflu.supabase.co';
const SUPABASE_SERVICE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImpsYWxhZXdraWxmaGhrcG14Zmx1Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3NDU1MTMwMCwiZXhwIjoyMDkwMTI3MzAwfQ.HlG319xOfepkUKxdq89icHJY_uRO8jW2_DWU4XtrqqM';
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const GESTOR_SECRET = 'atrius-gestor-2026';

// ── HELPER SUPABASE ──
async function sb(path, options = {}) {
  const fetch = (await import('node-fetch')).default;
  const res = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, {
    ...options,
    headers: {
      'apikey': SUPABASE_SERVICE_KEY,
      'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
      'Content-Type': 'application/json',
      'Prefer': options.prefer || 'return=representation',
      ...(options.headers || {})
    }
  });
  const text = await res.text();
  if (!res.ok) throw new Error(text);
  return text ? JSON.parse(text) : [];
}

// ── MIDDLEWARE GESTOR ──
function requireGestor(req, res, next) {
  if (req.headers['x-gestor-secret'] !== GESTOR_SECRET) {
    return res.status(403).json({ error: 'Acesso negado' });
  }
  next();
}

// ── HEALTH ──
app.get('/health', (req, res) => res.json({ status: 'ok' }));

// ══════════════════════════════════════════
// AUTH
// ══════════════════════════════════════════

// Login de usuário (cliente)
app.post('/api/auth/login', async (req, res) => {
  try {
    const { code, user, senha } = req.body;
    if (!code || !user) return res.status(400).json({ error: 'Dados incompletos' });

    const labs = await sb(`laboratorios?codigo=eq.${encodeURIComponent(code.toUpperCase())}&ativo=eq.true`);
    if (!labs.length) return res.status(401).json({ error: 'Laboratório não encontrado' });
    const lab = labs[0];

    const users = await sb(`usuarios?lab_id=eq.${lab.id}&usuario=eq.${encodeURIComponent(user.toLowerCase())}&ativo=eq.true`);
    if (!users.length) return res.status(401).json({ error: 'Usuário não encontrado' });
    const userObj = users[0];

    // Se senha foi enviada (não null/undefined/vazio), verificar no backend
    if (senha && senha !== 'null') {
      const hash = userObj.senha;
      let senhaOk = false;
      if (hash && hash.startsWith('$2')) {
        senhaOk = await bcrypt.compare(senha, hash);
      } else {
        // senha em texto puro (legado)
        senhaOk = (senha === hash);
      }
      if (!senhaOk) return res.status(401).json({ error: 'Senha incorreta' });
      // Migrar senha para hash se ainda for texto puro
      if (hash && !hash.startsWith('$2')) {
        const novoHash = await bcrypt.hash(senha, 10);
        await sb(`usuarios?id=eq.${userObj.id}`, {
          method: 'PATCH', body: JSON.stringify({ senha: novoHash }), prefer: 'return=minimal'
        });
      }
      return res.json({ lab, user: userObj });
    }

    // Compatibilidade: retornar hash para verificação no frontend (legado)
    res.json({ lab, user: userObj, senhaHash: userObj.senha });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Login alternativo para sessão restaurada (busca por lab+usuario sem senha)
app.get('/api/auth/login-lab', async (req, res) => {
  try {
    const { 'codigo': code, 'ativo': ativo } = req.query;
    if (!code) return res.status(400).json({ error: 'Código obrigatório' });
    const labs = await sb(`laboratorios?codigo=eq.${encodeURIComponent(code)}&ativo=eq.true`);
    res.json(labs);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Alterar senha de usuário
app.patch('/api/usuarios/:id/senha', async (req, res) => {
  try {
    const { id } = req.params;
    const { senhaHash } = req.body;
    await sb(`usuarios?id=eq.${id}`, {
      method: 'PATCH',
      body: JSON.stringify({ senha: senhaHash }),
      prefer: 'return=minimal'
    });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Migrar senha para hash
app.patch('/api/auth/migrar-senha', async (req, res) => {
  try {
    const { userId, senhaHash } = req.body;
    await sb(`usuarios?id=eq.${userId}`, {
      method: 'PATCH',
      body: JSON.stringify({ senha: senhaHash }),
      prefer: 'return=minimal'
    });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════════════════
// ESTOQUE
// ══════════════════════════════════════════

app.get('/api/estoque', async (req, res) => {
  try {
    const labId = req.headers['x-lab-id'];
    if (!labId) return res.status(400).json({ error: 'lab_id obrigatório' });
    const data = await sb(`estoque?lab_id=eq.${labId}&order=criado_em.desc`);
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/estoque', async (req, res) => {
  try {
    const labId = req.headers['x-lab-id'];
    const body = { ...req.body, lab_id: labId };
    const data = await sb('estoque', { method: 'POST', body: JSON.stringify(body) });
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/estoque/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const data = await sb(`estoque?id=eq.${id}`, {
      method: 'PATCH', body: JSON.stringify(req.body), prefer: 'return=representation'
    });
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/estoque/:id', async (req, res) => {
  try {
    const { id } = req.params;
    // Excluir movimentações vinculadas antes de excluir o item
    await sb(`movimentacoes?item_id=eq.${id}`, { method: 'DELETE', prefer: 'return=minimal' });
    await sb(`estoque?id=eq.${id}`, { method: 'DELETE', prefer: 'return=minimal' });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════
// MOVIMENTAÇÕES
// ══════════════════════════════════════════

app.get('/api/movimentacoes', async (req, res) => {
  try {
    const labId = req.headers['x-lab-id'];
    if (!labId) return res.status(400).json({ error: 'lab_id obrigatório' });
    const limit = req.query.limit || 200;
    const data = await sb(`movimentacoes?lab_id=eq.${labId}&order=criado_em.desc&limit=${limit}`);
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/movimentacoes', async (req, res) => {
  try {
    const labId = req.headers['x-lab-id'];
    const body = { ...req.body, lab_id: labId };
    const data = await sb('movimentacoes', { method: 'POST', body: JSON.stringify(body) });
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/movimentacoes', async (req, res) => {
  try {
    const labId = req.headers['x-lab-id'];
    await sb(`movimentacoes?lab_id=eq.${labId}`, { method: 'DELETE', prefer: 'return=minimal' });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════
// USUÁRIOS
// ══════════════════════════════════════════

app.get('/api/usuarios', async (req, res) => {
  try {
    const labId = req.headers['x-lab-id'];
    if (!labId) return res.status(400).json({ error: 'lab_id obrigatório' });
    const data = await sb(`usuarios?lab_id=eq.${labId}&order=criado_em.desc`);
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/usuarios', async (req, res) => {
  try {
    const labId = req.headers['x-lab-id'];
    const body = { ...req.body, lab_id: labId };
    const data = await sb('usuarios', { method: 'POST', body: JSON.stringify(body) });
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/usuarios/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const data = await sb(`usuarios?id=eq.${id}`, {
      method: 'PATCH', body: JSON.stringify(req.body), prefer: 'return=representation'
    });
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/usuarios/:id', async (req, res) => {
  try {
    const { id } = req.params;
    await sb(`usuarios?id=eq.${id}`, { method: 'DELETE', prefer: 'return=minimal' });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════
// FORNECEDORES
// ══════════════════════════════════════════

app.get('/api/fornecedores', async (req, res) => {
  try {
    const labId = req.headers['x-lab-id'];
    const data = await sb(`fornecedores?lab_id=eq.${labId}&order=nome.asc`);
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/fornecedores', async (req, res) => {
  try {
    const labId = req.headers['x-lab-id'];
    const body = { ...req.body, lab_id: labId };
    const data = await sb('fornecedores', { method: 'POST', body: JSON.stringify(body) });
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/fornecedores/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const data = await sb(`fornecedores?id=eq.${id}`, {
      method: 'PATCH', body: JSON.stringify(req.body), prefer: 'return=representation'
    });
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/fornecedores/:id', async (req, res) => {
  try {
    const { id } = req.params;
    await sb(`fornecedores?id=eq.${id}`, { method: 'DELETE', prefer: 'return=minimal' });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════
// LABORATÓRIOS (self-service)
// ══════════════════════════════════════════

app.get('/api/laboratorios', async (req, res) => {
  try {
    const labId = req.headers['x-lab-id'];
    if (!labId) return res.status(400).json({ error: 'lab_id obrigatório' });
    const data = await sb(`laboratorios?id=eq.${labId}`);
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/laboratorios/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const data = await sb(`laboratorios?id=eq.${id}`, {
      method: 'PATCH', body: JSON.stringify(req.body), prefer: 'return=representation'
    });
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════
// ADMIN (gestor Atrius)
// ══════════════════════════════════════════

app.get('/api/admin/labs', requireGestor, async (req, res) => {
  try {
    const data = await sb('laboratorios?order=criado_em.desc');
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/labs', requireGestor, async (req, res) => {
  try {
    const data = await sb('laboratorios', { method: 'POST', body: JSON.stringify(req.body) });
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/admin/labs/:id', requireGestor, async (req, res) => {
  try {
    const { id } = req.params;
    const data = await sb(`laboratorios?id=eq.${id}`, {
      method: 'PATCH', body: JSON.stringify(req.body), prefer: 'return=representation'
    });
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/labs/:id', requireGestor, async (req, res) => {
  try {
    const { id } = req.params;
    // Deletar tudo do lab em cascata
    await sb(`movimentacoes?lab_id=eq.${id}`, { method: 'DELETE', prefer: 'return=minimal' });
    await sb(`estoque?lab_id=eq.${id}`, { method: 'DELETE', prefer: 'return=minimal' });
    await sb(`usuarios?lab_id=eq.${id}`, { method: 'DELETE', prefer: 'return=minimal' });
    await sb(`fornecedores?lab_id=eq.${id}`, { method: 'DELETE', prefer: 'return=minimal' });
    await sb(`laboratorios?id=eq.${id}`, { method: 'DELETE', prefer: 'return=minimal' });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/usuarios', requireGestor, async (req, res) => {
  try {
    const labId = req.query.lab_id;
    const path = labId ? `usuarios?lab_id=eq.${labId}&order=criado_em.desc` : 'usuarios?order=criado_em.desc';
    const data = await sb(path);
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/usuarios', requireGestor, async (req, res) => {
  try {
    const data = await sb('usuarios', { method: 'POST', body: JSON.stringify(req.body) });
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/estoque', requireGestor, async (req, res) => {
  try {
    const labId = req.query.lab_id;
    const path = labId ? `estoque?lab_id=eq.${labId}&order=criado_em.desc` : 'estoque?order=criado_em.desc';
    const data = await sb(path);
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/movimentacoes', requireGestor, async (req, res) => {
  try {
    const labId = req.query.lab_id;
    const limit = req.query.limit || 500;
    const path = labId
      ? `movimentacoes?lab_id=eq.${labId}&order=criado_em.desc&limit=${limit}`
      : `movimentacoes?order=criado_em.desc&limit=${limit}`;
    const data = await sb(path);
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════
// EMAIL (Resend)
// ══════════════════════════════════════════

app.post('/api/email', async (req, res) => {
  try {
    if (!RESEND_API_KEY) return res.status(200).json({ ok: false, error: 'Email não configurado' });
    const fetch = (await import('node-fetch')).default;
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(req.body)
    });
    const data = await r.json();
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════
// START
// ══════════════════════════════════════════

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Atrius API rodando na porta ${PORT}`));
