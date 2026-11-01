import { get, head, put } from '@vercel/blob';
import { createHmac, randomBytes, scryptSync, timingSafeEqual, randomUUID } from 'node:crypto';

const STORE_PATH = 'private/coletaflow-access.json';
const SECRET = process.env.AUTH_SECRET || process.env.BLOB_READ_WRITE_TOKEN || '';
function isAllowedOrigin(req: any) {
  const origin = req.headers.origin as string | undefined;
  const host = req.headers.host as string | undefined;
  // Same-origin only: supports canonical and unique Vercel deployment URLs.
  return !origin || (!!host && origin === 'https://' + host);
}

type User = { id: string; username: string; salt: string; hash: string; active: boolean; createdAt: string };
type Data = { admin: { email: string; salt: string; hash: string } | null; users: User[] };

function send(res: any, status: number, body: unknown) {
  res.status(status).setHeader('Cache-Control', 'no-store').json(body);
}
function passwordHash(password: string, salt: string) {
  return scryptSync(password, salt, 64).toString('hex');
}
function safeEqual(a: string, b: string) {
  const aa = Buffer.from(a, 'hex'), bb = Buffer.from(b, 'hex');
  return aa.length === bb.length && timingSafeEqual(aa, bb);
}
function sign(payload: object) {
  const value = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = createHmac('sha256', SECRET).update(value).digest('base64url');
  return value + '.' + signature;
}
function verify(token: string) {
  if (!SECRET || !token.includes('.')) return null;
  const [value, signature] = token.split('.');
  const expected = createHmac('sha256', SECRET).update(value).digest('base64url');
  if (signature.length !== expected.length || !timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;
  try {
    const payload = JSON.parse(Buffer.from(value, 'base64url').toString());
    if (!payload.exp || payload.exp < Date.now()) return null;
    return payload as { role: 'admin' | 'user'; id?: string; exp: number };
  } catch { return null; }
}
async function readData(): Promise<Data | null> {
  try {
    const blob = await get(STORE_PATH, { access: 'private', useCache: false });
    if (!blob || blob.statusCode !== 200) return null;
    return JSON.parse(await new Response(blob.stream).text()) as Data;
  } catch (error: any) {
    if (error?.status === 404 || error?.statusCode === 404) return null;
    throw error;
  }
}
async function writeData(data: Data, create = false) {
  const body = JSON.stringify(data);
  if (create) {
    await put(STORE_PATH, body, { access: 'private', addRandomSuffix: false, allowOverwrite: false, contentType: 'application/json' });
    return;
  }
  for (let attempt = 0; attempt < 3; attempt++) {
    const current = await head(STORE_PATH, { access: 'private' });
    try {
      await put(STORE_PATH, body, { access: 'private', addRandomSuffix: false, allowOverwrite: true, ifMatch: current.etag, contentType: 'application/json' });
      return;
    } catch (error: any) {
      if (error?.name !== 'BlobPreconditionFailedError' && error?.status !== 412) throw error;
    }
  }
  throw new Error('Conflito ao salvar. Tente novamente.');
}
function bearer(req: any) {
  const header = String(req.headers.authorization || '');
  return header.startsWith('Bearer ') ? header.slice(7) : '';
}
function originAllowed(req: any) {
  return isAllowedOrigin(req);
}

export default async function handler(req: any, res: any) {
  const origin = req.headers.origin as string | undefined;
  if (origin && isAllowedOrigin(req)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, OPTIONS');
  }
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (!originAllowed(req)) return send(res, 403, { error: 'Origem não autorizada.' });
  if (!SECRET) return send(res, 500, { error: 'Servidor sem chave de autenticação configurada.' });

  const requestPath = new URL(req.url || '/', 'http://localhost').pathname;
  const rawPath = requestPath.startsWith('/api/')
    ? requestPath.slice('/api/'.length)
    : (Array.isArray(req.query.path) ? req.query.path.join('/') : String(req.query.path || ''));
  const path = '/' + rawPath.replace(/^\/+|\/+$/g, '');
  let stage = 'route_dispatch';
  try {
    if (req.method === 'GET' && path === '/status') {
      stage = 'status_blob_read';
      const data = await readData();
      return send(res, 200, { initialized: !!data?.admin });
    }
    if (req.method === 'POST' && path === '/admin/setup') {
      stage = 'setup_validate_payload';
      const { email, password } = req.body || {};
      if (typeof email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) return send(res, 400, { error: 'Informe um e-mail válido.' });
      if (typeof password !== 'string' || password.length < 10) return send(res, 400, { error: 'Use uma senha com pelo menos 10 caracteres.' });
      stage = 'setup_check_existing_admin';
      const existing = await readData();
      if (existing?.admin) return send(res, 409, { error: 'O administrador já foi configurado.' });
      const salt = randomBytes(16).toString('hex');
      const data: Data = { admin: { email: email.trim().toLowerCase(), salt, hash: passwordHash(password, salt) }, users: [] };
      stage = 'setup_blob_create';
      try { await writeData(data, true); }
      catch (error: any) {
        console.error('ColetaFlow setup blob create failed:', { name: error?.name, status: error?.status, statusCode: error?.statusCode, code: error?.code, message: String(error?.message || '').slice(0, 300) });
        return send(res, 500, { error: 'Falha ao gravar o cadastro inicial no armazenamento. Nenhuma conta foi confirmada.' });
      }
      stage = 'setup_create_session';
      const token = sign({ role: 'admin', exp: Date.now() + 8 * 60 * 60 * 1000 });
      return send(res, 201, { token, email: data.admin.email });
    }
    if (req.method === 'POST' && path === '/admin/login') {
      const { email, password } = req.body || {};
      const data = await readData();
      if (!data?.admin || typeof email !== 'string' || typeof password !== 'string') return send(res, 401, { error: 'E-mail ou senha incorretos.' });
      const hash = passwordHash(password, data.admin.salt);
      if (email.trim().toLowerCase() !== data.admin.email || !safeEqual(hash, data.admin.hash)) return send(res, 401, { error: 'E-mail ou senha incorretos.' });
      const token = sign({ role: 'admin', exp: Date.now() + 8 * 60 * 60 * 1000 });
      return send(res, 200, { token, email: data.admin.email });
    }
    if (path.startsWith('/admin/')) {
      const session = verify(bearer(req));
      if (session?.role !== 'admin') return send(res, 401, { error: 'Sessão administrativa inválida. Entre novamente.' });
      const data = await readData();
      if (!data?.admin) return send(res, 503, { error: 'Configuração administrativa não encontrada.' });
      if (req.method === 'GET' && path === '/admin/users') {
        return send(res, 200, { users: data.users.map(({ id, username, active, createdAt }) => ({ id, username, active, createdAt })) });
      }
      if (req.method === 'POST' && path === '/admin/users') {
        const { username, password } = req.body || {};
        const name = typeof username === 'string' ? username.trim() : '';
        if (!/^[a-zA-Z0-9._-]{3,32}$/.test(name)) return send(res, 400, { error: 'Use um login de 3 a 32 caracteres (letras, números, ponto, _ ou -).' });
        if (typeof password !== 'string' || password.length < 8) return send(res, 400, { error: 'A senha deve ter pelo menos 8 caracteres.' });
        if (data.users.some(user => user.username.toLowerCase() === name.toLowerCase())) return send(res, 409, { error: 'Esse usuário já existe.' });
        const salt = randomBytes(16).toString('hex');
        data.users.push({ id: randomUUID(), username: name, salt, hash: passwordHash(password, salt), active: true, createdAt: new Date().toISOString() });
        await writeData(data);
        return send(res, 201, { users: data.users.map(({ id, username, active, createdAt }) => ({ id, username, active, createdAt })) });
      }
      if (req.method === 'PATCH' && path.startsWith('/admin/users/')) {
        const id = path.split('/').pop();
        const user = data.users.find(item => item.id === id);
        if (!user) return send(res, 404, { error: 'Usuário não encontrado.' });
        const { active, password } = req.body || {};
        if (typeof active === 'boolean') user.active = active;
        if (typeof password === 'string') {
          if (password.length < 8) return send(res, 400, { error: 'A nova senha deve ter pelo menos 8 caracteres.' });
          user.salt = randomBytes(16).toString('hex');
          user.hash = passwordHash(password, user.salt);
        }
        await writeData(data);
        return send(res, 200, { ok: true, users: data.users.map(({ id, username, active, createdAt }) => ({ id, username, active, createdAt })) });
      }
      if (req.method === 'DELETE' && path.startsWith('/admin/users/')) {
        const id = path.split('/').pop();
        data.users = data.users.filter(item => item.id !== id);
        await writeData(data);
        return send(res, 200, { users: data.users.map(({ id, username, active, createdAt }) => ({ id, username, active, createdAt })) });
      }
      return send(res, 404, { error: 'Rota administrativa não encontrada.' });
    }
    if (req.method === 'POST' && path === '/auth/login') {
      const { username, password } = req.body || {};
      const data = await readData();
      const user = data?.users.find(item => item.username.toLowerCase() === String(username || '').trim().toLowerCase());
      if (!user || !user.active || typeof password !== 'string' || !safeEqual(passwordHash(password, user.salt), user.hash)) return send(res, 401, { error: 'Usuário ou senha inválidos.' });
      const token = sign({ role: 'user', id: user.id, exp: Date.now() + 12 * 60 * 60 * 1000 });
      return send(res, 200, { token, username: user.username });
    }
    if (req.method === 'GET' && path === '/auth/me') {
      const session = verify(bearer(req));
      if (session?.role !== 'user' || !session.id) return send(res, 401, { error: 'Sessão inválida.' });
      const data = await readData();
      const user = data?.users.find(item => item.id === session.id);
      if (!user?.active) return send(res, 401, { error: 'Acesso bloqueado. Fale com o administrador.' });
      return send(res, 200, { username: user.username });
    }
    return send(res, 404, { error: 'Rota não encontrada.' });
  } catch (error: any) {
    console.error('ColetaFlow access API error:', { stage, method: req.method, path, name: error?.name, status: error?.status, statusCode: error?.statusCode, code: error?.code, message: String(error?.message || '').slice(0, 300) });
    return send(res, 500, { error: 'Falha interna na etapa: ' + stage + '. Consulte os logs do servidor para identificar a causa.' });
  }
}