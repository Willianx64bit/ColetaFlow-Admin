import { get } from '@vercel/blob';
import { createHmac, scryptSync, timingSafeEqual } from 'node:crypto';

const STORE_PATH = 'private/coletaflow-access.json';
const SECRET = process.env.AUTH_SECRET || process.env.BLOB_READ_WRITE_TOKEN || '';

function send(res: any, status: number, body: unknown) {
  res.setHeader('Cache-Control', 'no-store');
  return res.status(status).json(body);
}

function passwordHash(password: string, salt: string) {
  return scryptSync(password, salt, 64).toString('hex');
}

function safeEqual(a: string, b: string) {
  const aa = Buffer.from(a, 'hex');
  const bb = Buffer.from(b, 'hex');
  return aa.length === bb.length && timingSafeEqual(aa, bb);
}

function sign(payload: object) {
  const value = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = createHmac('sha256', SECRET).update(value).digest('base64url');
  return value + '.' + signature;
}

export default async function handler(req: any, res: any) {
  res.setHeader('Cache-Control', 'no-store');
  const origin = req.headers.origin as string | undefined;
  const host = req.headers.host as string | undefined;

  if (origin && (!host || origin !== 'https://' + host)) {
    return send(res, 403, { error: 'Origem não autorizada.' });
  }
  if (req.method !== 'POST') return send(res, 405, { error: 'Método não permitido.' });
  if (!process.env.BLOB_READ_WRITE_TOKEN) {
    return send(res, 500, { error: 'Armazenamento não configurado no servidor.' });
  }
  if (!SECRET) return send(res, 500, { error: 'Chave de autenticação não configurada.' });

  try {
    const { email, password } = req.body || {};
    if (typeof email !== 'string' || typeof password !== 'string') {
      return send(res, 400, { error: 'Informe o e-mail e a senha.' });
    }

    const blob = await get(STORE_PATH, { access: 'private', useCache: false });
    if (!blob || blob.statusCode !== 200) {
      return send(res, 503, { error: 'Cadastro administrativo não encontrado no armazenamento.' });
    }

    const data = JSON.parse(await new Response(blob.stream).text());
    if (!data?.admin || typeof data.admin.email !== 'string' ||
        typeof data.admin.salt !== 'string' || typeof data.admin.hash !== 'string') {
      return send(res, 503, { error: 'Cadastro administrativo está incompleto. Nenhum dado foi alterado.' });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const hash = passwordHash(password, data.admin.salt);
    if (normalizedEmail !== data.admin.email || !safeEqual(hash, data.admin.hash)) {
      return send(res, 401, { error: 'E-mail ou senha incorretos.' });
    }

    const token = sign({ role: 'admin', exp: Date.now() + 8 * 60 * 60 * 1000 });
    return send(res, 200, { token, email: data.admin.email });
  } catch (error: any) {
    console.error('ColetaFlow explicit admin login failed:', {
      name: error?.name,
      status: error?.status,
      statusCode: error?.statusCode,
      code: error?.code,
      message: String(error?.message || '').slice(0, 250)
    });
    return send(res, 500, { error: 'Falha ao validar o acesso administrativo. Consulte os registros do servidor.' });
  }
}
