import { get, put } from '@vercel/blob';
import { createHmac, randomBytes, scryptSync } from 'node:crypto';

const STORE_PATH = 'private/coletaflow-access.json';
const SECRET = process.env.AUTH_SECRET || process.env.BLOB_READ_WRITE_TOKEN || '';


function send(res: any, status: number, body: unknown) {
  res.setHeader('Cache-Control', 'no-store');
  return res.status(status).json(body);
}

export default async function handler(req: any, res: any) {
  const origin = req.headers.origin as string | undefined;
  const requestHost = req.headers.host as string | undefined;
  const expectedOrigin = requestHost ? 'https://' + requestHost : '';
  // Aceita somente requisições same-origin, inclusive URLs únicas de deployment da Vercel.
  if (origin && origin !== expectedOrigin) {
    return send(res, 403, { error: 'Origem não autorizada.' });
  }
  if (req.method !== 'POST') return send(res, 405, { error: 'Método não permitido.' });
  if (!process.env.BLOB_READ_WRITE_TOKEN) {
    return send(res, 500, { error: 'Armazenamento não configurado no servidor.' });
  }
  if (!SECRET) return send(res, 500, { error: 'Chave de autenticação não configurada.' });

  try {
    const { email, password } = req.body || {};
    if (typeof email !== 'string' || !/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email.trim())) {
      return send(res, 400, { error: 'Informe um e-mail válido.' });
    }
    if (typeof password !== 'string' || password.length < 10) {
      return send(res, 400, { error: 'Use uma senha com pelo menos 10 caracteres.' });
    }

    let existing: any = null;
    try {
      const blob = await get(STORE_PATH, { access: 'private', useCache: false });
      if (blob?.statusCode === 200) existing = JSON.parse(await new Response(blob.stream).text());
    } catch (error: any) {
      if (error?.status !== 404 && error?.statusCode !== 404) throw error;
    }
    if (existing?.admin) return send(res, 409, { error: 'O administrador já foi configurado.' });

    const salt = randomBytes(16).toString('hex');
    const hash = scryptSync(password, salt, 64).toString('hex');
    const data = {
      admin: { email: email.trim().toLowerCase(), salt, hash },
      users: []
    };

    // Criação atômica: nunca sobrescreve um cadastro que já exista.
    await put(STORE_PATH, JSON.stringify(data), {
      access: 'private',
      addRandomSuffix: false,
      allowOverwrite: false,
      contentType: 'application/json'
    });

    const payload = Buffer.from(JSON.stringify({
      role: 'admin', exp: Date.now() + 8 * 60 * 60 * 1000
    })).toString('base64url');
    const signature = createHmac('sha256', SECRET).update(payload).digest('base64url');
    return send(res, 201, { token: payload + '.' + signature, email: data.admin.email });
  } catch (error: any) {
    const status = error?.status || error?.statusCode;
    console.error('ColetaFlow explicit admin setup failed:', {
      name: error?.name, status, statusCode: error?.statusCode,
      code: error?.code, message: String(error?.message || '').slice(0, 300)
    });
    if (status === 409 || error?.name === 'BlobAlreadyExistsError') {
      return send(res, 409, { error: 'O arquivo de configuração já existe. Não foi sobrescrito.' });
    }
    return send(res, 500, {
      error: 'Falha no cadastro inicial (' + String(error?.name || 'erro') + '). Consulte os registros da Vercel.'
    });
  }
}
