import { get } from '@vercel/blob';

const STORE_PATH = 'private/coletaflow-access.json';

export default async function handler(req: any, res: any) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'GET') return res.status(405).json({ error: 'Método não permitido.' });
  if (!process.env.BLOB_READ_WRITE_TOKEN) {
    return res.status(500).json({ error: 'Armazenamento não configurado no servidor.' });
  }
  try {
    const blob = await get(STORE_PATH, { access: 'private', useCache: false });
    if (!blob || blob.statusCode !== 200) return res.status(200).json({ initialized: false });
    const data = JSON.parse(await new Response(blob.stream).text());
    return res.status(200).json({ initialized: !!data?.admin });
  } catch (error: any) {
    if (error?.status === 404 || error?.statusCode === 404) {
      return res.status(200).json({ initialized: false });
    }
    console.error('ColetaFlow status endpoint failed:', {
      name: error?.name, status: error?.status, statusCode: error?.statusCode,
      code: error?.code, message: String(error?.message || '').slice(0, 250)
    });
    return res.status(500).json({ error: 'Falha ao consultar a configuração inicial no armazenamento.' });
  }
}
