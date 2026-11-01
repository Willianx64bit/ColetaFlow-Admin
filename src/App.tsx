import { useEffect, useState } from 'react';
import { ShieldCheck, LockKeyhole, Mail, Eye, EyeOff, LogOut, Boxes } from 'lucide-react';

const KEY = 'coletaflow_admin_v1';
const SESSION = 'coletaflow_admin_session';
async function digest(value: string) {
  const bytes = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}
type Account = { email: string; salt: string; hash: string };
export default function App() {
  const [account, setAccount] = useState<Account | null>(null);
  const [logged, setLogged] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [show, setShow] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    try { const saved = localStorage.getItem(KEY); if (saved) setAccount(JSON.parse(saved)); setLogged(sessionStorage.getItem(SESSION) === '1'); } catch { setError('Não foi possível carregar a configuração deste navegador.'); }
  }, []);
  async function submit(e: React.FormEvent) {
    e.preventDefault(); setError(''); setBusy(true);
    try {
      const normalized = email.trim().toLowerCase();
      if (!normalized || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized)) throw new Error('Informe um e-mail válido.');
      if (password.length < 8) throw new Error('Use uma senha com pelo menos 8 caracteres.');
      if (!account) {
        if (password !== confirm) throw new Error('As senhas não coincidem.');
        const salt = crypto.randomUUID();
        const next = { email: normalized, salt, hash: await digest(salt + password) };
        localStorage.setItem(KEY, JSON.stringify(next)); setAccount(next);
      } else {
        if (normalized !== account.email || await digest(account.salt + password) !== account.hash) throw new Error('E-mail ou senha incorretos.');
      }
      sessionStorage.setItem(SESSION, '1'); setLogged(true); setPassword(''); setConfirm('');
    } catch (err) { setError(err instanceof Error ? err.message : 'Não foi possível concluir.'); }
    finally { setBusy(false); }
  }
  function logout() { sessionStorage.removeItem(SESSION); setLogged(false); setPassword(''); }
  if (logged) return <main className="shell"><header className="top"><div className="brand"><div className="mark"><Boxes /></div><div><b>ColetaFlow</b><small> CENTRAL ADMINISTRATIVA</small></div></div><button className="logout" onClick={logout}><LogOut size={17}/> Sair</button></header><section className="welcome"><div className="welcomeIcon"><ShieldCheck size={30}/></div><span className="eyebrow">ACESSO ADMINISTRATIVO</span><h1>Bem-vindo à central.</h1><p>Seu acesso administrativo foi iniciado. O painel de gestão será construído aqui.</p><div className="account"><span>Administrador</span><b>{account?.email}</b></div></section><footer>ColetaFlow Admin · Área restrita</footer></main>;
  return <main className="loginShell"><div className="loginCard"><div className="brand centered"><div className="mark"><Boxes /></div><div><b>ColetaFlow</b><small> CENTRAL ADMINISTRATIVA</small></div></div><div className="intro"><span className="eyebrow">{account ? 'ACESSO RESTRITO' : 'CONFIGURAÇÃO INICIAL'}</span><h1>{account ? 'Entrar na central' : 'Criar administrador'}</h1><p>{account ? 'Entre com seu e-mail e senha administrativa.' : 'Cadastre seu acesso. Esta opção some depois da configuração neste navegador.'}</p></div><form onSubmit={submit}><label>E-mail administrativo</label><div className="field"><Mail size={18}/><input type="email" autoComplete="username" placeholder="seu@email.com" value={email} onChange={e=>setEmail(e.target.value)} required/></div><label>Senha</label><div className="field"><LockKeyhole size={18}/><input type={show?'text':'password'} autoComplete={account?'current-password':'new-password'} placeholder="Mínimo de 8 caracteres" value={password} onChange={e=>setPassword(e.target.value)} required/><button type="button" className="eye" onClick={()=>setShow(!show)} aria-label="Mostrar senha">{show?<EyeOff size={18}/>:<Eye size={18}/>}</button></div>{!account && <><label>Confirmar senha</label><div className="field"><LockKeyhole size={18}/><input type={show?'text':'password'} autoComplete="new-password" placeholder="Digite a senha novamente" value={confirm} onChange={e=>setConfirm(e.target.value)} required/></div></>} {error && <div className="error">{error}</div>}<button className="submit" disabled={busy}>{busy?'Aguarde…':account?'Entrar':'Criar acesso administrativo'}</button></form><div className="notice"><ShieldCheck size={17}/><span>Somente um acesso administrativo é configurado por navegador. Guarde sua senha.</span></div></div><footer>ColetaFlow Admin · Acesso privado</footer></main>;
}