import { useCallback, useEffect, useState } from 'react';
import { ShieldCheck, LockKeyhole, Mail, Eye, EyeOff, LogOut, Boxes, UserPlus, Users, Ban, CheckCircle2, Trash2, KeyRound, RefreshCw } from 'lucide-react';

type User = { id: string; username: string; active: boolean; createdAt: string };
const SESSION = 'coletaflow_admin_api_session';
async function api<T = any>(path: string, options: RequestInit = {}): Promise<T> {
  const token = sessionStorage.getItem(SESSION);
  const response = await fetch('/api/' + path, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}), ...(options.headers || {}) }
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || 'Não foi possível concluir.');
  return data as T;
}
export default function App() {
  const [initialized, setInitialized] = useState<boolean | null>(null);
  const [logged, setLogged] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [show, setShow] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [users, setUsers] = useState<User[]>([]);
  const [username, setUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [success, setSuccess] = useState('');
  const [savingUser, setSavingUser] = useState(false);

  const loadUsers = useCallback(async () => {
    const result = await api<{ users: User[] }>('admin/users');
    setUsers(result.users);
  }, []);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const status = await api<{ initialized: boolean }>('status');
        if (!alive) return;
        setInitialized(status.initialized);
        if (status.initialized && sessionStorage.getItem(SESSION)) {
          try { await loadUsers(); if (alive) setLogged(true); }
          catch { sessionStorage.removeItem(SESSION); }
        }
      } catch (e) { if (alive) setError(e instanceof Error ? e.message : 'Falha ao conectar ao servidor.'); }
    })();
    return () => { alive = false; };
  }, [loadUsers]);

  async function submit(e: React.FormEvent) {
    e.preventDefault(); setError(''); setBusy(true);
    try {
      const normalized = email.trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized)) throw new Error('Informe um e-mail válido.');
      if (password.length < 10) throw new Error('Use uma senha com pelo menos 10 caracteres.');
      const setup = !initialized;
      if (setup && password !== confirm) throw new Error('As senhas não coincidem.');
      await new Promise(resolve => window.setTimeout(resolve, 1800));
      const result = await api<{ token: string; email: string }>(setup ? 'admin/setup' : 'admin/login', {
        method: 'POST', body: JSON.stringify({ email: normalized, password })
      });
      sessionStorage.setItem(SESSION, result.token);
      setEmail(result.email); setPassword(''); setConfirm('');
      setInitialized(true); await loadUsers(); setLogged(true);
    } catch (e) { setError(e instanceof Error ? e.message : 'Não foi possível concluir.'); }
    finally { setBusy(false); }
  }
  function logout() { sessionStorage.removeItem(SESSION); setLogged(false); setPassword(''); setUsers([]); }

  async function createUser(e: React.FormEvent) {
    e.preventDefault(); setError(''); setSuccess(''); setSavingUser(true);
    try {
      const result = await api<{ users: User[] }>('admin/users', { method: 'POST', body: JSON.stringify({ username, password: newPassword }) });
      setUsers(result.users); setUsername(''); setNewPassword(''); setSuccess('Usuário criado. Ele já pode entrar no ColetaFlow.');
    } catch (e) { setError(e instanceof Error ? e.message : 'Não foi possível criar o usuário.'); }
    finally { setSavingUser(false); }
  }
  async function toggleUser(user: User) {
    setError(''); setSuccess('');
    try {
      const result = await api<{ users: User[] }>('admin/users/' + user.id, { method: 'PATCH', body: JSON.stringify({ active: !user.active }) });
      setUsers(result.users); setSuccess(user.active ? 'Acesso bloqueado.' : 'Acesso liberado.');
    } catch (e) { setError(e instanceof Error ? e.message : 'Falha ao atualizar usuário.'); }
  }
  async function resetPassword(user: User) {
    const next = window.prompt('Nova senha para ' + user.username + ' (mínimo 8 caracteres):');
    if (next === null) return;
    setError(''); setSuccess('');
    try {
      const result = await api<{ users: User[] }>('admin/users/' + user.id, { method: 'PATCH', body: JSON.stringify({ password: next }) });
      setUsers(result.users); setSuccess('Senha redefinida para ' + user.username + '.');
    } catch (e) { setError(e instanceof Error ? e.message : 'Falha ao redefinir senha.'); }
  }
  async function deleteUser(user: User) {
    if (!window.confirm('Excluir o usuário ' + user.username + '?')) return;
    setError(''); setSuccess('');
    try {
      const result = await api<{ users: User[] }>('admin/users/' + user.id, { method: 'DELETE' });
      setUsers(result.users); setSuccess('Usuário excluído.');
    } catch (e) { setError(e instanceof Error ? e.message : 'Falha ao excluir usuário.'); }
  }

  if (initialized === null) return <main className="loginShell"><div className="loginCard"><div className="brand centered"><div className="mark"><Boxes /></div><div><b>ColetaFlow</b><small> CENTRAL ADMINISTRATIVA</small></div></div><p className="loading">Conectando à central segura…</p>{error && <div className="error">{error}</div>}</div><footer>ColetaFlow Admin · Acesso privado</footer></main>;

  if (!logged) return <main className="loginShell"><div className="loginCard"><div className="brand centered"><div className="mark"><Boxes /></div><div><b>ColetaFlow</b><small> CENTRAL ADMINISTRATIVA</small></div></div><div className="intro"><span className="eyebrow">{initialized ? 'ACESSO RESTRITO' : 'CONFIGURAÇÃO INICIAL'}</span><h1>{initialized ? 'Entrar na central' : 'Criar administrador'}</h1><p>{initialized ? 'Entre com seu e-mail e senha administrativa.' : 'Configure seu administrador. Essa opção será encerrada após o primeiro cadastro.'}</p></div><form onSubmit={submit}><label>E-mail administrativo</label><div className="field"><Mail size={18}/><input type="email" autoComplete="username" placeholder="seu@email.com" value={email} onChange={e=>setEmail(e.target.value)} required/></div><label>Senha</label><div className="field"><LockKeyhole size={18}/><input type={show?'text':'password'} autoComplete={initialized?'current-password':'new-password'} placeholder="Mínimo de 10 caracteres" value={password} onChange={e=>setPassword(e.target.value)} required/><button type="button" className="eye" onClick={()=>setShow(!show)} aria-label="Mostrar senha">{show?<EyeOff size={18}/>:<Eye size={18}/>}</button></div>{!initialized && <><label>Confirmar senha</label><div className="field"><LockKeyhole size={18}/><input type={show?'text':'password'} autoComplete="new-password" placeholder="Digite a senha novamente" value={confirm} onChange={e=>setConfirm(e.target.value)} required/></div></>}{error && <div className="error">{error}</div>}<button className="submit" disabled={busy}>{busy?'Validando acesso…':initialized?'Entrar':'Criar acesso administrativo'}</button></form><div className="notice"><ShieldCheck size={17}/><span>Cadastro protegido no servidor. Somente o administrador pode criar usuários do coletor.</span></div></div><footer>ColetaFlow Admin · Acesso privado</footer></main>;

  return <main className="shell"><header className="top"><div className="brand"><div className="mark"><Boxes /></div><div><b>ColetaFlow</b><small> CENTRAL ADMINISTRATIVA</small></div></div><button className="logout" onClick={logout}><LogOut size={17}/> Sair</button></header><section className="adminContent"><div className="adminHeading"><div><span className="eyebrow">PAINEL DE GESTÃO</span><h1>Usuários do ColetaFlow</h1><p>Crie e controle quem tem permissão para abrir o coletor.</p></div><div className="userCount"><Users size={20}/><b>{users.length}</b><span>cadastros</span></div></div>
    <section className="adminCard"><div className="cardTitle"><UserPlus size={19}/><div><b>Novo usuário</b><small>Somente os usuários criados aqui poderão entrar no coletor.</small></div></div><form className="createUserForm" onSubmit={createUser}><label>Nome de usuário<div className="field"><Users size={17}/><input value={username} onChange={e=>setUsername(e.target.value)} placeholder="Ex.: conferente01" minLength={3} maxLength={32} required/></div></label><label>Senha inicial<div className="field"><LockKeyhole size={17}/><input type="password" value={newPassword} onChange={e=>setNewPassword(e.target.value)} placeholder="Mínimo de 8 caracteres" minLength={8} required/></div></label><button className="submit createButton" disabled={savingUser}>{savingUser?'Criando…':<><UserPlus size={17}/> Criar usuário</>}</button></form></section>
    {error && <div className="error globalError">{error}</div>}{success && <div className="success globalSuccess"><CheckCircle2 size={17}/>{success}</div>}
    <section className="adminCard listCard"><div className="cardTitle"><Users size={19}/><div><b>Usuários cadastrados</b><small>O bloqueio passa a valer no próximo acesso e na próxima validação de sessão.</small></div><button className="refresh" onClick={()=>loadUsers().catch(e=>setError(e.message))} title="Atualizar lista"><RefreshCw size={17}/></button></div>
    {users.length === 0 ? <div className="emptyUsers">Nenhum usuário criado ainda.</div> : <div className="userList">{users.map(user=><div className="userRow" key={user.id}><div className="userAvatar"><Users size={18}/></div><div className="userDetails"><b>{user.username}</b><small>Criado em {new Date(user.createdAt).toLocaleDateString('pt-BR')}</small></div><span className={user.active?'status active':'status inactive'}>{user.active?'Ativo':'Bloqueado'}</span><div className="userActions"><button onClick={()=>toggleUser(user)} title={user.active?'Bloquear acesso':'Liberar acesso'}>{user.active?<Ban size={17}/>:<CheckCircle2 size={17}/>}</button><button onClick={()=>resetPassword(user)} title="Redefinir senha"><KeyRound size={17}/></button><button className="dangerAction" onClick={()=>deleteUser(user)} title="Excluir usuário"><Trash2 size={17}/></button></div></div>)}</div>}</section>
    </section><footer>ColetaFlow Admin · Área restrita · {email}</footer></main>;
}