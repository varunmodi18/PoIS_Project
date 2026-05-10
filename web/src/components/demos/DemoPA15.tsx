import { useState } from 'react';
import { apiPost } from '../../api';

export default function DemoPA15() {
  const [msg, setMsg] = useState('Sign this message');
  const [sig, setSig] = useState('');
  const [pk, setPk] = useState<{n: string; e: number} | null>(null);
  const [verifyResult, setVerifyResult] = useState<boolean | null>(null);
  const [tampered, setTampered] = useState(false);
  const [forgery, setForgery] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const msgToHex = (s: string) => Array.from(new TextEncoder().encode(s)).map(b => b.toString(16).padStart(2, '0')).join('');

  const sign = async () => {
    setLoading(true); setError(''); setTampered(false); setVerifyResult(null);
    try {
      const res = await apiPost<{signature: string; public_key: {n: string; e: number}}>('/pa15/sign', { message_hex: msgToHex(msg), rsa_bits: 512 });
      setSig(res.signature);
      setPk(res.public_key);
    } catch (e: unknown) { setError(String(e)); }
    finally { setLoading(false); }
  };

  const verify = async () => {
    if (!pk) return;
    setLoading(true); setError('');
    try {
      const msgHex = tampered ? msgToHex(msg + '!') : msgToHex(msg);
      const res = await apiPost<{valid: boolean}>('/pa15/verify', { message_hex: msgHex, signature: sig, n: pk.n, e: pk.e });
      setVerifyResult(res.valid);
    } catch (e: unknown) { setError(String(e)); }
    finally { setLoading(false); }
  };

  const runForgery = async () => {
    setLoading(true); setError('');
    try {
      const res = await apiPost<Record<string, unknown>>('/pa15/forgery-demo', {});
      setForgery(res);
    } catch (e: unknown) { setError(String(e)); }
    finally { setLoading(false); }
  };

  return (
    <div style={s.panel}>
      <h3 style={s.h3}>PA#15 — Digital Signatures</h3>
      <p style={s.desc}>Hash-then-sign with RSA. Multiplicative forgery blocked by hashing.</p>
      <div style={s.row}>
        <input style={s.input} value={msg} onChange={e => setMsg(e.target.value)} placeholder="Message to sign" />
        <button style={s.btn} onClick={sign} disabled={loading}>Sign</button>
      </div>
      {sig && (
        <div>
          <div style={s.sigBox}>σ = {sig.slice(0, 20)}…</div>
          <div style={s.row}>
            <label style={s.label}>
              <input type="checkbox" checked={tampered} onChange={e => setTampered(e.target.checked)} /> Tamper message
            </label>
            <button style={s.btn} onClick={verify} disabled={loading || !pk}>Verify</button>
          </div>
          {verifyResult !== null && (
            <div style={{...s.badge, color: verifyResult ? '#a6e3a1' : '#f38ba8'}}>
              {verifyResult ? '✓ Valid signature' : '✗ Invalid signature'}
            </div>
          )}
        </div>
      )}
      {error && <div style={s.err}>{error}</div>}
      <hr style={s.hr} />
      <button style={{...s.btn, background: '#f38ba8'}} onClick={runForgery} disabled={loading}>Multiplicative Forgery Demo</button>
      {forgery && (
        <div style={s.forgeryBox}>
          <div style={s.fRow}><span style={s.k}>Raw RSA forgery:</span><span style={{color: (forgery['raw_rsa_forgery_works'] as boolean) ? '#f38ba8' : '#a6e3a1'}}>{(forgery['raw_rsa_forgery_works'] as boolean) ? 'Works (insecure!)' : 'Blocked'}</span></div>
          <div style={s.fRow}><span style={s.k}>Hash-then-sign forgery:</span><span style={{color: (forgery['hash_then_sign_forgery_works'] as boolean) ? '#f38ba8' : '#a6e3a1'}}>{(forgery['hash_then_sign_forgery_works'] as boolean) ? 'Works' : 'Blocked (secure)'}</span></div>
        </div>
      )}
    </div>
  );
}

const s: Record<string, React.CSSProperties> = {
  panel: { padding: 16 },
  h3: { margin: '0 0 4px', color: '#89b4fa' },
  desc: { margin: '0 0 12px', color: '#6c7086', fontSize: '0.85rem' },
  row: { display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8, flexWrap: 'wrap' },
  label: { color: '#cdd6f4', fontSize: '0.85rem', display: 'flex', alignItems: 'center', gap: 4, cursor: 'pointer' },
  input: { background: '#313244', border: '1px solid #45475a', color: '#cdd6f4', padding: '6px 10px', borderRadius: 4, flex: 1 },
  btn: { padding: '6px 14px', background: '#89b4fa', color: '#1e1e2e', border: 'none', borderRadius: 6, cursor: 'pointer', fontWeight: 600 },
  sigBox: { fontFamily: 'monospace', background: '#313244', padding: 8, borderRadius: 6, fontSize: '0.8rem', color: '#89b4fa', marginBottom: 8 },
  badge: { fontWeight: 700, padding: '6px 12px', background: '#313244', borderRadius: 6, marginBottom: 8 },
  err: { color: '#f38ba8' },
  hr: { borderColor: '#45475a', margin: '12px 0' },
  forgeryBox: { background: '#313244', padding: 12, borderRadius: 6, marginTop: 8 },
  fRow: { display: 'flex', gap: 8, marginBottom: 4, fontSize: '0.85rem' },
  k: { color: '#6c7086' },
};
