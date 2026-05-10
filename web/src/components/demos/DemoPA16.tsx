import { useState } from 'react';
import { apiPost } from '../../api';

export default function DemoPA16() {
  const [m, setM] = useState('42');
  const [kp, setKp] = useState<{p: string; g: string; q: string; h: string; x: string} | null>(null);
  const [ct, setCt] = useState<{c1: string; c2: string} | null>(null);
  const [decrypted, setDecrypted] = useState('');
  const [successes, setSuccesses] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const keygen = async () => {
    setLoading(true); setError('');
    try {
      const res = await apiPost<typeof kp>('/pa16/keygen', { bits: 64 });
      setKp(res);
      setCt(null); setDecrypted('');
    } catch (e: unknown) { setError(String(e)); }
    finally { setLoading(false); }
  };

  const encrypt = async () => {
    if (!kp) return;
    setLoading(true); setError('');
    try {
      const res = await apiPost<typeof ct>('/pa16/encrypt', { p: kp.p, g: kp.g, q: kp.q, h: kp.h, message: m });
      setCt(res); setDecrypted('');
    } catch (e: unknown) { setError(String(e)); }
    finally { setLoading(false); }
  };

  const malleate = async () => {
    if (!kp || !ct) return;
    setLoading(true); setError('');
    try {
      // Multiply c2 by 2 mod p
      const p = BigInt(kp.p);
      const c2_mal = ((BigInt(ct.c2) * 2n) % p).toString();
      const res = await apiPost<{plaintext: string}>('/pa16/decrypt', { x: kp.x, c1: ct.c1, c2: c2_mal, p: kp.p });
      const expected2m = ((BigInt(m) * 2n) % p).toString();
      setDecrypted(res.plaintext);
      if (res.plaintext === expected2m) setSuccesses(s => s + 1);
    } catch (e: unknown) { setError(String(e)); }
    finally { setLoading(false); }
  };

  return (
    <div style={s.panel}>
      <h3 style={s.h3}>PA#16 — ElGamal Malleability</h3>
      <p style={s.desc}>ElGamal is malleable: (c1, 2·c2) decrypts to 2m. Proof of DDH ⇏ CCA security.</p>
      <div style={s.row}>
        <label style={s.label}>Message m:</label>
        <input style={s.input} value={m} onChange={e => setM(e.target.value)} />
        <button style={s.btn} onClick={keygen} disabled={loading}>New Keypair</button>
        <button style={s.btn} onClick={encrypt} disabled={loading || !kp}>Encrypt</button>
        <button style={{...s.btn, background: '#f38ba8'}} onClick={malleate} disabled={loading || !ct}>Multiply c₂ by 2</button>
      </div>
      {error && <div style={s.err}>{error}</div>}
      {loading && <div style={s.info}>Computing...</div>}
      {ct && (
        <div style={s.ctBox}>
          <div>c₁ = {ct.c1.slice(0, 12)}…</div>
          <div>c₂ = {ct.c2.slice(0, 12)}…</div>
        </div>
      )}
      {decrypted && (
        <div style={s.resultBox}>
          <div style={s.resultLine}><span style={s.label}>m:</span><span style={s.val}>{m}</span></div>
          <div style={s.resultLine}><span style={s.label}>Decrypt(c₁, 2·c₂) =</span><span style={s.val}>{decrypted}</span></div>
          <div style={s.resultLine}><span style={s.label}>2m mod p =</span><span style={s.val}>{kp ? ((BigInt(m) * 2n) % BigInt(kp.p)).toString() : '?'}</span></div>
          <div style={{color: '#f38ba8', fontSize: '0.85rem'}}>Successes: {successes}</div>
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
  label: { color: '#cdd6f4', fontSize: '0.85rem' },
  input: { background: '#313244', border: '1px solid #45475a', color: '#cdd6f4', padding: '4px 8px', borderRadius: 4, width: 80, fontFamily: 'monospace' },
  btn: { padding: '6px 14px', background: '#89b4fa', color: '#1e1e2e', border: 'none', borderRadius: 6, cursor: 'pointer', fontWeight: 600 },
  err: { color: '#f38ba8' }, info: { color: '#f9e2af' },
  ctBox: { background: '#313244', padding: 8, borderRadius: 6, fontFamily: 'monospace', fontSize: '0.8rem', color: '#89b4fa', marginBottom: 8 },
  resultBox: { background: '#2a1e1e', padding: 12, borderRadius: 8 },
  resultLine: { display: 'flex', gap: 8, marginBottom: 4, fontSize: '0.9rem' },
  val: { fontFamily: 'monospace', color: '#f38ba8', fontWeight: 600 },
};
