import { useState } from 'react';
import { apiPost } from '../../api';

export default function DemoPA12() {
  const [result, setResult] = useState<{textbook: {ct1: string; ct2: string; identical: boolean}; pkcs15: {ct1: string; ct2: string; identical: boolean}} | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const demo = async () => {
    setLoading(true); setError('');
    try {
      const res = await apiPost<typeof result>('/pa12/determinism-demo', {});
      setResult(res);
    } catch (e: unknown) { setError(String(e)); }
    finally { setLoading(false); }
  };

  return (
    <div style={s.panel}>
      <h3 style={s.h3}>PA#12 — RSA Determinism Attack</h3>
      <p style={s.desc}>Textbook RSA: same message → same ciphertext. PKCS#1 v1.5: randomized padding.</p>
      <button style={s.btn} onClick={demo} disabled={loading}>Encrypt "hello" Twice</button>
      {error && <div style={s.err}>{error}</div>}
      {loading && <div style={s.info}>Generating 512-bit RSA key...</div>}
      {result && (
        <div style={s.columns}>
          <div style={{...s.col, borderColor: result.textbook.identical ? '#f38ba8' : '#a6e3a1'}}>
            <div style={{...s.colHead, color: '#f38ba8'}}>Textbook RSA (deterministic)</div>
            <div style={s.ct}><span style={s.lbl}>CT 1:</span><span style={s.mono}>{result.textbook.ct1.slice(0,20)}…</span></div>
            <div style={s.ct}><span style={s.lbl}>CT 2:</span><span style={s.mono}>{result.textbook.ct2.slice(0,20)}…</span></div>
            <div style={s.badge_bad}>⚠ Identical — Dictionary attack possible!</div>
          </div>
          <div style={{...s.col, borderColor: '#a6e3a1'}}>
            <div style={{...s.colHead, color: '#a6e3a1'}}>PKCS#1 v1.5 (randomized)</div>
            <div style={s.ct}><span style={s.lbl}>CT 1:</span><span style={s.mono}>{result.pkcs15.ct1.slice(0,20)}…</span></div>
            <div style={s.ct}><span style={s.lbl}>CT 2:</span><span style={s.mono}>{result.pkcs15.ct2.slice(0,20)}…</span></div>
            <div style={s.badge_ok}>✓ Different — IND-CPA secure</div>
          </div>
        </div>
      )}
    </div>
  );
}

const s: Record<string, React.CSSProperties> = {
  panel: { padding: 16 },
  h3: { margin: '0 0 4px', color: '#89b4fa' },
  desc: { margin: '0 0 12px', color: '#6c7086', fontSize: '0.85rem' },
  btn: { padding: '6px 14px', background: '#89b4fa', color: '#1e1e2e', border: 'none', borderRadius: 6, cursor: 'pointer', fontWeight: 600, marginBottom: 12 },
  err: { color: '#f38ba8' }, info: { color: '#f9e2af' },
  columns: { display: 'flex', gap: 12 },
  col: { flex: 1, border: '2px solid', borderRadius: 8, padding: 12 },
  colHead: { fontWeight: 700, marginBottom: 8 },
  ct: { display: 'flex', gap: 6, marginBottom: 4, fontSize: '0.8rem' },
  lbl: { color: '#6c7086', minWidth: 35 },
  mono: { fontFamily: 'monospace', color: '#cdd6f4', wordBreak: 'break-all' },
  badge_bad: { marginTop: 8, background: '#3a1e1e', padding: '4px 8px', borderRadius: 4, color: '#f38ba8', fontSize: '0.8rem' },
  badge_ok: { marginTop: 8, background: '#1e3a2a', padding: '4px 8px', borderRadius: 4, color: '#a6e3a1', fontSize: '0.8rem' },
};
