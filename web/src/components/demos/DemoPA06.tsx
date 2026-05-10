import { useState } from 'react';
import { apiPost } from '../../api';

export default function DemoPA06() {
  const [msg, setMsg] = useState('48656c6c6f20576f726c6421');
  const [result, setResult] = useState<{cpa_only: {corrupted_hex: string; blocked: boolean}; cca: {blocked: boolean; error?: string}} | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const demo = async () => {
    setLoading(true); setError('');
    try {
      const res = await apiPost<typeof result>('/pa06/malleability-demo', {
        message_hex: msg, flip_bit: 0
      });
      setResult(res);
    } catch (e: unknown) { setError(String(e)); }
    finally { setLoading(false); }
  };

  return (
    <div style={s.panel}>
      <h3 style={s.h3}>PA#6 — CCA vs CPA Malleability</h3>
      <p style={s.desc}>Flip a bit in the ciphertext. CPA decrypts (corrupted). CCA rejects (⊥).</p>
      <div style={s.row}>
        <label style={s.label}>Message (hex):</label>
        <input style={s.input} value={msg} onChange={e => setMsg(e.target.value)} />
        <button style={s.btn} onClick={demo} disabled={loading}>Run Demo</button>
      </div>
      {error && <div style={s.err}>{error}</div>}
      {loading && <div style={s.info}>Computing...</div>}
      {result && (
        <div style={s.columns}>
          <div style={{...s.col, borderColor: '#f38ba8'}}>
            <div style={{...s.colHead, color: '#f38ba8'}}>CPA-only (malleable)</div>
            <div style={s.colBody}>
              Bit flipped → decryption succeeds<br />
              <span style={s.mono}>{result.cpa_only.corrupted_hex.slice(0, 32) || '(no output)'}…</span>
              <div style={s.badge_bad}>⚠ Corrupted plaintext accepted</div>
            </div>
          </div>
          <div style={{...s.col, borderColor: '#a6e3a1'}}>
            <div style={{...s.colHead, color: '#a6e3a1'}}>Encrypt-then-MAC (CCA)</div>
            <div style={s.colBody}>
              Bit flipped → MAC rejects<br />
              <span style={s.blocked}>⊥ MAC verification failed</span>
              <div style={s.badge_ok}>✓ Tamper detected</div>
            </div>
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
  row: { display: 'flex', gap: 8, alignItems: 'center', marginBottom: 12, flexWrap: 'wrap' },
  label: { color: '#cdd6f4', fontSize: '0.85rem' },
  input: { background: '#313244', border: '1px solid #45475a', color: '#cdd6f4', padding: '4px 8px', borderRadius: 4, fontFamily: 'monospace', width: 250 },
  btn: { padding: '6px 14px', background: '#89b4fa', color: '#1e1e2e', border: 'none', borderRadius: 6, cursor: 'pointer', fontWeight: 600 },
  err: { color: '#f38ba8' }, info: { color: '#f9e2af' },
  columns: { display: 'flex', gap: 12 },
  col: { flex: 1, border: '2px solid', borderRadius: 8, padding: 12 },
  colHead: { fontWeight: 700, marginBottom: 8 },
  colBody: { color: '#cdd6f4', fontSize: '0.85rem', lineHeight: 1.6 },
  mono: { fontFamily: 'monospace', color: '#f38ba8', fontSize: '0.75rem', wordBreak: 'break-all' },
  blocked: { color: '#f38ba8', fontWeight: 600 },
  badge_bad: { marginTop: 8, background: '#3a1e1e', padding: '4px 8px', borderRadius: 4, color: '#f38ba8', fontSize: '0.8rem' },
  badge_ok: { marginTop: 8, background: '#1e3a2a', padding: '4px 8px', borderRadius: 4, color: '#a6e3a1', fontSize: '0.8rem' },
};
