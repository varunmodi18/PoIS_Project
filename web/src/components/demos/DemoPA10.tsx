import { useState } from 'react';
import { apiPost } from '../../api';

export default function DemoPA10() {
  const [suffix, setSuffix] = useState('extra_data');
  const [result, setResult] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const demo = async () => {
    setLoading(true); setError('');
    try {
      const suffixHex = Array.from(new TextEncoder().encode(suffix)).map(b => b.toString(16).padStart(2, '0')).join('');
      const res = await apiPost<Record<string, unknown>>('/pa10/length-extension-demo', { suffix_hex: suffixHex });
      setResult(res);
    } catch (e: unknown) { setError(String(e)); }
    finally { setLoading(false); }
  };

  return (
    <div style={s.panel}>
      <h3 style={s.h3}>PA#10 — Length Extension vs HMAC</h3>
      <p style={s.desc}>H(k||m) is vulnerable to length extension. HMAC blocks it.</p>
      <div style={s.row}>
        <label style={s.label}>Suffix m' to append:</label>
        <input style={s.input} value={suffix} onChange={e => setSuffix(e.target.value)} />
        <button style={s.btn} onClick={demo} disabled={loading}>Run Demo</button>
      </div>
      {error && <div style={s.err}>{error}</div>}
      {loading && <div style={s.info}>Computing...</div>}
      {result && (
        <div style={s.columns}>
          <div style={{...s.col, borderColor: '#f38ba8'}}>
            <div style={{...s.colHead, color: '#f38ba8'}}>Naive H(k||m) — Vulnerable</div>
            <div style={s.item}><span style={s.lbl}>Naive tag:</span><span style={s.mono}>{String(result['naive_tag_hex']).slice(0, 16)}…</span></div>
            <div style={s.item}><span style={s.lbl}>Forged tag:</span><span style={s.mono}>{String(result['forged_tag_hex']).slice(0, 16)}…</span></div>
            <div style={s.verdict_bad}>Forgery VERIFIED ✓ (attack succeeded)</div>
          </div>
          <div style={{...s.col, borderColor: '#a6e3a1'}}>
            <div style={{...s.colHead, color: '#a6e3a1'}}>HMAC — Secure</div>
            <div style={s.item}><span style={s.lbl}>HMAC tag:</span><span style={s.mono}>{String(result['hmac_tag_hex']).slice(0, 16)}…</span></div>
            <div style={s.verdict_ok}>Forgery REJECTED ✗ (attack fails)</div>
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
  input: { background: '#313244', border: '1px solid #45475a', color: '#cdd6f4', padding: '4px 8px', borderRadius: 4, width: 200 },
  btn: { padding: '6px 14px', background: '#89b4fa', color: '#1e1e2e', border: 'none', borderRadius: 6, cursor: 'pointer', fontWeight: 600 },
  err: { color: '#f38ba8' }, info: { color: '#f9e2af' },
  columns: { display: 'flex', gap: 12 },
  col: { flex: 1, border: '2px solid', borderRadius: 8, padding: 12 },
  colHead: { fontWeight: 700, marginBottom: 8 },
  item: { marginBottom: 6, fontSize: '0.85rem' },
  lbl: { color: '#6c7086', marginRight: 6 },
  mono: { fontFamily: 'monospace', color: '#cdd6f4' },
  verdict_bad: { marginTop: 8, background: '#3a1e1e', padding: '4px 8px', borderRadius: 4, color: '#f38ba8', fontSize: '0.8rem' },
  verdict_ok: { marginTop: 8, background: '#1e3a2a', padding: '4px 8px', borderRadius: 4, color: '#a6e3a1', fontSize: '0.8rem' },
};
