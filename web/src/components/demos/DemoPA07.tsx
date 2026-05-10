import { useState } from 'react';
import { apiPost } from '../../api';

export default function DemoPA07() {
  const [msg, setMsg] = useState('Hello World');
  const [result, setResult] = useState<{blocks: string[]; chaining_values: string[]; digest: string; padded_hex: string} | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const hash = async () => {
    setLoading(true); setError('');
    try {
      const msgHex = Array.from(new TextEncoder().encode(msg)).map(b => b.toString(16).padStart(2, '0')).join('');
      const res = await apiPost<typeof result>('/pa07/hash-with-trace', { message_hex: msgHex });
      setResult(res);
    } catch (e: unknown) { setError(String(e)); }
    finally { setLoading(false); }
  };

  return (
    <div style={s.panel}>
      <h3 style={s.h3}>PA#7 — Merkle-Damgård Chain Viewer</h3>
      <p style={s.desc}>Message → pad → split into blocks → chain compress(CV, block).</p>
      <div style={s.row}>
        <input style={s.input} value={msg} onChange={e => setMsg(e.target.value)} placeholder="Enter message" />
        <button style={s.btn} onClick={hash} disabled={loading}>Hash</button>
      </div>
      {error && <div style={s.err}>{error}</div>}
      {result && (
        <div>
          <div style={s.chain}>
            <div style={s.cv}>IV: {result.chaining_values[0]}</div>
            {result.blocks.map((block, i) => (
              <div key={i} style={s.step}>
                <div style={s.arrow}>↓ compress(CV, block_{i})</div>
                <div style={s.blockBox}>
                  <span style={s.blockLabel}>M[{i}]:</span>
                  <span style={s.blockVal}>{block}</span>
                </div>
                <div style={s.cv}>CV[{i+1}]: {result.chaining_values[i+1]}</div>
              </div>
            ))}
            <div style={s.digest}>Digest: {result.digest}</div>
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
  row: { display: 'flex', gap: 8, alignItems: 'center', marginBottom: 12 },
  input: { background: '#313244', border: '1px solid #45475a', color: '#cdd6f4', padding: '6px 10px', borderRadius: 4, flex: 1 },
  btn: { padding: '6px 14px', background: '#89b4fa', color: '#1e1e2e', border: 'none', borderRadius: 6, cursor: 'pointer', fontWeight: 600 },
  err: { color: '#f38ba8', margin: '8px 0' },
  chain: { display: 'flex', flexDirection: 'column', gap: 4, alignItems: 'flex-start' },
  cv: { background: '#313244', padding: '4px 10px', borderRadius: 4, fontFamily: 'monospace', fontSize: '0.8rem', color: '#89b4fa' },
  step: { display: 'flex', flexDirection: 'column', gap: 4, marginLeft: 16, borderLeft: '2px solid #45475a', paddingLeft: 12 },
  arrow: { color: '#6c7086', fontSize: '0.8rem' },
  blockBox: { display: 'flex', gap: 6, alignItems: 'center' },
  blockLabel: { color: '#6c7086', fontSize: '0.8rem' },
  blockVal: { fontFamily: 'monospace', fontSize: '0.75rem', color: '#cdd6f4' },
  digest: { background: '#1e3a2a', padding: '6px 12px', borderRadius: 6, fontFamily: 'monospace', fontSize: '0.85rem', color: '#a6e3a1', fontWeight: 600 },
};
