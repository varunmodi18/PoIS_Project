import { useState } from 'react';
import { apiPost } from '../../api';

export default function DemoPA14() {
  const [result, setResult] = useState<{message: string; recovered: string; attack_succeeded: boolean; recipients: {N: string; c: string}[]} | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const attack = async () => {
    setLoading(true); setError('');
    try {
      const res = await apiPost<typeof result>('/pa14/hastad', { bits: 256, e: 3 });
      setResult(res);
    } catch (e: unknown) { setError(String(e)); }
    finally { setLoading(false); }
  };

  return (
    <div style={s.panel}>
      <h3 style={s.h3}>PA#14 — Håstad Broadcast Attack</h3>
      <p style={s.desc}>Same message encrypted under e=3 different 256-bit RSA keys. CRT recovers m^3, then take cube root.</p>
      <button style={s.btn} onClick={attack} disabled={loading}>Run Håstad Attack (e=3)</button>
      {error && <div style={s.err}>{error}</div>}
      {loading && <div style={s.info}>Generating 3 RSA keypairs and attacking...</div>}
      {result && (
        <div>
          <div style={s.recRow}>
            {result.recipients.map((r, i) => (
              <div key={i} style={s.recCard}>
                <div style={s.recHead}>Recipient {i+1}</div>
                <div style={s.kv}><span style={s.k}>N{i+1}:</span><span style={s.mono}>{r.N.slice(0,12)}…</span></div>
                <div style={s.kv}><span style={s.k}>c{i+1}=m^3:</span><span style={s.mono}>{r.c.slice(0,12)}…</span></div>
              </div>
            ))}
          </div>
          <div style={s.attackBox}>
            <div style={s.step}>Step 1: CRT → m^3 mod (N1·N2·N3)</div>
            <div style={s.step}>Step 2: Integer cube root → m</div>
            <div style={{...s.result, color: result.attack_succeeded ? '#a6e3a1' : '#f38ba8'}}>
              {result.attack_succeeded ? '✓ Attack succeeded!' : '✗ Attack failed'}
            </div>
            <div style={s.kv}><span style={s.k}>Original m:</span><span style={s.mono}>{result.message}</span></div>
            <div style={s.kv}><span style={s.k}>Recovered m:</span><span style={s.mono}>{result.recovered}</span></div>
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
  btn: { padding: '6px 14px', background: '#f38ba8', color: '#1e1e2e', border: 'none', borderRadius: 6, cursor: 'pointer', fontWeight: 600, marginBottom: 12 },
  err: { color: '#f38ba8' }, info: { color: '#f9e2af' },
  recRow: { display: 'flex', gap: 8, marginBottom: 12 },
  recCard: { flex: 1, background: '#313244', padding: 10, borderRadius: 6 },
  recHead: { color: '#89b4fa', fontWeight: 600, marginBottom: 6, fontSize: '0.85rem' },
  kv: { display: 'flex', gap: 4, marginBottom: 2, fontSize: '0.8rem' },
  k: { color: '#6c7086' },
  mono: { fontFamily: 'monospace', color: '#cdd6f4' },
  attackBox: { background: '#1e1e2e', padding: 12, borderRadius: 8, border: '1px solid #45475a' },
  step: { color: '#f9e2af', fontSize: '0.85rem', marginBottom: 4 },
  result: { fontWeight: 700, fontSize: '1.1rem', margin: '8px 0' },
};
