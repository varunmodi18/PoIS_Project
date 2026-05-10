import { useState } from 'react';
import { apiPost } from '../../api';

const EXAMPLES = ['561', '7919', '104729', '15485863', '2147483647'];

export default function DemoPA13() {
  const [n, setN] = useState('561');
  const [rounds, setRounds] = useState(20);
  const [result, setResult] = useState<{is_prime: boolean; rounds: number} | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [genBits, setGenBits] = useState(64);
  const [generated, setGenerated] = useState('');

  const test = async () => {
    setLoading(true); setError('');
    try {
      const res = await apiPost<{is_prime: boolean; rounds: number}>('/pa13/test', { n, rounds });
      setResult(res);
    } catch (e: unknown) { setError(String(e)); }
    finally { setLoading(false); }
  };

  const generate = async () => {
    setLoading(true); setError('');
    try {
      const res = await apiPost<{prime: string; bits: number}>('/pa13/generate', { bits: genBits });
      setGenerated(res.prime);
    } catch (e: unknown) { setError(String(e)); }
    finally { setLoading(false); }
  };

  return (
    <div style={s.panel}>
      <h3 style={s.h3}>PA#13 — Miller-Rabin Primality Tester</h3>
      <p style={s.desc}>Probabilistic primality testing. 561 = 3×11×17 (Carmichael number, fooled Fermat but not Miller-Rabin).</p>
      <div style={s.row}>
        <input style={s.input} value={n} onChange={e => setN(e.target.value)} placeholder="Enter a number" />
        <label style={s.label}>Rounds: {rounds}</label>
        <input type="range" min={1} max={40} value={rounds} onChange={e => setRounds(+e.target.value)} style={{width: 100}} />
        <button style={s.btn} onClick={test} disabled={loading}>Test</button>
      </div>
      <div style={s.examples}>
        {EXAMPLES.map(ex => (
          <button key={ex} style={s.exBtn} onClick={() => setN(ex)}>{ex}</button>
        ))}
      </div>
      {error && <div style={s.err}>{error}</div>}
      {result && (
        <div style={{...s.badge, background: result.is_prime ? '#1e3a2a' : '#3a1e1e', color: result.is_prime ? '#a6e3a1' : '#f38ba8'}}>
          {result.is_prime ? '✓ PRIME' : '✗ COMPOSITE'} — {rounds} rounds
        </div>
      )}
      <div style={s.genRow}>
        <label style={s.label}>Generate prime ({genBits} bits):</label>
        <input type="range" min={32} max={256} step={32} value={genBits} onChange={e => setGenBits(+e.target.value)} style={{width: 100}} />
        <button style={{...s.btn, background: '#a6e3a1'}} onClick={generate} disabled={loading}>Generate</button>
      </div>
      {generated && <div style={s.genOut}>{generated}</div>}
    </div>
  );
}

const s: Record<string, React.CSSProperties> = {
  panel: { padding: 16 },
  h3: { margin: '0 0 4px', color: '#89b4fa' },
  desc: { margin: '0 0 12px', color: '#6c7086', fontSize: '0.85rem' },
  row: { display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8, flexWrap: 'wrap' },
  genRow: { display: 'flex', gap: 8, alignItems: 'center', marginTop: 12, flexWrap: 'wrap' },
  label: { color: '#cdd6f4', fontSize: '0.85rem' },
  input: { background: '#313244', border: '1px solid #45475a', color: '#cdd6f4', padding: '6px 10px', borderRadius: 4, width: 200, fontFamily: 'monospace' },
  btn: { padding: '6px 14px', background: '#89b4fa', color: '#1e1e2e', border: 'none', borderRadius: 6, cursor: 'pointer', fontWeight: 600 },
  examples: { display: 'flex', gap: 6, marginBottom: 8, flexWrap: 'wrap' },
  exBtn: { padding: '3px 8px', background: '#313244', border: '1px solid #45475a', color: '#cdd6f4', borderRadius: 4, cursor: 'pointer', fontSize: '0.8rem', fontFamily: 'monospace' },
  err: { color: '#f38ba8' },
  badge: { padding: '8px 16px', borderRadius: 8, fontWeight: 700, fontSize: '1.1rem', marginTop: 8, display: 'inline-block' },
  genOut: { fontFamily: 'monospace', fontSize: '0.8rem', color: '#a6e3a1', wordBreak: 'break-all', marginTop: 8, background: '#313244', padding: 8, borderRadius: 6 },
};
