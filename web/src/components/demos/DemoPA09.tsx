import { useState } from 'react';
import { apiPost } from '../../api';

export default function DemoPA09() {
  const [bits, setBits] = useState(12);
  const [result, setResult] = useState<{collision_found: boolean; evaluations: number; expected: number; ratio: number} | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const run = async () => {
    setLoading(true); setError(''); setResult(null);
    try {
      const res = await apiPost<typeof result>('/pa09/attack', { output_bits: bits, algorithm: 'naive' });
      setResult(res);
    } catch (e: unknown) { setError(String(e)); }
    finally { setLoading(false); }
  };

  const expected = Math.round(Math.sqrt(Math.PI / 2) * Math.pow(2, bits / 2));
  const barWidth = result ? Math.min((result.evaluations / (expected * 3)) * 100, 100) : 0;
  const markerPos = Math.min((expected / (expected * 3)) * 100, 100);

  return (
    <div style={s.panel}>
      <h3 style={s.h3}>PA#9 — Birthday Attack Live</h3>
      <p style={s.desc}>Birthday paradox: expect collision after ~√(π/2 · 2^n) hash evaluations.</p>
      <div style={s.row}>
        <label style={s.label}>Output bits (n): {bits}</label>
        <input type="range" min={8} max={16} step={2} value={bits} onChange={e => setBits(+e.target.value)} style={{width: 200}} />
        <span style={s.label}>2^{bits} outputs, ~{expected} expected</span>
      </div>
      <button style={s.btn} onClick={run} disabled={loading}>Run Birthday Attack</button>
      {error && <div style={s.err}>{error}</div>}
      {loading && <div style={s.info}>Running attack...</div>}
      {result && (
        <div>
          <div style={s.statRow}>
            <span style={s.label}>Evaluations:</span>
            <span style={{...s.val, color: result.collision_found ? '#a6e3a1' : '#f38ba8'}}>{result.evaluations}</span>
          </div>
          <div style={s.statRow}>
            <span style={s.label}>Expected:</span>
            <span style={s.val}>{Math.round(result.expected)}</span>
          </div>
          <div style={s.statRow}>
            <span style={s.label}>Ratio (actual/expected):</span>
            <span style={s.val}>{result.ratio.toFixed(3)}</span>
          </div>
          <div style={s.barContainer}>
            <div style={{...s.bar, width: `${barWidth}%`, background: result.collision_found ? '#a6e3a1' : '#f38ba8'}} />
            <div style={{...s.marker, left: `${markerPos}%`}} />
          </div>
          <div style={s.barLabel}>← 2^(n/2) birthday bound at {expected}</div>
        </div>
      )}
    </div>
  );
}

const s: Record<string, React.CSSProperties> = {
  panel: { padding: 16 },
  h3: { margin: '0 0 4px', color: '#89b4fa' },
  desc: { margin: '0 0 12px', color: '#6c7086', fontSize: '0.85rem' },
  row: { display: 'flex', gap: 12, alignItems: 'center', marginBottom: 12, flexWrap: 'wrap' },
  label: { color: '#cdd6f4', fontSize: '0.85rem' },
  btn: { padding: '6px 14px', background: '#89b4fa', color: '#1e1e2e', border: 'none', borderRadius: 6, cursor: 'pointer', fontWeight: 600, marginBottom: 12 },
  err: { color: '#f38ba8', margin: '8px 0' },
  info: { color: '#f9e2af', margin: '8px 0' },
  statRow: { display: 'flex', gap: 8, marginBottom: 4 },
  val: { fontFamily: 'monospace', color: '#89b4fa' },
  barContainer: { position: 'relative', background: '#313244', height: 20, borderRadius: 10, margin: '12px 0', overflow: 'hidden' },
  bar: { height: '100%', borderRadius: 10, transition: 'width 0.5s' },
  marker: { position: 'absolute', top: 0, width: 2, height: '100%', background: '#f9e2af' },
  barLabel: { color: '#6c7086', fontSize: '0.75rem' },
};
