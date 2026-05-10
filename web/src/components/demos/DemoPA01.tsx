import { useState } from 'react';
import { apiPost } from '../../api';

export default function DemoPA01() {
  const [seed, setSeed] = useState('42');
  const [length, setLength] = useState(64);
  const [bits, setBits] = useState<number[]>([]);
  const [statResults, setStatResults] = useState<Record<string, {passed: boolean; p_value: number}> | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const generate = async () => {
    setLoading(true); setError('');
    try {
      const res = await apiPost<{bits: number[]}>('/pa01/generate-prg', {
        seed: parseInt(seed) || 42, output_bits: length, owf_bits: 64
      });
      setBits(res.bits);
    } catch (e: unknown) {
      setError(String(e));
    } finally { setLoading(false); }
  };

  const runTests = async () => {
    setLoading(true); setError('');
    try {
      const genRes = await apiPost<{bits: number[]}>('/pa01/generate-prg', {
        seed: parseInt(seed) || 42, output_bits: Math.max(length, 1000), owf_bits: 64
      });
      const res = await apiPost<Record<string, {pass: boolean; p_value: number}>>('/pa01/run-statistical-tests', {
        bits: genRes.bits
      });
      const mapped: Record<string, {passed: boolean; p_value: number}> = {};
      for (const [k, v] of Object.entries(res)) {
        mapped[k] = { passed: v.pass, p_value: v.p_value };
      }
      setStatResults(mapped);
    } catch (e: unknown) {
      setError(String(e));
    } finally { setLoading(false); }
  };

  return (
    <div style={s.panel}>
      <h3 style={s.h3}>PA#1 — Live PRG Output Viewer</h3>
      <p style={s.desc}>DLP-based OWF → PRG via hard-core bits. HILL Theorem.</p>
      <div style={s.row}>
        <label style={s.label}>Seed (integer):</label>
        <input style={s.input} value={seed} onChange={e => setSeed(e.target.value)} />
        <label style={s.label}>Length: {length} bits</label>
        <input type="range" min={8} max={256} value={length} onChange={e => setLength(+e.target.value)} />
      </div>
      <div style={s.row}>
        <button style={s.btn} onClick={generate} disabled={loading}>Generate G(s)</button>
        <button style={s.btn} onClick={runTests} disabled={loading}>Randomness Tests</button>
      </div>
      {error && <div style={s.err}>{error}</div>}
      {loading && <div style={s.info}>Computing...</div>}
      {bits.length > 0 && (
        <div>
          <div style={s.label}>Output ({bits.length} bits):</div>
          <div style={s.bitGrid}>
            {bits.map((b, i) => (
              <span key={i} style={{...s.bit, background: b ? '#89b4fa' : '#313244'}} />
            ))}
          </div>
          <div style={s.hex}>{bits.join('')}</div>
        </div>
      )}
      {statResults && (
        <div style={s.statBox}>
          {Object.entries(statResults).map(([name, r]) => (
            <div key={name} style={s.statRow}>
              <span style={{color: r.passed ? '#a6e3a1' : '#f38ba8'}}>{r.passed ? '✓' : '✗'}</span>
              <span style={s.statName}>{name.replace(/_/g, ' ')}</span>
              <span style={s.statVal}>p = {r.p_value.toFixed(4)}</span>
            </div>
          ))}
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
  input: { background: '#313244', border: '1px solid #45475a', color: '#cdd6f4', padding: '4px 8px', borderRadius: 4, width: 80 },
  btn: { padding: '6px 14px', background: '#89b4fa', color: '#1e1e2e', border: 'none', borderRadius: 6, cursor: 'pointer', fontWeight: 600 },
  err: { color: '#f38ba8', margin: '8px 0', fontSize: '0.85rem' },
  info: { color: '#f9e2af', margin: '8px 0', fontSize: '0.85rem' },
  bitGrid: { display: 'flex', flexWrap: 'wrap', gap: 2, margin: '8px 0' },
  bit: { width: 8, height: 8, borderRadius: 1, display: 'inline-block' },
  hex: { fontFamily: 'monospace', fontSize: '0.75rem', color: '#6c7086', wordBreak: 'break-all' },
  statBox: { marginTop: 8, background: '#313244', padding: 8, borderRadius: 6 },
  statRow: { display: 'flex', gap: 8, alignItems: 'center', marginBottom: 4 },
  statName: { flex: 1, color: '#cdd6f4', fontSize: '0.85rem' },
  statVal: { color: '#6c7086', fontFamily: 'monospace', fontSize: '0.85rem' },
};
