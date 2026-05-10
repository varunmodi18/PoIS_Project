import { useState } from 'react';
import { apiPost } from '../../api';

export default function DemoPA02() {
  const [key, setKey] = useState('12345');
  const [query, setQuery] = useState('1011');
  const [result, setResult] = useState<{output: number; trace: {path: string[]}} | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const evaluate = async () => {
    setLoading(true); setError('');
    try {
      const queryInt = parseInt(query, 2);
      const res = await apiPost<{output: number; trace: {path: string[]; nodes: Record<string, number>}}>('/pa02/ggm/evaluate', {
        key: parseInt(key) || 1, query: queryInt, input_bits: query.length || 4
      });
      setResult(res);
    } catch (e: unknown) { setError(String(e)); }
    finally { setLoading(false); }
  };

  return (
    <div style={s.panel}>
      <h3 style={s.h3}>PA#2 — GGM PRF Tree Visualizer</h3>
      <p style={s.desc}>GGM construction: PRG → PRF. Follow the bit path in the binary tree.</p>
      <div style={s.row}>
        <label style={s.label}>Key (integer):</label>
        <input style={s.input} value={key} onChange={e => setKey(e.target.value)} />
        <label style={s.label}>Query (bits e.g. 1011):</label>
        <input style={s.input} value={query} onChange={e => setQuery(e.target.value.replace(/[^01]/g, '').slice(0, 8))} />
        <button style={s.btn} onClick={evaluate} disabled={loading}>Evaluate</button>
      </div>
      {error && <div style={s.err}>{error}</div>}
      {loading && <div style={s.info}>Computing GGM tree...</div>}
      {result && (
        <div>
          <div style={s.treeBox}>
            <div style={s.treeLabel}>Path for query "{query}":</div>
            {query.split('').map((bit, i) => (
              <div key={i} style={s.treeNode}>
                <span style={s.depth}>Depth {i+1}</span>
                <span style={{...s.bitTag, background: bit === '1' ? '#89b4fa' : '#a6e3a1'}}>{bit === '1' ? 'G₁ (right)' : 'G₀ (left)'}</span>
              </div>
            ))}
          </div>
          <div style={s.outputBox}>
            <span style={s.label}>F(k, {query}) = </span>
            <span style={s.outputVal}>{result.output}</span>
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
  row: { display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8, flexWrap: 'wrap' },
  label: { color: '#cdd6f4', fontSize: '0.85rem' },
  input: { background: '#313244', border: '1px solid #45475a', color: '#cdd6f4', padding: '4px 8px', borderRadius: 4, width: 100 },
  btn: { padding: '6px 14px', background: '#89b4fa', color: '#1e1e2e', border: 'none', borderRadius: 6, cursor: 'pointer', fontWeight: 600 },
  err: { color: '#f38ba8', margin: '8px 0', fontSize: '0.85rem' },
  info: { color: '#f9e2af', margin: '8px 0', fontSize: '0.85rem' },
  treeBox: { background: '#313244', padding: 12, borderRadius: 6, marginBottom: 8 },
  treeLabel: { color: '#6c7086', fontSize: '0.8rem', marginBottom: 8 },
  treeNode: { display: 'flex', gap: 8, alignItems: 'center', marginBottom: 6 },
  depth: { color: '#6c7086', fontSize: '0.8rem', width: 60 },
  bitTag: { padding: '2px 8px', borderRadius: 4, color: '#1e1e2e', fontSize: '0.8rem', fontWeight: 600 },
  outputBox: { background: '#1e1e2e', padding: 12, borderRadius: 6, display: 'flex', gap: 8, alignItems: 'center' },
  outputVal: { fontFamily: 'monospace', color: '#a6e3a1', fontSize: '1rem', fontWeight: 600 },
};
