import { useState } from 'react';
import { apiPost } from '../../api';

export default function DemoPA19() {
  const [a, setA] = useState<0 | 1>(0);
  const [b, setB] = useState<0 | 1>(0);
  const [andResult, setAndResult] = useState<{result: number; protocol_log: string[]} | null>(null);
  const [xorResult, setXorResult] = useState<{result: number} | null>(null);
  const [notResult, setNotResult] = useState<{result: number} | null>(null);
  const [tableResult, setTableResult] = useState<{truth_table: {a: number; b: number; result: number; correct: boolean}[]} | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const runAnd = async () => {
    setLoading(true); setError('');
    try {
      const res = await apiPost<typeof andResult>('/pa19/and', { a, b, bits: 64 });
      setAndResult(res); setXorResult(null); setNotResult(null);
    } catch (e: unknown) { setError(String(e)); }
    finally { setLoading(false); }
  };

  const runXor = async () => {
    setLoading(true); setError('');
    try {
      const res = await apiPost<typeof xorResult>('/pa19/xor', { a, b });
      setXorResult(res); setAndResult(null); setNotResult(null);
    } catch (e: unknown) { setError(String(e)); }
    finally { setLoading(false); }
  };

  const runNot = async () => {
    setLoading(true); setError('');
    try {
      const res = await apiPost<typeof notResult>('/pa19/not', { a });
      setNotResult(res); setAndResult(null); setXorResult(null);
    } catch (e: unknown) { setError(String(e)); }
    finally { setLoading(false); }
  };

  const runAll = async () => {
    setLoading(true); setError('');
    try {
      const res = await apiPost<typeof tableResult>('/pa19/run-all', { bits: 64 });
      setTableResult(res);
    } catch (e: unknown) { setError(String(e)); }
    finally { setLoading(false); }
  };

  return (
    <div style={s.panel}>
      <h3 style={s.h3}>PA#19 — Secure Boolean Gates</h3>
      <p style={s.desc}>AND via 1-of-2 OT (Alice holds truth table row), XOR via secret sharing, NOT is local. No party learns the other's input.</p>

      <div style={s.inputRow}>
        <div style={s.bitCtrl}>
          <span style={s.label}>Alice a:</span>
          <button style={{...s.bit, background: a === 0 ? '#89b4fa' : '#313244'}} onClick={() => setA(0)}>0</button>
          <button style={{...s.bit, background: a === 1 ? '#89b4fa' : '#313244'}} onClick={() => setA(1)}>1</button>
        </div>
        <div style={s.bitCtrl}>
          <span style={s.label}>Bob b:</span>
          <button style={{...s.bit, background: b === 0 ? '#89b4fa' : '#313244'}} onClick={() => setB(0)}>0</button>
          <button style={{...s.bit, background: b === 1 ? '#89b4fa' : '#313244'}} onClick={() => setB(1)}>1</button>
        </div>
      </div>

      <div style={s.gateRow}>
        <button style={{...s.gateBtn, background: '#89b4fa'}} onClick={runAnd} disabled={loading}>Secure AND</button>
        <button style={{...s.gateBtn, background: '#cba6f7'}} onClick={runXor} disabled={loading}>Secure XOR</button>
        <button style={{...s.gateBtn, background: '#f9e2af', color: '#1e1e2e'}} onClick={runNot} disabled={loading}>Secure NOT(a)</button>
      </div>

      {error && <div style={s.err}>{error}</div>}
      {loading && <div style={s.info}>Computing secure gate...</div>}

      {andResult && (
        <div>
          <div style={s.resultBadge}>AND({a}, {b}) = <span style={s.resVal}>{andResult.result}</span><span style={s.expected}> (expected {a & b})</span></div>
          <div style={s.logBox}>
            <div style={s.logHead}>OT Protocol Log</div>
            {andResult.protocol_log.map((l, i) => <div key={i} style={s.logLine}>{l}</div>)}
          </div>
        </div>
      )}
      {xorResult && (
        <div style={s.resultBadge}>XOR({a}, {b}) = <span style={s.resVal}>{xorResult.result}</span><span style={s.expected}> (expected {a ^ b})</span></div>
      )}
      {notResult && (
        <div style={s.resultBadge}>NOT({a}) = <span style={s.resVal}>{notResult.result}</span><span style={s.expected}> (expected {1 - a})</span></div>
      )}

      <hr style={s.hr} />
      <button style={{...s.gateBtn, background: '#a6e3a1', color: '#1e1e2e'}} onClick={runAll} disabled={loading}>Run All Gates (Truth Table)</button>
      {tableResult && (
        <div style={s.tableWrap}>
          <div style={s.tableHead}>AND Gate Truth Table</div>
          <table style={s.table}>
            <thead><tr><th style={s.th}>a</th><th style={s.th}>b</th><th style={s.th}>a AND b</th></tr></thead>
            <tbody>
              {tableResult.truth_table.map((row, i) => (
                <tr key={i}>
                  <td style={s.td}>{row.a}</td>
                  <td style={s.td}>{row.b}</td>
                  <td style={{...s.td, color: '#a6e3a1', fontWeight: 600}}>{row.result}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

const s: Record<string, React.CSSProperties> = {
  panel: { padding: 16 },
  h3: { margin: '0 0 4px', color: '#89b4fa' },
  desc: { margin: '0 0 12px', color: '#6c7086', fontSize: '0.85rem' },
  inputRow: { display: 'flex', gap: 24, marginBottom: 12, flexWrap: 'wrap' },
  bitCtrl: { display: 'flex', gap: 6, alignItems: 'center' },
  label: { color: '#cdd6f4', fontSize: '0.85rem' },
  bit: { width: 32, height: 32, border: 'none', borderRadius: 4, cursor: 'pointer', fontWeight: 700, color: '#1e1e2e', fontSize: '1rem' },
  gateRow: { display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap' },
  gateBtn: { padding: '6px 14px', color: '#1e1e2e', border: 'none', borderRadius: 6, cursor: 'pointer', fontWeight: 600 },
  err: { color: '#f38ba8' }, info: { color: '#f9e2af' },
  resultBadge: { background: '#313244', padding: '8px 14px', borderRadius: 6, fontSize: '0.9rem', color: '#cdd6f4', marginBottom: 8, display: 'inline-block' },
  resVal: { color: '#a6e3a1', fontWeight: 700, fontSize: '1.1rem', marginLeft: 4 },
  expected: { color: '#6c7086', fontSize: '0.8rem', marginLeft: 4 },
  logBox: { background: '#1e1e2e', border: '1px solid #45475a', borderRadius: 6, padding: 10 },
  logHead: { color: '#89b4fa', fontWeight: 600, marginBottom: 6, fontSize: '0.8rem' },
  logLine: { color: '#cdd6f4', fontSize: '0.78rem', marginBottom: 2, fontFamily: 'monospace' },
  hr: { borderColor: '#45475a', margin: '12px 0' },
  tableWrap: { marginTop: 8 },
  tableHead: { color: '#89b4fa', fontWeight: 600, marginBottom: 6, fontSize: '0.85rem' },
  table: { borderCollapse: 'collapse', fontSize: '0.85rem' },
  th: { background: '#313244', color: '#cdd6f4', padding: '4px 16px', textAlign: 'center' as const },
  td: { padding: '3px 16px', textAlign: 'center' as const, borderBottom: '1px solid #45475a', color: '#cdd6f4' },
};
