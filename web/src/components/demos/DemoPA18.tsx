import { useState } from 'react';
import { apiPost } from '../../api';

export default function DemoPA18() {
  const [choice, setChoice] = useState<0 | 1 | null>(null);
  const [result, setResult] = useState<{m0: string; m1: string; chosen: string; other_hidden: boolean; protocol_log: string[]} | null>(null);
  const [cheatResult, setCheatResult] = useState<{learned_other: boolean; note: string} | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const run = async (b: 0 | 1) => {
    setChoice(b); setLoading(true); setError(''); setCheatResult(null);
    try {
      const res = await apiPost<typeof result>('/pa18/run', { choice: b, bits: 64 });
      setResult(res);
    } catch (e: unknown) { setError(String(e)); }
    finally { setLoading(false); }
  };

  const cheat = async () => {
    if (result === null || choice === null) return;
    setLoading(true); setError('');
    try {
      const res = await apiPost<typeof cheatResult>('/pa18/cheat-attempt', { choice, bits: 64 });
      setCheatResult(res);
    } catch (e: unknown) { setError(String(e)); }
    finally { setLoading(false); }
  };

  return (
    <div style={s.panel}>
      <h3 style={s.h3}>PA#18 — Oblivious Transfer (1-of-2 OT)</h3>
      <p style={s.desc}>Alice holds two secret messages. Bob chooses one. He learns m_b, but Alice doesn't know b. Bob can't learn m_(1-b).</p>
      <div style={s.twoCol}>
        <div style={s.aliceBox}>
          <div style={s.boxHead}>Alice (Sender)</div>
          <div style={s.secretRow}><span style={s.label}>m₀ =</span><span style={s.hidden}>{result ? '[ hidden ]' : '???'}</span></div>
          <div style={s.secretRow}><span style={s.label}>m₁ =</span><span style={s.hidden}>{result ? '[ hidden ]' : '???'}</span></div>
          <div style={s.note}>Alice never learns Bob's choice b</div>
        </div>
        <div style={s.bobBox}>
          <div style={s.boxHead}>Bob (Receiver)</div>
          <div style={s.choiceRow}>
            <button style={{...s.choiceBtn, background: choice === 0 ? '#89b4fa' : '#313244'}} onClick={() => run(0)} disabled={loading}>Choose 0</button>
            <button style={{...s.choiceBtn, background: choice === 1 ? '#89b4fa' : '#313244'}} onClick={() => run(1)} disabled={loading}>Choose 1</button>
          </div>
          {result && (
            <div>
              <div style={s.reveal}><span style={s.label}>m_{choice} =</span><span style={s.val}>{result.chosen}</span></div>
              <div style={s.blocked}><span style={s.label}>m_{choice === 0 ? 1 : 0} =</span><span style={s.redacted}>?? (hidden)</span></div>
            </div>
          )}
        </div>
      </div>
      {error && <div style={s.err}>{error}</div>}
      {loading && <div style={s.info}>Running OT protocol...</div>}
      {result && (
        <div style={s.logBox}>
          <div style={s.logHead}>Protocol Log</div>
          {result.protocol_log.map((line, i) => <div key={i} style={s.logLine}>{line}</div>)}
        </div>
      )}
      {result && (
        <div>
          <button style={{...s.choiceBtn, background: '#f38ba8', color: '#1e1e2e', marginTop: 8}} onClick={cheat} disabled={loading}>
            Cheat Attempt (try to learn both)
          </button>
          {cheatResult && (
            <div style={{...s.badge, color: cheatResult.learned_other ? '#f38ba8' : '#a6e3a1'}}>
              {cheatResult.learned_other ? '⚠ Leaked!' : '✓ ' + cheatResult.note}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

const s: Record<string, React.CSSProperties> = {
  panel: { padding: 16 },
  h3: { margin: '0 0 4px', color: '#89b4fa' },
  desc: { margin: '0 0 12px', color: '#6c7086', fontSize: '0.85rem' },
  twoCol: { display: 'flex', gap: 12, marginBottom: 12 },
  aliceBox: { flex: 1, background: '#1e3a2a', border: '2px solid #a6e3a1', borderRadius: 8, padding: 12 },
  bobBox: { flex: 1, background: '#1e2a3a', border: '2px solid #89b4fa', borderRadius: 8, padding: 12 },
  boxHead: { fontWeight: 700, marginBottom: 10, fontSize: '0.9rem', color: '#cdd6f4' },
  secretRow: { display: 'flex', gap: 8, marginBottom: 6, fontSize: '0.85rem', alignItems: 'center' },
  label: { color: '#6c7086', fontSize: '0.85rem' },
  hidden: { fontFamily: 'monospace', color: '#6c7086', fontStyle: 'italic' },
  note: { color: '#6c7086', fontSize: '0.75rem', marginTop: 8, fontStyle: 'italic' },
  choiceRow: { display: 'flex', gap: 8, marginBottom: 10 },
  choiceBtn: { padding: '6px 14px', color: '#1e1e2e', border: 'none', borderRadius: 6, cursor: 'pointer', fontWeight: 600 },
  reveal: { display: 'flex', gap: 8, marginBottom: 4, fontSize: '0.85rem', alignItems: 'center' },
  blocked: { display: 'flex', gap: 8, fontSize: '0.85rem', alignItems: 'center' },
  val: { fontFamily: 'monospace', color: '#a6e3a1', fontWeight: 600 },
  redacted: { fontFamily: 'monospace', color: '#6c7086' },
  err: { color: '#f38ba8' }, info: { color: '#f9e2af' },
  logBox: { background: '#1e1e2e', border: '1px solid #45475a', borderRadius: 6, padding: 10, marginTop: 8 },
  logHead: { color: '#89b4fa', fontWeight: 600, marginBottom: 6, fontSize: '0.8rem' },
  logLine: { color: '#cdd6f4', fontSize: '0.78rem', marginBottom: 3, fontFamily: 'monospace' },
  badge: { padding: '6px 12px', background: '#313244', borderRadius: 6, marginTop: 8, fontWeight: 600, display: 'inline-block' },
};
