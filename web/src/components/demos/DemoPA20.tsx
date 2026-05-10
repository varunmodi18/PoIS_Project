import { useState } from 'react';
import { apiPost } from '../../api';

export default function DemoPA20() {
  const [aliceVal, setAliceVal] = useState(7);
  const [bobVal, setBobVal] = useState(5);
  const [millResult, setMillResult] = useState<{alice_richer: boolean; bob_richer: boolean; equal: boolean; gates: number; and_gates: number; correct: boolean} | null>(null);
  const [eqResult, setEqResult] = useState<{equal: boolean; correct: boolean} | null>(null);
  const [addResult, setAddResult] = useState<{sum: number; expected: number; correct: boolean} | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [activeDemo, setActiveDemo] = useState<'mill' | 'eq' | 'add'>('mill');

  const runMillionaires = async () => {
    setLoading(true); setError(''); setMillResult(null);
    try {
      const res = await apiPost<typeof millResult>('/pa20/millionaires', { x: aliceVal, y: bobVal, n_bits: 4 });
      setMillResult(res);
    } catch (e: unknown) { setError(String(e)); }
    finally { setLoading(false); }
  };

  const runEquality = async () => {
    setLoading(true); setError(''); setEqResult(null);
    try {
      const res = await apiPost<typeof eqResult>('/pa20/equality', { x: aliceVal, y: bobVal, n_bits: 4 });
      setEqResult(res);
    } catch (e: unknown) { setError(String(e)); }
    finally { setLoading(false); }
  };

  const runAddition = async () => {
    setLoading(true); setError(''); setAddResult(null);
    try {
      const res = await apiPost<typeof addResult>('/pa20/addition', { x: aliceVal, y: bobVal, n_bits: 4 });
      setAddResult(res);
    } catch (e: unknown) { setError(String(e)); }
    finally { setLoading(false); }
  };

  return (
    <div style={s.panel}>
      <h3 style={s.h3}>PA#20 — Multi-Party Computation</h3>
      <p style={s.desc}>Boolean circuit evaluation over secret inputs. Millionaire's problem, equality test, and secure addition — nobody reveals their value.</p>

      <div style={s.inputSection}>
        <div style={s.inputBlock}>
          <div style={s.inputLabel}>Alice's value</div>
          <input type="range" min={0} max={15} value={aliceVal} onChange={e => setAliceVal(+e.target.value)} style={{width: 120}} />
          <span style={s.valDisplay}>{aliceVal}</span>
        </div>
        <div style={s.vs}>vs</div>
        <div style={s.inputBlock}>
          <div style={s.inputLabel}>Bob's value</div>
          <input type="range" min={0} max={15} value={bobVal} onChange={e => setBobVal(+e.target.value)} style={{width: 120}} />
          <span style={s.valDisplay}>{bobVal}</span>
        </div>
      </div>

      <div style={s.tabs}>
        {(['mill', 'eq', 'add'] as const).map(tab => (
          <button key={tab} style={{...s.tab, background: activeDemo === tab ? '#89b4fa' : '#313244', color: activeDemo === tab ? '#1e1e2e' : '#cdd6f4'}} onClick={() => setActiveDemo(tab)}>
            {tab === 'mill' ? "Millionaire's" : tab === 'eq' ? 'Equality' : 'Addition'}
          </button>
        ))}
      </div>

      {activeDemo === 'mill' && (
        <div>
          <p style={s.tabDesc}>Who has more wealth? Circuit compares 4-bit values without revealing them.</p>
          <button style={s.btn} onClick={runMillionaires} disabled={loading}>Run Millionaire's Problem</button>
          {millResult && (
            <div style={s.resultBox}>
              <div style={s.bigResult}>{millResult.alice_richer ? 'Alice is richer' : millResult.equal ? 'Equal wealth' : 'Bob is richer'}</div>
              <div style={s.detail}>Alice={aliceVal}, Bob={bobVal}</div>
              <div style={s.detail}>Circuit: {millResult.gates} gates ({millResult.and_gates} AND via OT)</div>
            </div>
          )}
        </div>
      )}

      {activeDemo === 'eq' && (
        <div>
          <p style={s.tabDesc}>Are the two values equal? XNOR each bit pair, AND all results.</p>
          <button style={s.btn} onClick={runEquality} disabled={loading}>Run Equality Test</button>
          {eqResult && (
            <div style={s.resultBox}>
              <div style={{...s.bigResult, color: eqResult.equal ? '#a6e3a1' : '#f38ba8'}}>{eqResult.equal ? '= Equal' : '≠ Not Equal'}</div>
              <div style={s.detail}>Alice={aliceVal}, Bob={bobVal}</div>
            </div>
          )}
        </div>
      )}

      {activeDemo === 'add' && (
        <div>
          <p style={s.tabDesc}>Compute Alice + Bob using ripple-carry adder circuit. Result revealed without revealing individual inputs.</p>
          <button style={s.btn} onClick={runAddition} disabled={loading}>Run Secure Addition</button>
          {addResult && (
            <div style={s.resultBox}>
              <div style={s.bigResult}>{aliceVal} + {bobVal} = <span style={{color: addResult.correct ? '#a6e3a1' : '#f38ba8'}}>{addResult.sum}</span></div>
              <div style={s.detail}>Expected: {addResult.expected} → {addResult.correct ? '✓ Correct' : '✗ Wrong'}</div>
            </div>
          )}
        </div>
      )}

      {error && <div style={s.err}>{error}</div>}
      {loading && <div style={s.info}>Evaluating boolean circuit securely...</div>}
    </div>
  );
}

const s: Record<string, React.CSSProperties> = {
  panel: { padding: 16 },
  h3: { margin: '0 0 4px', color: '#89b4fa' },
  desc: { margin: '0 0 12px', color: '#6c7086', fontSize: '0.85rem' },
  inputSection: { display: 'flex', gap: 16, alignItems: 'center', marginBottom: 14, flexWrap: 'wrap' },
  inputBlock: { display: 'flex', gap: 8, alignItems: 'center' },
  inputLabel: { color: '#cdd6f4', fontSize: '0.85rem', minWidth: 90 },
  valDisplay: { fontFamily: 'monospace', color: '#89b4fa', fontWeight: 700, fontSize: '1.2rem', minWidth: 28 },
  vs: { color: '#6c7086', fontSize: '1rem', fontWeight: 600 },
  tabs: { display: 'flex', gap: 6, marginBottom: 12 },
  tab: { padding: '5px 14px', border: 'none', borderRadius: 6, cursor: 'pointer', fontWeight: 600, fontSize: '0.85rem' },
  tabDesc: { color: '#6c7086', fontSize: '0.82rem', margin: '0 0 10px' },
  btn: { padding: '6px 14px', background: '#89b4fa', color: '#1e1e2e', border: 'none', borderRadius: 6, cursor: 'pointer', fontWeight: 600, marginBottom: 10 },
  err: { color: '#f38ba8' }, info: { color: '#f9e2af' },
  resultBox: { background: '#313244', padding: 14, borderRadius: 8 },
  bigResult: { fontSize: '1.3rem', fontWeight: 700, color: '#cdd6f4', marginBottom: 6 },
  detail: { color: '#6c7086', fontSize: '0.82rem', marginTop: 4 },
};
