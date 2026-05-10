import { useState } from 'react';
import { apiPost } from '../../api';

export default function DemoPA03() {
  const [m0, setM0] = useState('48656c6c6f');
  const [m1, setM1] = useState('576f726c64');
  const [challenge, setChallenge] = useState<{ciphertext_hex: string; nonce_hex: string; id: string} | null>(null);
  const [score, setScore] = useState({rounds: 0, correct: 0});
  const [lastResult, setLastResult] = useState<{correct: boolean; actual_b: number} | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const encrypt = async () => {
    if (m0.length !== m1.length) { setError('m0 and m1 must be same length'); return; }
    setLoading(true); setError('');
    try {
      const res = await apiPost<{ciphertext_hex: string; nonce_hex: string; challenge_id: string}>('/pa03/cpa-game', {
        m0_hex: m0, m1_hex: m1
      });
      setChallenge({ciphertext_hex: res.ciphertext_hex, nonce_hex: res.nonce_hex, id: res.challenge_id});
      setLastResult(null);
    } catch (e: unknown) { setError(String(e)); }
    finally { setLoading(false); }
  };

  const guess = async (b: number) => {
    if (!challenge) return;
    setLoading(true);
    try {
      const res = await apiPost<{correct: boolean; actual_b: number}>('/pa03/cpa-game/guess', {
        challenge_id: challenge.id, guess: b
      });
      setLastResult(res);
      setScore(prev => ({rounds: prev.rounds + 1, correct: prev.correct + (res.correct ? 1 : 0)}));
      setChallenge(null);
    } catch (e: unknown) { setError(String(e)); }
    finally { setLoading(false); }
  };

  const advantage = score.rounds > 0 ? Math.abs((score.correct / score.rounds) - 0.5) * 2 : 0;

  return (
    <div style={s.panel}>
      <h3 style={s.h3}>PA#3 — IND-CPA Security Game</h3>
      <p style={s.desc}>Submit m₀ and m₁. Challenger encrypts one. Guess which!</p>
      <div style={s.row}>
        <label style={s.label}>m₀ (hex):</label>
        <input style={s.input} value={m0} onChange={e => setM0(e.target.value)} />
      </div>
      <div style={s.row}>
        <label style={s.label}>m₁ (hex):</label>
        <input style={s.input} value={m1} onChange={e => setM1(e.target.value)} />
      </div>
      <button style={s.btn} onClick={encrypt} disabled={loading || !!challenge}>
        Encrypt m_b (challenger picks b)
      </button>
      {error && <div style={s.err}>{error}</div>}
      {challenge && (
        <div style={s.challengeBox}>
          <div style={s.label}>C* = {challenge.ciphertext_hex.slice(0, 32)}...</div>
          <div style={s.row}>
            <button style={{...s.btn, background: '#a6e3a1'}} onClick={() => guess(0)} disabled={loading}>Guess b=0 (m₀)</button>
            <button style={{...s.btn, background: '#f38ba8', color: '#1e1e2e'}} onClick={() => guess(1)} disabled={loading}>Guess b=1 (m₁)</button>
          </div>
        </div>
      )}
      {lastResult && (
        <div style={{...s.resultBox, background: lastResult.correct ? '#1e3a2a' : '#3a1e1e'}}>
          {lastResult.correct ? '✓ Correct!' : '✗ Wrong!'} actual b = {lastResult.actual_b}
        </div>
      )}
      <div style={s.scoreBox}>
        Rounds: {score.rounds} | Correct: {score.correct} | Advantage: {advantage.toFixed(3)}
        <br /><span style={s.hint}>(A perfect adversary has advantage 1. Random guessing ≈ 0.)</span>
      </div>
    </div>
  );
}

const s: Record<string, React.CSSProperties> = {
  panel: { padding: 16 },
  h3: { margin: '0 0 4px', color: '#89b4fa' },
  desc: { margin: '0 0 12px', color: '#6c7086', fontSize: '0.85rem' },
  row: { display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8, flexWrap: 'wrap' },
  label: { color: '#cdd6f4', fontSize: '0.85rem' },
  input: { background: '#313244', border: '1px solid #45475a', color: '#cdd6f4', padding: '4px 8px', borderRadius: 4, width: 200, fontFamily: 'monospace' },
  btn: { padding: '6px 14px', background: '#89b4fa', color: '#1e1e2e', border: 'none', borderRadius: 6, cursor: 'pointer', fontWeight: 600 },
  err: { color: '#f38ba8', margin: '8px 0', fontSize: '0.85rem' },
  challengeBox: { background: '#313244', padding: 12, borderRadius: 6, margin: '8px 0' },
  resultBox: { padding: 8, borderRadius: 6, margin: '8px 0', color: '#cdd6f4' },
  scoreBox: { marginTop: 12, background: '#313244', padding: 10, borderRadius: 6, color: '#cdd6f4', fontSize: '0.9rem' },
  hint: { color: '#6c7086', fontSize: '0.8rem' },
};
