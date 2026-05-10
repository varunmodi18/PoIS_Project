import { useState } from 'react';
import { apiPost } from '../../api';

const MODES = ['CBC', 'OFB', 'CTR'];

export default function DemoPA04() {
  const [mode, setMode] = useState('CBC');
  const [msg, setMsg] = useState('41'.repeat(32));
  const [key] = useState('00'.repeat(16));
  const [result, setResult] = useState<{iv_hex: string; ciphertext_hex: string} | null>(null);
  const [flipResult, setFlipResult] = useState<{original_hex: string; corrupted_hex: string; corrupted_blocks: number[]} | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const encrypt = async () => {
    setLoading(true); setError('');
    try {
      const res = await apiPost<{iv_hex: string; ciphertext_hex: string}>('/pa04/encrypt', {
        mode, key_hex: key, message_hex: msg
      });
      setResult(res);
      setFlipResult(null);
    } catch (e: unknown) { setError(String(e)); }
    finally { setLoading(false); }
  };

  const flipBit = async () => {
    setLoading(true); setError('');
    try {
      const res = await apiPost<{original_hex: string; corrupted_hex: string; corrupted_blocks: number[]}>('/pa04/bit-flip', {
        mode, key_hex: key, message_hex: msg, flip_block: 0, flip_bit: 0
      });
      setFlipResult(res);
    } catch (e: unknown) { setError(String(e)); }
    finally { setLoading(false); }
  };

  const blocks = (hex: string) => {
    const arr = [];
    for (let i = 0; i < hex.length; i += 32) arr.push(hex.slice(i, i + 32));
    return arr;
  };

  return (
    <div style={s.panel}>
      <h3 style={s.h3}>PA#4 — Block Cipher Mode Animator</h3>
      <div style={s.tabs}>
        {MODES.map(m => (
          <button key={m} style={{...s.tab, ...(mode === m ? s.activeTab : {})}} onClick={() => setMode(m)}>{m}</button>
        ))}
      </div>
      <div style={s.row}>
        <label style={s.label}>Message (hex):</label>
        <input style={{...s.input, width: 300}} value={msg} onChange={e => setMsg(e.target.value)} />
        <button style={s.btn} onClick={encrypt} disabled={loading}>Encrypt</button>
        <button style={{...s.btn, background: '#f9e2af', color: '#1e1e2e'}} onClick={flipBit} disabled={loading}>Flip Bit</button>
      </div>
      {error && <div style={s.err}>{error}</div>}
      {result && (
        <div>
          <div style={s.label}>Ciphertext blocks:</div>
          <div style={s.blockRow}>
            {blocks(result.ciphertext_hex).map((b, i) => (
              <div key={i} style={s.block}><span style={s.blockIdx}>C{i}</span><span style={s.blockVal}>{b.slice(0, 8)}…</span></div>
            ))}
          </div>
        </div>
      )}
      {flipResult && (
        <div style={s.flipBox}>
          <div style={s.label}>Bit flip in C[0] corrupts plaintext blocks: {flipResult.corrupted_blocks.map(b => `P[${b}]`).join(', ') || 'none'}</div>
          <div style={s.modeNote}>
            {mode === 'CBC' && 'CBC: bit flip in C[i] corrupts P[i] (garbled) and P[i+1] (same bit flipped)'}
            {mode === 'OFB' && 'OFB: bit flip in C[i] corrupts only P[i] at the same position (1-bit error)'}
            {mode === 'CTR' && 'CTR: bit flip in C[i] corrupts only P[i] at the same position (1-bit error)'}
          </div>
        </div>
      )}
    </div>
  );
}

const s: Record<string, React.CSSProperties> = {
  panel: { padding: 16 },
  h3: { margin: '0 0 8px', color: '#89b4fa' },
  tabs: { display: 'flex', gap: 4, marginBottom: 12 },
  tab: { padding: '4px 12px', border: '1px solid #45475a', borderRadius: 4, background: '#313244', color: '#cdd6f4', cursor: 'pointer' },
  activeTab: { background: '#89b4fa', color: '#1e1e2e', fontWeight: 600, borderColor: '#89b4fa' },
  row: { display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8, flexWrap: 'wrap' },
  label: { color: '#cdd6f4', fontSize: '0.85rem', marginBottom: 4 },
  input: { background: '#313244', border: '1px solid #45475a', color: '#cdd6f4', padding: '4px 8px', borderRadius: 4, fontFamily: 'monospace' },
  btn: { padding: '6px 14px', background: '#89b4fa', color: '#1e1e2e', border: 'none', borderRadius: 6, cursor: 'pointer', fontWeight: 600 },
  err: { color: '#f38ba8', margin: '8px 0', fontSize: '0.85rem' },
  blockRow: { display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 8 },
  block: { background: '#313244', padding: '4px 8px', borderRadius: 4, display: 'flex', flexDirection: 'column', alignItems: 'center' },
  blockIdx: { color: '#6c7086', fontSize: '0.7rem' },
  blockVal: { fontFamily: 'monospace', fontSize: '0.8rem', color: '#89b4fa' },
  flipBox: { background: '#2a1e2e', padding: 10, borderRadius: 6, marginTop: 8 },
  modeNote: { color: '#f9e2af', fontSize: '0.85rem', marginTop: 6 },
};
