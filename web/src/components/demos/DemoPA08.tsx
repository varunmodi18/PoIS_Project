import { useState } from 'react';
import { apiPost } from '../../api';

export default function DemoPA08() {
  const [msg, setMsg] = useState('Hello');
  const [digest, setDigest] = useState('');
  const [collision, setCollision] = useState<{collision_found: boolean; input1_hex: string; input2_hex: string; evaluations: number} | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const msgToHex = (s: string) => Array.from(new TextEncoder().encode(s)).map(b => b.toString(16).padStart(2, '0')).join('');

  const hashMsg = async () => {
    setLoading(true); setError('');
    try {
      const res = await apiPost<{digest_hex: string}>('/pa08/hash', { message_hex: msgToHex(msg), bits: 64 });
      setDigest(res.digest_hex);
    } catch (e: unknown) { setError(String(e)); }
    finally { setLoading(false); }
  };

  const hunt = async () => {
    setLoading(true); setError(''); setCollision(null);
    try {
      const res = await apiPost<typeof collision>('/pa08/collision-hunt', { output_bits: 12 });
      setCollision(res);
    } catch (e: unknown) { setError(String(e)); }
    finally { setLoading(false); }
  };

  return (
    <div style={s.panel}>
      <h3 style={s.h3}>PA#8 — DLP Hash Live</h3>
      <p style={s.desc}>DLP-based CRHF: h(x,y) = g^x · ĥ^y mod p, chained via Merkle-Damgård.</p>
      <div style={s.row}>
        <input style={s.input} value={msg} onChange={e => setMsg(e.target.value)} placeholder="Enter message" />
        <button style={s.btn} onClick={hashMsg} disabled={loading}>Hash</button>
      </div>
      {digest && <div style={s.digest}>H(msg) = <span style={s.mono}>{digest}</span></div>}
      <button style={{...s.btn, background: '#f38ba8', marginTop: 12}} onClick={hunt} disabled={loading}>
        Run Birthday Collision Hunt (12-bit output)
      </button>
      {error && <div style={s.err}>{error}</div>}
      {loading && <div style={s.info}>Hunting for collision...</div>}
      {collision && (
        <div style={s.collisionBox}>
          {collision.collision_found ? (
            <>
              <div style={s.colFound}>Collision found in {collision.evaluations} evaluations!</div>
              <div style={s.colRow}><span style={s.colLabel}>Input 1:</span><span style={s.mono}>{collision.input1_hex}</span></div>
              <div style={s.colRow}><span style={s.colLabel}>Input 2:</span><span style={s.mono}>{collision.input2_hex}</span></div>
              <div style={{color: '#6c7086', fontSize: '0.8rem'}}>Expected ≈ √(π/2 · 2^12) ≈ {Math.round(Math.sqrt(Math.PI / 2 * 4096))} evals</div>
            </>
          ) : <div style={s.err}>No collision found within limit</div>}
        </div>
      )}
    </div>
  );
}

const s: Record<string, React.CSSProperties> = {
  panel: { padding: 16 },
  h3: { margin: '0 0 4px', color: '#89b4fa' },
  desc: { margin: '0 0 12px', color: '#6c7086', fontSize: '0.85rem' },
  row: { display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8 },
  input: { background: '#313244', border: '1px solid #45475a', color: '#cdd6f4', padding: '6px 10px', borderRadius: 4, flex: 1 },
  btn: { padding: '6px 14px', background: '#89b4fa', color: '#1e1e2e', border: 'none', borderRadius: 6, cursor: 'pointer', fontWeight: 600 },
  digest: { background: '#313244', padding: 8, borderRadius: 6, fontSize: '0.85rem', color: '#cdd6f4' },
  mono: { fontFamily: 'monospace', color: '#89b4fa' },
  err: { color: '#f38ba8', margin: '8px 0', fontSize: '0.85rem' },
  info: { color: '#f9e2af', margin: '8px 0', fontSize: '0.85rem' },
  collisionBox: { background: '#313244', padding: 12, borderRadius: 6, marginTop: 8 },
  colFound: { color: '#a6e3a1', fontWeight: 600, marginBottom: 8 },
  colRow: { display: 'flex', gap: 8, marginBottom: 4 },
  colLabel: { color: '#6c7086', fontSize: '0.85rem', width: 60 },
};
