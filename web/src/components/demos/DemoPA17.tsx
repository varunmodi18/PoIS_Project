import { useState } from 'react';
import { apiPost } from '../../api';

export default function DemoPA17() {
  const [result, setResult] = useState<{original_m: string; cca_pkc: {blocked: boolean; error?: string}; plain_elgamal: {malleable: boolean; decrypted: string; expected_2m: string}} | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const demo = async () => {
    setLoading(true); setError('');
    try {
      const res = await apiPost<typeof result>('/pa17/tamper-demo', { elgamal_bits: 64, rsa_bits: 512 });
      setResult(res);
    } catch (e: unknown) { setError(String(e)); }
    finally { setLoading(false); }
  };

  return (
    <div style={s.panel}>
      <h3 style={s.h3}>PA#17 — CCA-Secure PKC via Signcrypt</h3>
      <p style={s.desc}>Encrypt-then-Sign: tamper c₂ → signature fails → decryption blocked. Contrast with plain ElGamal.</p>
      <button style={s.btn} onClick={demo} disabled={loading}>Run Tamper Demo</button>
      {error && <div style={s.err}>{error}</div>}
      {loading && <div style={s.info}>Generating keys and running demo...</div>}
      {result && (
        <div>
          <div style={s.msgLine}>Original m: <span style={s.mono}>{result.original_m.slice(0, 12)}…</span></div>
          <div style={s.columns}>
            <div style={{...s.col, borderColor: '#a6e3a1'}}>
              <div style={{...s.colHead, color: '#a6e3a1'}}>CCA-Secure (Encrypt-then-Sign)</div>
              <div>Tamper c₂ → verify signature…</div>
              <div style={s.verdict}>{result.cca_pkc.blocked ? '⊥ Signature invalid — decryption BLOCKED' : '⚠ Tamper not caught'}</div>
            </div>
            <div style={{...s.col, borderColor: '#f38ba8'}}>
              <div style={{...s.colHead, color: '#f38ba8'}}>Plain ElGamal (malleable)</div>
              <div>Tamper c₂ → decrypt(c₁, 2c₂)…</div>
              <div style={s.verdict_bad}>
                {result.plain_elgamal.malleable ? `Decrypted = 2m ✗` : 'Not malleable'}<br />
                Got: {result.plain_elgamal.decrypted.slice(0, 12)}… expected: {result.plain_elgamal.expected_2m.slice(0, 12)}…
              </div>
            </div>
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
  btn: { padding: '6px 14px', background: '#89b4fa', color: '#1e1e2e', border: 'none', borderRadius: 6, cursor: 'pointer', fontWeight: 600, marginBottom: 12 },
  err: { color: '#f38ba8' }, info: { color: '#f9e2af' },
  msgLine: { color: '#cdd6f4', marginBottom: 8, fontSize: '0.9rem' },
  mono: { fontFamily: 'monospace', color: '#89b4fa' },
  columns: { display: 'flex', gap: 12 },
  col: { flex: 1, border: '2px solid', borderRadius: 8, padding: 12, fontSize: '0.85rem', color: '#cdd6f4' },
  colHead: { fontWeight: 700, marginBottom: 8 },
  verdict: { marginTop: 8, color: '#a6e3a1', fontWeight: 600 },
  verdict_bad: { marginTop: 8, color: '#f38ba8', fontWeight: 600, fontSize: '0.8rem' },
};
