import { useState } from 'react';
import { apiPost } from '../../api';

export default function DemoPA11() {
  const [eveEnabled, setEveEnabled] = useState(false);
  const [dh, setDh] = useState<Record<string, string> | null>(null);
  const [mitm, setMitm] = useState<Record<string, string> | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const exchange = async () => {
    setLoading(true); setError('');
    try {
      if (eveEnabled) {
        const res = await apiPost<Record<string, string>>('/pa11/mitm', { bits: 64 });
        setMitm(res); setDh(null);
      } else {
        const res = await apiPost<Record<string, string>>('/pa11/exchange', { bits: 64 });
        setDh(res); setMitm(null);
      }
    } catch (e: unknown) { setError(String(e)); }
    finally { setLoading(false); }
  };

  return (
    <div style={s.panel}>
      <h3 style={s.h3}>PA#11 — Live Diffie-Hellman Exchange</h3>
      <p style={s.desc}>Alice and Bob establish a shared secret. Eve intercepts in MITM mode.</p>
      <div style={s.row}>
        <label style={s.label}>
          <input type="checkbox" checked={eveEnabled} onChange={e => setEveEnabled(e.target.checked)} /> Enable Eve (MITM)
        </label>
        <button style={s.btn} onClick={exchange} disabled={loading}>Exchange</button>
      </div>
      {error && <div style={s.err}>{error}</div>}
      {loading && <div style={s.info}>Computing...</div>}
      {dh && (
        <div style={s.row}>
          <div style={s.party}>
            <div style={s.partyHead}>Alice</div>
            <div style={s.kv}><span style={s.k}>a =</span><span style={s.v}>{dh.a?.slice(0,8)}…</span></div>
            <div style={s.kv}><span style={s.k}>A = g^a =</span><span style={s.v}>{dh.A?.slice(0,8)}…</span></div>
          </div>
          <div style={s.shared}>
            <div style={{color: '#a6e3a1', fontWeight: 600}}>K = B^a = A^b</div>
            <div style={{fontFamily: 'monospace', color: '#a6e3a1', fontSize: '0.85rem'}}>{dh.K?.slice(0,12)}…</div>
            <div style={{color: dh.keys_match === 'true' ? '#a6e3a1' : '#f38ba8', fontSize: '0.85rem'}}>{dh.keys_match === 'true' ? '✓ Match' : '✗ Mismatch'}</div>
          </div>
          <div style={s.party}>
            <div style={s.partyHead}>Bob</div>
            <div style={s.kv}><span style={s.k}>b =</span><span style={s.v}>{dh.b?.slice(0,8)}…</span></div>
            <div style={s.kv}><span style={s.k}>B = g^b =</span><span style={s.v}>{dh.B?.slice(0,8)}…</span></div>
          </div>
        </div>
      )}
      {mitm && (
        <div>
          <div style={s.mitmWarning}>⚠ MITM Active — Eve intercepts both parties</div>
          <div style={s.row}>
            <div style={s.party}><div style={s.partyHead}>Alice</div><div style={s.kv}><span style={s.k}>K_AE =</span><span style={s.vWarn}>{mitm.K_AE?.slice(0,8) || '?'}…</span></div></div>
            <div style={{...s.party, borderColor: '#f38ba8'}}><div style={{...s.partyHead, color: '#f38ba8'}}>Eve</div><div style={s.kv}><span style={s.k}>K_AE =</span><span style={s.vWarn}>{mitm.K_AE?.slice(0,8) || '?'}…</span></div><div style={s.kv}><span style={s.k}>K_BE =</span><span style={s.vWarn}>{mitm.K_BE?.slice(0,8) || '?'}…</span></div></div>
            <div style={s.party}><div style={s.partyHead}>Bob</div><div style={s.kv}><span style={s.k}>K_BE =</span><span style={s.vWarn}>{mitm.K_BE?.slice(0,8) || '?'}…</span></div></div>
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
  row: { display: 'flex', gap: 12, alignItems: 'center', marginBottom: 12, flexWrap: 'wrap' },
  label: { color: '#cdd6f4', fontSize: '0.85rem', display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' },
  btn: { padding: '6px 14px', background: '#89b4fa', color: '#1e1e2e', border: 'none', borderRadius: 6, cursor: 'pointer', fontWeight: 600 },
  err: { color: '#f38ba8' }, info: { color: '#f9e2af' },
  party: { background: '#313244', padding: 12, borderRadius: 8, border: '1px solid #45475a', minWidth: 140 },
  partyHead: { color: '#89b4fa', fontWeight: 600, marginBottom: 6 },
  kv: { display: 'flex', gap: 4, fontSize: '0.8rem', marginBottom: 2 },
  k: { color: '#6c7086' },
  v: { fontFamily: 'monospace', color: '#cdd6f4' },
  vWarn: { fontFamily: 'monospace', color: '#f38ba8' },
  shared: { background: '#1e3a2a', padding: 12, borderRadius: 8, textAlign: 'center', minWidth: 120 },
  mitmWarning: { background: '#3a1e1e', color: '#f38ba8', padding: '6px 12px', borderRadius: 6, marginBottom: 8, fontWeight: 600 },
};
