import { useState, useEffect } from 'react';
import { apiPost, apiGet } from '../../api';

export default function DemoPA05() {
  const [pairs, setPairs] = useState<{message_hex: string; tag_hex: string}[]>([]);
  const [forgeMsg, setForgeMsg] = useState('');
  const [forgeTag, setForgeTag] = useState('');
  const [attempts, setAttempts] = useState(0);
  const [successes, setSuccesses] = useState(0);
  const [lastResult, setLastResult] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    apiGet<{pairs: {message_hex: string; tag_hex: string}[]}>('/pa05/forge-signed-messages').then(r => setPairs(r.pairs));
  }, []);

  const submitForgery = async () => {
    setLoading(true);
    try {
      const res = await apiPost<{forgery_accepted: boolean}>('/pa05/forge-attempt', {
        message_hex: forgeMsg, tag_hex: forgeTag
      });
      setLastResult(res.forgery_accepted);
      setAttempts(a => a + 1);
      if (res.forgery_accepted) setSuccesses(s => s + 1);
    } catch (_) { setLastResult(false); setAttempts(a => a + 1); }
    finally { setLoading(false); }
  };

  return (
    <div style={s.panel}>
      <h3 style={s.h3}>PA#5 — MAC Forge Attempt</h3>
      <p style={s.desc}>Server has a hidden key. Given signed messages, try to forge a new tag.</p>
      <div style={s.sigList}>
        <div style={s.label}>Signed messages (server's hidden key):</div>
        {pairs.slice(0, 5).map((p, i) => (
          <div key={i} style={s.sigRow}>
            <span style={s.msgHex}>{p.message_hex}</span>
            <span style={s.arrow}>→</span>
            <span style={s.tagHex}>{p.tag_hex}</span>
          </div>
        ))}
        {pairs.length > 5 && <div style={s.more}>…{pairs.length - 5} more</div>}
      </div>
      <div style={s.row}>
        <label style={s.label}>m* (hex):</label>
        <input style={s.input} value={forgeMsg} onChange={e => setForgeMsg(e.target.value)} placeholder="message hex" />
      </div>
      <div style={s.row}>
        <label style={s.label}>t* (hex):</label>
        <input style={s.input} value={forgeTag} onChange={e => setForgeTag(e.target.value)} placeholder="tag hex" />
      </div>
      <button style={s.btn} onClick={submitForgery} disabled={loading || !forgeMsg || !forgeTag}>
        Submit Forgery
      </button>
      {lastResult !== null && (
        <div style={{...s.result, color: lastResult ? '#f38ba8' : '#a6e3a1'}}>
          {lastResult ? '✓ Forgery ACCEPTED (unexpected!)' : '✗ Forgery rejected (expected)'}
        </div>
      )}
      <div style={s.score}>Attempts: {attempts} | Successes: {successes}</div>
    </div>
  );
}

const s: Record<string, React.CSSProperties> = {
  panel: { padding: 16 },
  h3: { margin: '0 0 4px', color: '#89b4fa' },
  desc: { margin: '0 0 12px', color: '#6c7086', fontSize: '0.85rem' },
  sigList: { background: '#313244', padding: 10, borderRadius: 6, marginBottom: 12 },
  sigRow: { display: 'flex', gap: 6, alignItems: 'center', marginBottom: 4, fontSize: '0.75rem', fontFamily: 'monospace' },
  msgHex: { color: '#89b4fa' },
  arrow: { color: '#6c7086' },
  tagHex: { color: '#a6e3a1' },
  more: { color: '#6c7086', fontSize: '0.8rem' },
  row: { display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8 },
  label: { color: '#cdd6f4', fontSize: '0.85rem', minWidth: 80 },
  input: { background: '#1e1e2e', border: '1px solid #45475a', color: '#cdd6f4', padding: '4px 8px', borderRadius: 4, fontFamily: 'monospace', width: 250 },
  btn: { padding: '6px 14px', background: '#f38ba8', color: '#1e1e2e', border: 'none', borderRadius: 6, cursor: 'pointer', fontWeight: 600 },
  result: { marginTop: 8, padding: 8, background: '#313244', borderRadius: 6, fontSize: '0.9rem' },
  score: { marginTop: 8, color: '#6c7086', fontSize: '0.85rem' },
};
