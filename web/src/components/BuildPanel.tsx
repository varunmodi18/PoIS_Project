import { useState } from 'react';
import { PRIMITIVES, type Primitive } from '../data/reductions';
import { apiPost } from '../api';

interface BuildPanelProps {
  selected: Primitive;
  seed: string;
  onSelectChange: (p: Primitive) => void;
  onSeedChange: (s: string) => void;
}

interface ResultRow {
  label: string;
  value: string;
}

function truncate(s: string, max = 44): string {
  return s.length > max ? s.slice(0, max) + '…' : s;
}

async function evaluate(primitive: Primitive, seedHex: string): Promise<ResultRow[]> {
  const clean = seedHex.replace(/\s/g, '');

  switch (primitive) {
    case 'OWF': {
      const x = clean ? parseInt(clean, 16) : 42;
      const r = await apiPost<{ y: number; p: number; q: number; g: number }>(
        '/pa01/evaluate-owf', { x, bits: 64 }
      );
      return [
        { label: 'Input x', value: x.toString() },
        { label: 'f(x) = g^x mod p', value: truncate(r.y.toString()) },
        { label: 'Generator g', value: truncate(r.g.toString()) },
        { label: 'Prime p', value: truncate(r.p.toString()) },
      ];
    }

    case 'PRG': {
      const seed = clean ? parseInt(clean, 16) : 42;
      const r = await apiPost<{ bits: number[]; output_length: number }>(
        '/pa01/generate-prg', { seed, output_bits: 64, owf_bits: 64 }
      );
      const bitStr = r.bits.join('');
      const hexOut = BigInt('0b' + bitStr).toString(16).padStart(16, '0');
      return [
        { label: 'Seed', value: seed.toString() },
        { label: 'Output (64 bits)', value: bitStr },
        { label: 'Output (hex)', value: hexOut },
      ];
    }

    case 'PRF': {
      const keyHex = (clean || 'deadbeefcafe0000deadbeefcafe0000').padEnd(32, '0').slice(0, 32);
      const ptHex = 'deadbeefcafe000000000000deadbeef';
      const r = await apiPost<{ ciphertext_hex: string }>(
        '/pa02/aes/encrypt', { key_hex: keyHex, plaintext_hex: ptHex }
      );
      return [
        { label: 'Key (AES-128)', value: keyHex },
        { label: 'Input block', value: ptHex },
        { label: 'F_k(x)', value: r.ciphertext_hex },
      ];
    }

    case 'PRP': {
      const keyHex = (clean || 'deadbeefcafe0000deadbeefcafe0000').padEnd(32, '0').slice(0, 32);
      const msgHex = 'deadbeefcafe000000000000deadbeef';
      const r = await apiPost<{ iv_hex: string; ciphertext_hex: string }>(
        '/pa04/encrypt', { mode: 'CBC', key_hex: keyHex, message_hex: msgHex }
      );
      return [
        { label: 'Key', value: keyHex },
        { label: 'Plaintext', value: msgHex },
        { label: 'IV', value: r.iv_hex },
        { label: 'Ciphertext (CBC)', value: r.ciphertext_hex },
      ];
    }

    case 'MAC': {
      const keyHex = (clean || 'deadbeefcafe0000deadbeefcafe0000').padEnd(32, '0').slice(0, 32);
      const msgHex = '48656c6c6f576f726c64'; // "HelloWorld"
      const r = await apiPost<{ tag_hex: string }>(
        '/pa05/mac', { key_hex: keyHex, message_hex: msgHex, mode: 'cbc' }
      );
      return [
        { label: 'Key', value: keyHex },
        { label: 'Message', value: '"HelloWorld"' },
        { label: 'Tag (CBC-MAC)', value: r.tag_hex },
      ];
    }

    case 'CRHF': {
      const msgHex = clean.length >= 2 ? clean : '48656c6c6f576f726c64';
      const r = await apiPost<{ digest_hex: string }>(
        '/pa08/hash', { message_hex: msgHex, bits: 64 }
      );
      return [
        { label: 'Message (hex)', value: truncate(msgHex) },
        { label: 'DLP Hash digest', value: r.digest_hex },
      ];
    }

    case 'HMAC': {
      const keyHex = (clean || 'deadbeefcafe0000deadbeefcafe0000').padEnd(32, '0').slice(0, 32);
      const msgHex = '48656c6c6f576f726c64'; // "HelloWorld"
      const r = await apiPost<{ tag_hex: string }>(
        '/pa10/hmac', { key_hex: keyHex, message_hex: msgHex }
      );
      return [
        { label: 'Key', value: keyHex },
        { label: 'Message', value: '"HelloWorld"' },
        { label: 'HMAC tag', value: r.tag_hex },
      ];
    }

    default:
      return [];
  }
}

export default function BuildPanel({ selected, seed, onSelectChange, onSeedChange }: BuildPanelProps) {
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<ResultRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleSelectChange = (p: Primitive) => {
    setResults(null);
    setError(null);
    onSelectChange(p);
  };

  const handleRun = async () => {
    setLoading(true);
    setError(null);
    setResults(null);
    try {
      setResults(await evaluate(selected, seed));
    } catch (e: unknown) {
      const err = e as { response?: { data?: { detail?: string } }; message?: string };
      setError(err?.response?.data?.detail ?? err?.message ?? 'Request failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={styles.panel}>
      <h2 style={styles.heading}>Build Panel — Source Primitive A</h2>

      <label style={styles.label}>Select primitive:</label>
      <select
        style={styles.select}
        value={selected}
        onChange={e => handleSelectChange(e.target.value as Primitive)}
      >
        {PRIMITIVES.map(p => (
          <option key={p} value={p}>{p}</option>
        ))}
      </select>

      <label style={styles.label}>Hex seed / key:</label>
      <input
        style={styles.input}
        type="text"
        placeholder="e.g. deadbeefcafe..."
        value={seed}
        onChange={e => onSeedChange(e.target.value)}
      />

      <button
        style={{ ...styles.btn, opacity: loading ? 0.6 : 1, cursor: loading ? 'not-allowed' : 'pointer' }}
        onClick={handleRun}
        disabled={loading}
      >
        {loading ? 'Running…' : `▶  Run ${selected}`}
      </button>

      <div style={styles.stepBox}>
        {!results && !error && !loading && (
          <p style={styles.hint}>
            Enter a hex seed / key and click Run to evaluate <strong>{selected}</strong>.
          </p>
        )}
        {loading && <p style={styles.hint}>Computing…</p>}
        {error && <span style={styles.errorText}>{error}</span>}
        {results && (
          <>
            <span style={styles.implLabel}>✓ {selected} evaluated</span>
            {results.map((row, i) => (
              <div key={i} style={styles.row}>
                <span style={styles.rowLabel}>{row.label}</span>
                <span style={styles.rowValue}>{row.value}</span>
              </div>
            ))}
          </>
        )}
      </div>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  panel: {
    flex: 1,
    background: '#181825',
    borderRadius: '10px',
    padding: '20px',
    display: 'flex',
    flexDirection: 'column',
    gap: '10px',
  },
  heading: {
    margin: '0 0 6px',
    fontSize: '1rem',
    color: '#89b4fa',
  },
  label: {
    fontSize: '0.85rem',
    color: '#a6adc8',
  },
  select: {
    padding: '8px',
    borderRadius: '6px',
    border: '1px solid #45475a',
    background: '#313244',
    color: '#cdd6f4',
    fontSize: '0.9rem',
  },
  input: {
    padding: '8px',
    borderRadius: '6px',
    border: '1px solid #45475a',
    background: '#313244',
    color: '#cdd6f4',
    fontSize: '0.85rem',
    fontFamily: 'monospace',
  },
  btn: {
    padding: '9px 0',
    borderRadius: '6px',
    border: 'none',
    background: '#89b4fa',
    color: '#1e1e2e',
    fontWeight: 700,
    fontSize: '0.9rem',
  },
  stepBox: {
    marginTop: '4px',
    padding: '14px',
    background: '#1e1e2e',
    borderRadius: '8px',
    border: '1px solid #45475a',
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
    minHeight: '80px',
  },
  implLabel: {
    color: '#a6e3a1',
    fontWeight: 600,
    fontSize: '0.9rem',
  },
  row: {
    display: 'flex',
    flexDirection: 'column',
    gap: '2px',
  },
  rowLabel: {
    color: '#6c7086',
    fontSize: '0.75rem',
  },
  rowValue: {
    color: '#cdd6f4',
    fontFamily: 'monospace',
    fontSize: '0.82rem',
    wordBreak: 'break-all',
  },
  hint: {
    margin: 0,
    color: '#6c7086',
    fontSize: '0.8rem',
  },
  errorText: {
    color: '#f38ba8',
    fontSize: '0.85rem',
  },
};
