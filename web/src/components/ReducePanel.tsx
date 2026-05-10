import { PRIMITIVES, REDUCTIONS, type Primitive } from '../data/reductions';

interface ReducePanelProps {
  source: Primitive;
  target: Primitive;
  message: string;
  direction: 'forward' | 'backward';
  onTargetChange: (p: Primitive) => void;
  onMessageChange: (m: string) => void;
}

function getReductionName(from: string, to: string): { name: string; paNum: number } {
  const r = REDUCTIONS.find(r => r.from === from && r.to === to);
  if (r) return { name: r.name, paNum: r.paNumber };
  return { name: 'No direct reduction known for A → B', paNum: 0 };
}

export default function ReducePanel({
  source, target, message, direction, onTargetChange, onMessageChange,
}: ReducePanelProps) {
  const availableTargets = PRIMITIVES.filter(p => p !== source);
  const { name: reductionName, paNum } = getReductionName(source, target);

  const fromLabel = direction === 'forward' ? source : target;
  const toLabel = direction === 'forward' ? target : source;

  return (
    <div style={styles.panel}>
      <h2 style={styles.heading}>Reduce Panel — Target Primitive B</h2>

      <label style={styles.label}>Select target primitive:</label>
      <select
        style={styles.select}
        value={target}
        onChange={e => onTargetChange(e.target.value as Primitive)}
      >
        {availableTargets.map(p => (
          <option key={p} value={p}>{p}</option>
        ))}
      </select>

      <label style={styles.label}>Message / query:</label>
      <input
        style={styles.input}
        type="text"
        placeholder="Enter message..."
        value={message}
        onChange={e => onMessageChange(e.target.value)}
      />

      <div style={styles.stepBox}>
        <span style={styles.direction}>
          {fromLabel} → {toLabel}
        </span>
        <div style={styles.reductionName}>{reductionName}</div>
        {paNum > 0 ? (
          <span style={styles.impl}>✓ Implemented (PA#{paNum})</span>
        ) : (
          <span style={styles.noPath}>{reductionName}</span>
        )}
        {paNum > 0 && (
          <p style={styles.hint}>
            Reduction <strong>{reductionName}</strong> implemented in PA#{paNum}.
          </p>
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
    color: '#a6e3a1',
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
  },
  stepBox: {
    marginTop: '12px',
    padding: '14px',
    background: '#1e1e2e',
    borderRadius: '8px',
    border: '1px dashed #45475a',
    display: 'flex',
    flexDirection: 'column',
    gap: '6px',
  },
  direction: {
    fontSize: '0.85rem',
    color: '#89dceb',
    fontFamily: 'monospace',
  },
  reductionName: {
    fontSize: '0.95rem',
    color: '#cdd6f4',
    fontWeight: 600,
  },
  impl: {
    color: '#a6e3a1',
    fontWeight: 600,
    fontSize: '0.9rem',
  },
  noPath: {
    color: '#fab387',
    fontSize: '0.9rem',
  },
  hint: {
    margin: '4px 0 0',
    color: '#6c7086',
    fontSize: '0.8rem',
  },
};
