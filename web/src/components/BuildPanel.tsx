import { PRIMITIVES, PA_NUMBERS, type Primitive } from '../data/reductions';

interface BuildPanelProps {
  selected: Primitive;
  seed: string;
  onSelectChange: (p: Primitive) => void;
  onSeedChange: (s: string) => void;
}

export default function BuildPanel({ selected, seed, onSelectChange, onSeedChange }: BuildPanelProps) {
  const paNum = PA_NUMBERS[selected];

  return (
    <div style={styles.panel}>
      <h2 style={styles.heading}>Build Panel — Source Primitive A</h2>

      <label style={styles.label}>Select primitive:</label>
      <select
        style={styles.select}
        value={selected}
        onChange={e => onSelectChange(e.target.value as Primitive)}
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

      <div style={styles.stepBox}>
        <span style={styles.stub}>
          Not yet implemented (due: PA#{paNum})
        </span>
        <p style={styles.hint}>
          Primitive <strong>{selected}</strong> will be implemented in PA#{paNum}.
        </p>
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
  stepBox: {
    marginTop: '12px',
    padding: '14px',
    background: '#1e1e2e',
    borderRadius: '8px',
    border: '1px dashed #45475a',
  },
  stub: {
    color: '#f38ba8',
    fontWeight: 600,
    fontSize: '0.9rem',
  },
  hint: {
    margin: '8px 0 0',
    color: '#6c7086',
    fontSize: '0.8rem',
  },
};
