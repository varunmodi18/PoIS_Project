import { useState } from 'react';
import { REDUCTIONS, type Primitive } from '../data/reductions';

interface BottomPanelProps {
  foundation: 'AES' | 'DLP';
  source: Primitive;
  target: Primitive;
}

export default function BottomPanel({ foundation, source, target }: BottomPanelProps) {
  const [open, setOpen] = useState(false);

  const step = REDUCTIONS.find(r => r.from === source && r.to === target);

  return (
    <div style={styles.container}>
      <button style={styles.toggleBtn} onClick={() => setOpen(o => !o)}>
        {open ? '▲' : '▼'} Reduction Proof Summary
      </button>

      {open && (
        <div style={styles.content}>
          <div style={styles.chain}>
            <span style={styles.node}>Foundation: {foundation}</span>
            <span style={styles.arrow}> → </span>
            <span style={styles.node}>{source}</span>
            <span style={styles.arrow}> → </span>
            <span style={styles.node}>{target}</span>
          </div>

          {step ? (
            <div style={styles.details}>
              <p><strong>Reduction:</strong> {step.name}</p>
              <p><strong>Theorem:</strong> {step.theorem}</p>
              <p><strong>PA#:</strong> {step.paNumber}</p>
              <p><strong>Status:</strong>{' '}
                <span style={{ color: step.implemented ? '#a6e3a1' : '#f38ba8' }}>
                  {step.implemented ? '✓ Implemented' : '○ Not yet implemented'}
                </span>
              </p>
            </div>
          ) : (
            <p style={styles.noStep}>No direct reduction from {source} to {target} in the table.</p>
          )}
        </div>
      )}
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  container: {
    borderTop: '1px solid #313244',
    background: '#181825',
  },
  toggleBtn: {
    width: '100%',
    padding: '10px 24px',
    textAlign: 'left',
    background: 'transparent',
    border: 'none',
    color: '#cdd6f4',
    cursor: 'pointer',
    fontSize: '0.9rem',
    fontWeight: 600,
  },
  content: {
    padding: '12px 24px 20px',
  },
  chain: {
    fontSize: '1rem',
    marginBottom: '12px',
  },
  node: {
    padding: '4px 10px',
    background: '#313244',
    borderRadius: '6px',
    color: '#89b4fa',
    fontWeight: 600,
  },
  arrow: {
    color: '#6c7086',
    fontWeight: 700,
  },
  details: {
    fontSize: '0.9rem',
    color: '#cdd6f4',
    lineHeight: 1.8,
  },
  noStep: {
    color: '#6c7086',
    fontSize: '0.85rem',
  },
};
