import { type ReductionStep } from '../data/reductions';

interface StepDisplayProps {
  step: ReductionStep | null;
  source: string;
  target: string;
  direction: 'forward' | 'backward';
}

export default function StepDisplay({ step, source, target, direction }: StepDisplayProps) {
  const fromLabel = direction === 'forward' ? source : target;
  const toLabel = direction === 'forward' ? target : source;

  if (!step) {
    return (
      <div style={s.box}>
        <div style={s.noPath}>No direct reduction from {source} to {target} in the table.</div>
      </div>
    );
  }

  return (
    <div style={s.box}>
      <div style={s.arrow}>{fromLabel} → {toLabel}</div>
      <div style={s.name}>{step.name}</div>
      <div style={s.row}>
        <span style={s.label}>Theorem:</span>
        <span style={s.val}>{step.theorem}</span>
      </div>
      <div style={s.row}>
        <span style={s.label}>PA#:</span>
        <span style={s.val}>{step.paNumber}</span>
      </div>
      <div style={s.row}>
        <span style={s.label}>Status:</span>
        <span style={step.implemented ? s.impl : s.stub}>
          {step.implemented ? '✓ Implemented' : '○ Not yet implemented'}
        </span>
      </div>
    </div>
  );
}

const s: Record<string, React.CSSProperties> = {
  box: { padding: '14px', background: '#1e1e2e', borderRadius: '8px', border: '1px dashed #45475a', display: 'flex', flexDirection: 'column', gap: '6px' },
  arrow: { fontSize: '0.85rem', color: '#89dceb', fontFamily: 'monospace' },
  name: { fontSize: '0.95rem', color: '#cdd6f4', fontWeight: 600 },
  row: { display: 'flex', gap: '8px', fontSize: '0.85rem', alignItems: 'center' },
  label: { color: '#6c7086', minWidth: 70 },
  val: { color: '#cdd6f4' },
  impl: { color: '#a6e3a1', fontWeight: 600 },
  stub: { color: '#f38ba8', fontWeight: 600 },
  noPath: { color: '#fab387', fontSize: '0.9rem' },
};
