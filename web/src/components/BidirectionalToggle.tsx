interface BidirectionalToggleProps {
  direction: 'forward' | 'backward';
  onToggle: () => void;
}

export default function BidirectionalToggle({ direction, onToggle }: BidirectionalToggleProps) {
  return (
    <div style={styles.wrapper}>
      <button style={styles.btn} onClick={onToggle}>
        {direction === 'forward' ? '→ Forward (A → B)' : '← Backward (B → A)'}
      </button>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  wrapper: {
    display: 'flex',
    justifyContent: 'center',
    padding: '8px 0',
  },
  btn: {
    padding: '6px 18px',
    borderRadius: '20px',
    border: '1px solid #89b4fa',
    background: 'transparent',
    color: '#89b4fa',
    cursor: 'pointer',
    fontSize: '0.85rem',
    fontWeight: 600,
    transition: 'all 0.15s',
  },
};
