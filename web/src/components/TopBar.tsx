interface TopBarProps {
  foundation: 'AES' | 'DLP';
  onFoundationChange: (f: 'AES' | 'DLP') => void;
}

export default function TopBar({ foundation, onFoundationChange }: TopBarProps) {
  return (
    <header style={styles.header}>
      <h1 style={styles.title}>CS8.401 Minicrypt Clique Explorer</h1>
      <div style={styles.toggle}>
        <button
          style={{ ...styles.btn, ...(foundation === 'AES' ? styles.active : {}) }}
          onClick={() => onFoundationChange('AES')}
        >
          AES-128 (PRP)
        </button>
        <button
          style={{ ...styles.btn, ...(foundation === 'DLP' ? styles.active : {}) }}
          onClick={() => onFoundationChange('DLP')}
        >
          DLP (g^x mod p)
        </button>
      </div>
    </header>
  );
}

const styles: Record<string, React.CSSProperties> = {
  header: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '12px 24px',
    background: '#1e1e2e',
    borderBottom: '1px solid #313244',
  },
  title: {
    margin: 0,
    fontSize: '1.1rem',
    fontWeight: 600,
    color: '#cdd6f4',
  },
  toggle: {
    display: 'flex',
    gap: '8px',
  },
  btn: {
    padding: '6px 14px',
    border: '1px solid #45475a',
    borderRadius: '6px',
    background: '#313244',
    color: '#cdd6f4',
    cursor: 'pointer',
    fontSize: '0.85rem',
  },
  active: {
    background: '#89b4fa',
    color: '#1e1e2e',
    borderColor: '#89b4fa',
    fontWeight: 600,
  },
};
