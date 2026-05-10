import { useState } from 'react';
import TopBar from './components/TopBar';
import CliqueExplorer from './pages/CliqueExplorer';
import DemoGallery from './pages/DemoGallery';

type Tab = 'clique' | 'demos';

export default function App() {
  const [tab, setTab] = useState<Tab>('clique');
  const [foundation, setFoundation] = useState<'AES' | 'DLP'>('DLP');

  return (
    <div style={styles.app}>
      <TopBar foundation={foundation} onFoundationChange={setFoundation} />

      <div style={styles.tabBar}>
        <button
          style={{...styles.tabBtn, ...(tab === 'clique' ? styles.tabActive : {})}}
          onClick={() => setTab('clique')}
        >
          Clique Explorer
        </button>
        <button
          style={{...styles.tabBtn, ...(tab === 'demos' ? styles.tabActive : {})}}
          onClick={() => setTab('demos')}
        >
          PA Demos (1–20)
        </button>
      </div>

      {tab === 'clique' && <CliqueExplorer foundation={foundation} />}
      {tab === 'demos' && (
        <div style={styles.demoWrapper}>
          <DemoGallery />
        </div>
      )}
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  app: {
    minHeight: '100vh',
    background: '#1e1e2e',
    color: '#cdd6f4',
    display: 'flex',
    flexDirection: 'column',
    fontFamily: "'Inter', 'Segoe UI', sans-serif",
  },
  tabBar: {
    display: 'flex',
    gap: 0,
    borderBottom: '1px solid #313244',
    background: '#181825',
    padding: '0 16px',
  },
  tabBtn: {
    padding: '10px 20px',
    background: 'transparent',
    border: 'none',
    borderBottom: '2px solid transparent',
    color: '#6c7086',
    cursor: 'pointer',
    fontWeight: 600,
    fontSize: '0.9rem',
  },
  tabActive: {
    color: '#89b4fa',
    borderBottom: '2px solid #89b4fa',
  },
  demoWrapper: {
    flex: 1,
    display: 'flex',
    flexDirection: 'column',
    minHeight: 0,
    overflow: 'hidden',
  },
};
