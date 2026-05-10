import { useState } from 'react';
import DemoPA01 from '../components/demos/DemoPA01';
import DemoPA02 from '../components/demos/DemoPA02';
import DemoPA03 from '../components/demos/DemoPA03';
import DemoPA04 from '../components/demos/DemoPA04';
import DemoPA05 from '../components/demos/DemoPA05';
import DemoPA06 from '../components/demos/DemoPA06';
import DemoPA07 from '../components/demos/DemoPA07';
import DemoPA08 from '../components/demos/DemoPA08';
import DemoPA09 from '../components/demos/DemoPA09';
import DemoPA10 from '../components/demos/DemoPA10';
import DemoPA11 from '../components/demos/DemoPA11';
import DemoPA12 from '../components/demos/DemoPA12';
import DemoPA13 from '../components/demos/DemoPA13';
import DemoPA14 from '../components/demos/DemoPA14';
import DemoPA15 from '../components/demos/DemoPA15';
import DemoPA16 from '../components/demos/DemoPA16';
import DemoPA17 from '../components/demos/DemoPA17';
import DemoPA18 from '../components/demos/DemoPA18';
import DemoPA19 from '../components/demos/DemoPA19';
import DemoPA20 from '../components/demos/DemoPA20';

const DEMOS = [
  { id: 'pa01', label: 'PA#01 — OWF / PRG', component: DemoPA01, category: 'Primitives' },
  { id: 'pa02', label: 'PA#02 — GGM PRF', component: DemoPA02, category: 'Primitives' },
  { id: 'pa03', label: 'PA#03 — CPA Security', component: DemoPA03, category: 'Symmetric' },
  { id: 'pa04', label: 'PA#04 — Block Cipher Modes', component: DemoPA04, category: 'Symmetric' },
  { id: 'pa05', label: 'PA#05 — MAC Forgery', component: DemoPA05, category: 'Symmetric' },
  { id: 'pa06', label: 'PA#06 — CCA Security', component: DemoPA06, category: 'Symmetric' },
  { id: 'pa07', label: 'PA#07 — Hash Chain', component: DemoPA07, category: 'Hash' },
  { id: 'pa08', label: 'PA#08 — DLP Hash', component: DemoPA08, category: 'Hash' },
  { id: 'pa09', label: 'PA#09 — Birthday Attack', component: DemoPA09, category: 'Hash' },
  { id: 'pa10', label: 'PA#10 — HMAC & Length Ext.', component: DemoPA10, category: 'Hash' },
  { id: 'pa11', label: 'PA#11 — DH Key Exchange', component: DemoPA11, category: 'Public Key' },
  { id: 'pa12', label: 'PA#12 — RSA Determinism', component: DemoPA12, category: 'Public Key' },
  { id: 'pa13', label: 'PA#13 — Miller-Rabin', component: DemoPA13, category: 'Public Key' },
  { id: 'pa14', label: 'PA#14 — Håstad Broadcast', component: DemoPA14, category: 'Public Key' },
  { id: 'pa15', label: 'PA#15 — Digital Signatures', component: DemoPA15, category: 'Signatures' },
  { id: 'pa16', label: 'PA#16 — ElGamal Malleability', component: DemoPA16, category: 'Public Key' },
  { id: 'pa17', label: 'PA#17 — CCA-Secure PKC', component: DemoPA17, category: 'Public Key' },
  { id: 'pa18', label: 'PA#18 — Oblivious Transfer', component: DemoPA18, category: 'MPC' },
  { id: 'pa19', label: 'PA#19 — Secure Gates', component: DemoPA19, category: 'MPC' },
  { id: 'pa20', label: 'PA#20 — MPC Circuits', component: DemoPA20, category: 'MPC' },
];

const CATEGORIES = ['All', 'Primitives', 'Symmetric', 'Hash', 'Public Key', 'Signatures', 'MPC'];

export default function DemoGallery() {
  const [selected, setSelected] = useState('pa01');
  const [categoryFilter, setCategoryFilter] = useState('All');

  const filtered = categoryFilter === 'All' ? DEMOS : DEMOS.filter(d => d.category === categoryFilter);
  const activeDemo = DEMOS.find(d => d.id === selected);
  const ActiveComponent = activeDemo?.component;

  return (
    <div style={s.layout}>
      <div style={s.sidebar}>
        <div style={s.sideHead}>PA Demos</div>
        <div style={s.catRow}>
          {CATEGORIES.map(cat => (
            <button
              key={cat}
              style={{...s.catBtn, background: categoryFilter === cat ? '#89b4fa' : '#313244', color: categoryFilter === cat ? '#1e1e2e' : '#cdd6f4'}}
              onClick={() => { setCategoryFilter(cat); }}
            >
              {cat}
            </button>
          ))}
        </div>
        <div style={s.list}>
          {filtered.map(demo => (
            <button
              key={demo.id}
              style={{...s.listItem, background: selected === demo.id ? '#313244' : 'transparent', borderLeft: selected === demo.id ? '3px solid #89b4fa' : '3px solid transparent'}}
              onClick={() => setSelected(demo.id)}
            >
              <span style={s.listLabel}>{demo.label}</span>
              <span style={s.listCat}>{demo.category}</span>
            </button>
          ))}
        </div>
      </div>
      <div style={s.content}>
        {ActiveComponent ? <ActiveComponent /> : <div style={s.empty}>Select a demo from the sidebar</div>}
      </div>
    </div>
  );
}

const s: Record<string, React.CSSProperties> = {
  layout: { display: 'flex', height: '100%', minHeight: 0 },
  sidebar: { width: 220, background: '#181825', borderRight: '1px solid #313244', display: 'flex', flexDirection: 'column', flexShrink: 0, overflowY: 'auto' },
  sideHead: { padding: '12px 14px 8px', fontWeight: 700, fontSize: '0.9rem', color: '#89b4fa', borderBottom: '1px solid #313244' },
  catRow: { display: 'flex', flexWrap: 'wrap', gap: 4, padding: '8px 8px 4px' },
  catBtn: { padding: '2px 7px', border: 'none', borderRadius: 10, cursor: 'pointer', fontSize: '0.7rem', fontWeight: 600 },
  list: { flex: 1, overflowY: 'auto' },
  listItem: { width: '100%', textAlign: 'left', border: 'none', cursor: 'pointer', padding: '8px 12px 8px 10px', display: 'flex', flexDirection: 'column', gap: 2 },
  listLabel: { color: '#cdd6f4', fontSize: '0.78rem', fontWeight: 500 },
  listCat: { color: '#6c7086', fontSize: '0.68rem' },
  content: { flex: 1, overflowY: 'auto', background: '#1e1e2e' },
  empty: { color: '#6c7086', padding: 32, fontSize: '0.9rem' },
};
