import { useState } from 'react';
import BuildPanel from '../components/BuildPanel';
import ReducePanel from '../components/ReducePanel';
import BidirectionalToggle from '../components/BidirectionalToggle';
import BottomPanel from '../components/BottomPanel';
import { type Primitive, PRIMITIVES } from '../data/reductions';

interface CliqueExplorerProps {
  foundation: 'AES' | 'DLP';
}

export default function CliqueExplorer({ foundation }: CliqueExplorerProps) {
  const [sourcePrimitive, setSourcePrimitive] = useState<Primitive>('OWF');
  const [targetPrimitive, setTargetPrimitive] = useState<Primitive>('PRG');
  const [inputSeed, setInputSeed] = useState('');
  const [inputMessage, setInputMessage] = useState('');
  const [direction, setDirection] = useState<'forward' | 'backward'>('forward');

  const handleSourceChange = (p: Primitive) => {
    setSourcePrimitive(p);
    if (targetPrimitive === p) {
      const others = PRIMITIVES.filter(x => x !== p);
      setTargetPrimitive(others[0]);
    }
  };

  return (
    <div style={s.wrapper}>
      <div style={s.main}>
        <BidirectionalToggle
          direction={direction}
          onToggle={() => setDirection(d => d === 'forward' ? 'backward' : 'forward')}
        />
        <div style={s.columns}>
          <BuildPanel
            selected={sourcePrimitive}
            seed={inputSeed}
            onSelectChange={handleSourceChange}
            onSeedChange={setInputSeed}
          />
          <ReducePanel
            source={sourcePrimitive}
            target={targetPrimitive}
            message={inputMessage}
            direction={direction}
            onTargetChange={setTargetPrimitive}
            onMessageChange={setInputMessage}
          />
        </div>
      </div>
      <BottomPanel
        foundation={foundation}
        source={sourcePrimitive}
        target={targetPrimitive}
      />
    </div>
  );
}

const s: Record<string, React.CSSProperties> = {
  wrapper: { flex: 1, display: 'flex', flexDirection: 'column' },
  main: { flex: 1, padding: '20px 24px', display: 'flex', flexDirection: 'column', gap: '12px' },
  columns: { display: 'flex', gap: '16px', flex: 1 },
};
