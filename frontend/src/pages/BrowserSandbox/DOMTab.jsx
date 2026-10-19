import { useReveal } from '../../hooks/useReveal';
import MetricGrid from '../../components/MetricGrid';

export default function DOMTab({ dom = {} }) {
  const reveal = useReveal();
  const row1 = [
    { label: 'Forms',           value: dom.form_count           ?? 0 },
    { label: 'Password Fields', value: dom.password_field_count ?? 0, warn: (dom.password_field_count ?? 0) > 0 },
    { label: 'Scripts',         value: dom.script_count         ?? 0 },
    { label: 'Iframes',         value: dom.iframe_count         ?? 0, warn: (dom.iframe_count ?? 0) > 0 },
  ];
  const row2 = [
    { label: 'Mutations',    value: dom.mutation_count ?? 0, warn: (dom.mutation_count ?? 0) > 400 },
    { label: 'Meta Refresh', value: dom.meta_refresh   ?? 0, warn: (dom.meta_refresh   ?? 0) > 0  },
    { label: 'Storage Keys', value: dom.storage_keys?.length ?? 0 },
    { label: 'Timer Calls',  value: dom.timer_count    ?? 0 },
  ];
  return (
    <div ref={reveal} className="glass-card p-6 space-y-4">
      <h3 className="text-lg font-bold text-white">DOM Analysis</h3>
      <MetricGrid stats={row1} cols={4} />
      <MetricGrid stats={row2} cols={4} />
    </div>
  );
}
