import { useReveal } from '../../hooks/useReveal';
import MetricGrid from '../../components/MetricGrid';

export default function StructureCard({ structure }) {
  const reveal = useReveal();
  const stats = [
    { label: 'Page Size',        value: `${(structure.page_size_bytes / 1024).toFixed(1)} KB` },
    { label: 'Forms',            value: structure.form_count },
    { label: 'Inputs',           value: structure.input_count },
    { label: 'Script Blocks',    value: structure.script_count },
    { label: 'Password Fields',  value: structure.password_fields,  warn: structure.password_fields > 0 },
    { label: 'Email Fields',     value: structure.email_fields },
    { label: 'Card Fields',      value: structure.card_fields,      warn: structure.card_fields > 0 },
    { label: 'OTP Fields',       value: structure.otp_fields,       warn: structure.otp_fields > 0 },
  ];
  const flags = [
    { label: 'Telegram Exfil',  active: structure.has_telegram_exfil },
    { label: 'Discord Exfil',   active: structure.has_discord_exfil },
    { label: 'Anti-Bot',        active: structure.has_antibot },
    { label: 'Obfuscation',     active: structure.has_obfuscation },
  ];
  return (
    <div ref={reveal} className="glass-card p-6 space-y-4">
      <h3 className="text-base font-bold text-white">Page Structure</h3>
      {structure.title && (
        <p className="text-xs text-gray-500">
          <span className="text-gray-600 mr-1">Title:</span>
          <span className="text-gray-300 font-mono">{structure.title}</span>
        </p>
      )}
      <MetricGrid stats={stats} cols={4} />
      <div className="flex flex-wrap gap-2">
        {flags.map(({ label, active }) => (
          <span key={label} className={`px-3 py-1 rounded-full text-xs font-semibold border ${
            active ? 'bg-red-900/40 text-red-300 border-red-700' : 'bg-gray-800/60 text-gray-600 border-gray-700 opacity-50'
          }`}>
            {active ? '✓' : '✗'} {label}
          </span>
        ))}
      </div>
      {structure.external_links?.length > 0 && (
        <div>
          <p className="text-xs text-gray-500 font-semibold mb-1">External Links</p>
          <div className="max-h-28 overflow-y-auto space-y-0.5">
            {structure.external_links.map((l, i) => (
              <p key={i} className="text-xs font-mono text-gray-500 truncate">{l}</p>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
