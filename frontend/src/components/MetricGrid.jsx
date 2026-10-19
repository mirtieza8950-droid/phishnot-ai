const SM_COLS = { 2: 'sm:grid-cols-2', 3: 'sm:grid-cols-3', 4: 'sm:grid-cols-4' };

export default function MetricGrid({ stats, cols = 4 }) {
  const smClass = SM_COLS[cols] ?? 'sm:grid-cols-4';
  return (
    <div className={`grid grid-cols-2 ${smClass} gap-4 text-center`}>
      {stats.map(({ label, value, warn, color }) => (
        <div key={label} className={`rounded-lg p-4 ${warn ? 'bg-red-950/20' : 'bg-black/20'}`}>
          <p className={`text-2xl font-black ${color ?? (warn ? 'text-red-400' : 'text-white')}`}>
            {value ?? 0}
          </p>
          <p className="text-xs text-gray-500 mt-1">{label}</p>
        </div>
      ))}
    </div>
  );
}
