import DmarcPanel    from './BrandProtection/DmarcPanel';
import LookalikePanel from './BrandProtection/LookalikePanel';
import CTPanel        from './BrandProtection/CTPanel';

export default function BrandProtection() {
  return (
    <div className="max-w-6xl mx-auto p-6 space-y-6">
      <div>
        <h2 className="text-2xl font-bold" style={{ color: 'var(--accent)' }}>Brand Protection Suite</h2>
        <p className="text-gray-500 text-sm mt-1">
          Monitor email authentication posture, detect lookalike domains, and track certificates issued to brand impersonators.
        </p>
      </div>
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <DmarcPanel />
        <LookalikePanel />
      </div>
      <CTPanel />
    </div>
  );
}
