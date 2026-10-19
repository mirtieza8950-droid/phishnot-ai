import { useReveal } from '../../hooks/useReveal';

export default function ScreenshotTab({ screenshot }) {
  const reveal = useReveal();
  return (
    <div ref={reveal} className="glass-card p-6 space-y-4">
      <h3 className="text-lg font-bold text-white">Page Screenshot</h3>
      {screenshot ? (
        <img
          src={`data:image/jpeg;base64,${screenshot}`}
          alt="Page screenshot"
          className="w-full rounded-lg border border-gray-700"
        />
      ) : (
        <p className="text-gray-500 text-sm">No screenshot captured.</p>
      )}
    </div>
  );
}
