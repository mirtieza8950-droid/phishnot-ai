import { useEffect, useRef } from 'react';
import { useReveal } from '../hooks/useReveal';
export default function RiskGauge({ score, level }) {
  const canvasRef = useRef(null);
  const containerRef = useReveal();
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width, h = canvas.height;
    ctx.clearRect(0, 0, w, h);
    const cx = w/2, cy = h/2, r = 45;
    const sA = Math.PI*0.75, eA = Math.PI*2.25;
    const angle = sA + (eA - sA) * (score/100);
    ctx.beginPath(); ctx.arc(cx, cy, r, sA, eA); ctx.strokeStyle = '#1a1d27'; ctx.lineWidth = 12; ctx.stroke();
    ctx.beginPath(); ctx.arc(cx, cy, r, sA, angle); ctx.strokeStyle = score>=80?'#ef4444':score>=60?'#f59e0b':'#22c55e'; ctx.stroke();
    ctx.fillStyle = '#fff'; ctx.font = 'bold 28px Segoe UI'; ctx.textAlign = 'center'; ctx.textBaseline = 'middle'; ctx.fillText(score, cx, cy);
  }, [score]);
  return (
    <div ref={containerRef} className="glass-card p-6 flex flex-col items-center">
      <h4 className="text-sm uppercase tracking-wider opacity-60 mb-4">Risk Gauge</h4>
      <canvas ref={canvasRef} width={120} height={120} />
      <div className="mt-2 text-sm font-semibold" style={{ color: 'var(--accent)' }}>{level}</div>
    </div>
  );
}

