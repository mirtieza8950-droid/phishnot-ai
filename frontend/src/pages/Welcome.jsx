import { Component } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useReveal } from '../hooks/useReveal';
import FeaturesCards, { ADVANCED_FEATURES } from '@/components/feature-shader-cards';
import { HeroLampOverlay } from '@/components/ui/lamp';

// LiquidButton has a broken internal Slot — replaced with a glass-pill styled button
function GlassCTA({ children, onClick, className = '' }) {
  return (
    <button
      onClick={onClick}
      className={`px-8 py-3.5 font-bold rounded-full text-sm transition-all
        backdrop-blur-md border border-white/20
        bg-white/10 hover:bg-white/20 active:scale-95
        shadow-[0_0_20px_rgba(108,99,255,0.3)] hover:shadow-[0_0_30px_rgba(108,99,255,0.5)]
        text-white ${className}`}>
      {children}
    </button>
  );
}

class ShaderBoundary extends Component {
  constructor(props) { super(props); this.state = { error: false }; }
  static getDerivedStateFromError() { return { error: true }; }
  render() {
    if (this.state.error) return this.props.fallback ?? null;
    return this.props.children;
  }
}

// ── System status ─────────────────────────────────────────────────────────────

const STATUS_ITEMS = [
  { label: 'Backend',      color: '#22c55e', status: 'Online'   },
  { label: 'ML Models',    color: '#22c55e', status: 'Loaded'   },
  { label: 'AI Analyst',   color: '#22c55e', status: 'Active'   },
  { label: 'Vision Model', color: '#f59e0b', status: 'Optional' },
];

function SystemStatus() {
  const ref = useReveal();
  return (
    <div ref={ref} className="glass-card px-6 py-4">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
        <p className="text-xs uppercase tracking-widest text-gray-600 font-bold shrink-0">System</p>
        {STATUS_ITEMS.map(({ label, color, status }) => (
          <div key={label} className="flex items-center gap-1.5 text-xs">
            <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: color }} />
            <span className="text-gray-500">{label}</span>
            <span className="font-semibold" style={{ color }}>{status}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function Welcome() {
  const navigate = useNavigate();
  return (
    <>
      <div className="relative" style={{ zIndex: 20 }}>

        {/* ── Hero ─────────────────────────────────────────────────────────── */}
        <section className="relative flex flex-col items-center justify-center text-center
                            px-6 pt-28 pb-32 min-h-[78vh] overflow-hidden">
          {/* Lamp overlay — absolute, sits above content without moving it */}
          <HeroLampOverlay />

          {/* Content — z-index keeps it above the lamp overlay */}
          <div className="relative z-10 flex flex-col items-center">
            <p className="text-xs uppercase tracking-widest font-bold mb-5"
               style={{ color: 'var(--accent)', opacity: 0.85 }}>
              Your AI Security Co-Pilot
            </p>

            <h1 className="font-black text-white leading-tight tracking-tight mb-6
                           text-[clamp(2.5rem,8vw,6.5rem)]">
              Is that safe<br className="hidden sm:block" /> to open?
            </h1>

            <p className="text-base sm:text-xl text-white/55 max-w-xl mx-auto leading-relaxed mb-10">
              PhishGuard analyzes suspicious emails, links, calls, and messages
              for scams and phishing attacks — and explains what it found in
              plain English.
            </p>

            <div className="flex flex-col sm:flex-row gap-3 justify-center items-center">
              <GlassCTA onClick={() => navigate('/scan/email')}>
                Scan Something Now
              </GlassCTA>

              <Link to="/chat"
                className="px-8 py-3 font-semibold rounded-full text-sm transition-all
                           border border-white/10 bg-white/5 hover:bg-white/10
                           text-white/75 hover:text-white flex items-center justify-center"
                style={{ textDecoration: 'none' }}>
                Ask the AI Analyst
              </Link>
            </div>
          </div>
        </section>

        {/* ── Features ─────────────────────────────────────────────────────── */}
        <div className="bg-transparent backdrop-blur-sm">
          <p className="text-xs uppercase tracking-widest text-gray-600 font-bold text-center pt-10">
            What can PhishGuard check for you?
          </p>
          <ShaderBoundary fallback={
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 max-w-7xl mx-auto px-4 py-16">
              {['Suspicious Email?','Unfamiliar Link?','Suspicious Call?','Strange SMS?','Got a Screenshot?','Ask the AI'].map(t => (
                <div key={t} className="glass-card p-6 h-48 flex items-end"><p className="font-bold text-white">{t}</p></div>
              ))}
            </div>
          }>
            <FeaturesCards />
          </ShaderBoundary>
        </div>

        {/* ── Advanced tools ───────────────────────────────────────────────── */}
        <div className="bg-transparent backdrop-blur-sm">
          <p className="text-xs uppercase tracking-widest text-gray-600 font-bold text-center pt-10">
            Advanced tools for security teams
          </p>
          <ShaderBoundary fallback={null}>
            <FeaturesCards features={ADVANCED_FEATURES} />
          </ShaderBoundary>
        </div>

        {/* ── Status ───────────────────────────────────────────────────────── */}
        <div className="bg-transparent max-w-5xl mx-auto px-4 pb-12">
          <SystemStatus />
        </div>

      </div>
    </>
  );
}
