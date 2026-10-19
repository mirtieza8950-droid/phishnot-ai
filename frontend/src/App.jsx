import { useState, useEffect, useRef } from 'react';
import { BrowserRouter, Routes, Route, Link, useLocation } from 'react-router-dom';
import { AnimatePresence, motion } from 'framer-motion';
import FloatingMarks from './components/FloatingMarks';
import { LampBackground, AmbientGlow, LampColorSync } from './components/ui/lamp';
import Welcome from './pages/Welcome';
import ScanEmail from './pages/ScanEmail';
import ScanUrl from './pages/ScanUrl';
import ScanImage from './pages/ScanImage';
import BatchLedger from './pages/BatchLedger';
import AnalystChat from './pages/AnalystChat';
import ScanHistory from './pages/ScanHistory';
import Analytics from './pages/Analytics';
import AdminPanel from './pages/AdminPanel';
import BrandProtection from './pages/BrandProtection';
import BrowserSandbox from './pages/BrowserSandbox';
import PhishingKit from './pages/PhishingKit';
import OAuthDetector from './pages/OAuthDetector';
import MobilePhishing from './pages/MobilePhishing';
import VishingAnalyzer from './pages/VishingAnalyzer';
import Login from './pages/Login';
import { AuthProvider, useAuth } from './context/AuthContext';

// ── Navigation structure ───────────────────────────────────────────────────────

const NAV_GROUPS = [
  {
    label: 'Scan',
    items: [
      { to: '/scan/email', label: 'Email',       icon: '📧', desc: 'Analyze suspicious messages'   },
      { to: '/scan/url',   label: 'URL',          icon: '🔗', desc: 'Check links before clicking'  },
      { to: '/scan/image', label: 'Screenshot',   icon: '📸', desc: 'OCR + vision AI analysis'     },
    ],
  },
  {
    label: 'Investigate',
    items: [
      { to: '/batch',   label: 'Batch',     icon: '📦', desc: 'Process hundreds at once'     },
      { to: '/sandbox', label: 'Sandbox',   icon: '🖥️', desc: 'Execute URLs in isolation'    },
      { to: '/vishing', label: 'Vishing',   icon: '🎙️', desc: 'Analyze call recordings'      },
      { to: '/mobile',  label: 'Mobile',    icon: '📱', desc: 'SMS & deep link threats'      },
    ],
  },
  {
    label: 'Intelligence',
    items: [
      { to: '/brand', label: 'Brand Guard', icon: '🛡️', desc: 'Lookalike domain monitoring'   },
      { to: '/kit',   label: 'Kit ID',      icon: '🔬', desc: 'Phishing kit fingerprinting'  },
      { to: '/oauth', label: 'OAuth',       icon: '🔐', desc: 'Token theft detection'        },
    ],
  },
  {
    label: 'Insights',
    items: [
      { to: '/history',   label: 'History',    icon: '📋', desc: 'All past scans'              },
      { to: '/analytics', label: 'Analytics',  icon: '📊', desc: 'Threat trends & charts'     },
      { to: '/chat',      label: 'AI Analyst', icon: '💬', desc: 'Ask security questions'      },
    ],
  },
];


// ── Hamburger icon ─────────────────────────────────────────────────────────────

function HamburgerIcon({ open }) {
  return (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
      {open
        ? <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
        : <path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h16" />}
    </svg>
  );
}

// ── Dropdown group button (desktop) ───────────────────────────────────────────

function DropdownGroup({ group, open, onEnter, onLeave }) {
  const { pathname } = useLocation();
  const active = group.items.some(i => pathname === i.to);

  return (
    <div
      className="relative"
      onMouseEnter={() => onEnter(group.label)}
      onMouseLeave={onLeave}
    >
      <button
        className={`flex items-center gap-1 px-3 py-1.5 rounded-lg font-semibold text-sm transition-all ${
          active || open
            ? 'bg-purple-600 text-white'
            : 'bg-gray-800/70 text-gray-300 hover:bg-gray-700 hover:text-white'
        }`}
      >
        {group.label}
        <svg className={`w-3 h-3 transition-transform ${open ? 'rotate-180' : ''}`}
          fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {open && (
        <div
          className="absolute top-full left-0 mt-2 w-52 rounded-2xl overflow-hidden z-50"
          style={{
            background: 'rgba(10, 12, 20, 0.92)',
            backdropFilter: 'blur(24px) saturate(160%)',
            WebkitBackdropFilter: 'blur(24px) saturate(160%)',
            border: '1px solid rgba(255,255,255,0.10)',
            boxShadow: '0 16px 48px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.06)',
          }}
          onMouseEnter={() => onEnter(group.label)}
          onMouseLeave={onLeave}
        >
          {group.items.map(item => (
            <Link
              key={item.to}
              to={item.to}
              onClick={() => onEnter(null)}
              className={`flex items-start gap-3 px-4 py-3 transition-colors ${
                pathname === item.to
                  ? 'bg-purple-600/30 text-white'
                  : 'hover:bg-white/5 text-gray-300'
              }`}
              style={{ textDecoration: 'none' }}
            >
              <span className="text-base mt-0.5 shrink-0">{item.icon}</span>
              <div>
                <p className="text-sm font-semibold text-white leading-tight">{item.label}</p>
                <p className="text-xs text-gray-500 mt-0.5">{item.desc}</p>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}

// ── NavBar ────────────────────────────────────────────────────────────────────

function NavBar() {
  const { pathname }      = useLocation();
  const { user, logout }  = useAuth();
  const [openGroup, setOpenGroup] = useState(null);
  const [mobileOpen, setMobileOpen] = useState(false);
  const closeTimer = useRef(null);

  useEffect(() => { setMobileOpen(false); setOpenGroup(null); }, [pathname]);

  const handleEnter = (label) => {
    clearTimeout(closeTimer.current);
    setOpenGroup(label);
  };
  const handleLeave = () => {
    closeTimer.current = setTimeout(() => setOpenGroup(null), 130);
  };

  if (!user) return null;

  return (
    <>
      {/* ── Desktop nav ────────────────────────────────────────────────────── */}
      <nav className="hidden md:flex items-center justify-between px-5 py-2.5 bg-black/30 border-b border-white/5 sticky top-0 z-30"
        style={{ backdropFilter: 'blur(20px) saturate(160%)', WebkitBackdropFilter: 'blur(20px) saturate(160%)' }}>

        {/* Logo */}
        <Link to="/" className="text-sm font-black tracking-tight shrink-0" style={{ color: 'var(--accent)', textDecoration: 'none' }}>
          PhishGuard
        </Link>

        {/* Groups */}
        <div className="flex items-center gap-1">
          {NAV_GROUPS.map(group => (
            <DropdownGroup
              key={group.label}
              group={group}
              open={openGroup === group.label}
              onEnter={handleEnter}
              onLeave={handleLeave}
            />
          ))}
          <Link to="/admin"
            className={`px-3 py-1.5 rounded-lg font-semibold text-sm transition-all ${
              pathname === '/admin'
                ? 'bg-purple-600 text-white'
                : 'bg-gray-800/70 text-gray-300 hover:bg-gray-700 hover:text-white'
            }`}
            style={{ textDecoration: 'none' }}>
            Admin
          </Link>
        </div>

        {/* Logout */}
        <button onClick={logout}
          className="text-xs text-gray-500 hover:text-gray-300 transition px-2 py-1 rounded shrink-0">
          Sign out
        </button>
      </nav>

      {/* ── Mobile header ───────────────────────────────────────────────────── */}
      <header className="md:hidden flex items-center justify-between px-4 py-3 sticky top-0 z-30 border-b border-white/5"
        style={{ background: 'rgba(8,10,15,0.85)', backdropFilter: 'blur(20px)', WebkitBackdropFilter: 'blur(20px)' }}>
        <Link to="/" className="text-sm font-black" style={{ color: 'var(--accent)', textDecoration: 'none' }}>
          PhishGuard
        </Link>
        <button
          onClick={() => setMobileOpen(v => !v)}
          className="p-2 rounded-lg bg-gray-800 text-gray-300 touch-manipulation"
          aria-label="Toggle menu"
        >
          <HamburgerIcon open={mobileOpen} />
        </button>
      </header>

      {/* ── Mobile full-screen menu ─────────────────────────────────────────── */}
      {mobileOpen && (
        <div className="md:hidden fixed inset-0 top-[53px] z-20 overflow-y-auto"
          style={{ background: 'rgba(6,8,14,0.97)', backdropFilter: 'blur(16px)' }}>
          <div className="p-4 space-y-5 pb-10">

            <Link to="/" onClick={() => setMobileOpen(false)}
              className={`flex items-center gap-2 px-4 py-3 rounded-xl text-sm font-semibold min-h-[48px] touch-manipulation ${
                pathname === '/' ? 'bg-purple-600 text-white' : 'bg-gray-800 text-gray-300'
              }`} style={{ textDecoration: 'none' }}>
              🏠 Home
            </Link>

            {NAV_GROUPS.map(group => (
              <div key={group.label}>
                <p className="text-xs uppercase tracking-widest text-gray-600 font-bold mb-2 px-1">{group.label}</p>
                <div className="grid grid-cols-2 gap-2">
                  {group.items.map(item => (
                    <Link key={item.to} to={item.to} onClick={() => setMobileOpen(false)}
                      className={`flex items-center gap-2 px-3 py-3 rounded-xl text-sm min-h-[52px] touch-manipulation ${
                        pathname === item.to ? 'bg-purple-600 text-white' : 'bg-gray-800 text-gray-300'
                      }`} style={{ textDecoration: 'none' }}>
                      <span className="text-base">{item.icon}</span>
                      <span className="font-semibold leading-tight">{item.label}</span>
                    </Link>
                  ))}
                </div>
              </div>
            ))}

            <div className="grid grid-cols-2 gap-2 pt-1">
              <Link to="/admin" onClick={() => setMobileOpen(false)}
                className={`flex items-center justify-center gap-2 px-3 py-3 rounded-xl text-sm font-semibold min-h-[48px] touch-manipulation ${
                  pathname === '/admin' ? 'bg-purple-600 text-white' : 'bg-gray-800 text-gray-300'
                }`} style={{ textDecoration: 'none' }}>
                ⚙️ Admin
              </Link>
              <button onClick={logout}
                className="flex items-center justify-center px-3 py-3 rounded-xl text-sm font-semibold bg-gray-800 text-gray-400 active:bg-red-900 min-h-[48px] touch-manipulation">
                Sign out
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

// ── Route guard ───────────────────────────────────────────────────────────────

function Protected({ children }) {
  const { user, loading } = useAuth();
  if (loading) return (
    <div className="flex items-center justify-center mt-24">
      <div className="animate-spin h-8 w-8 border-2 border-purple-500 border-t-transparent rounded-full" />
    </div>
  );
  if (!user) return <Login />;
  return children;
}

// ── App ───────────────────────────────────────────────────────────────────────

function AppRoutes() {
  const { pathname } = useLocation();
  const isHome = pathname === '/';
  const isChat = pathname === '/chat';

  return (
    <>
      {/* Full-page ambient gradient — cross-fades between RGB colors */}
      {!isChat && <AmbientGlow />}
      {/* Injects live CSS for glass-card RGB glow */}
      {!isChat && <LampColorSync />}
      {/* Lamp beams/line — all pages except homepage (handled in hero) and chat */}
      {!isHome && !isChat && <LampBackground />}
      <FloatingMarks />
      <div className="relative z-10 min-h-screen flex flex-col">
        <NavBar />
        <main className="flex-1 px-2 py-4 sm:px-4">
          <AnimatePresence mode="wait">
            <motion.div
              key={pathname}
              initial={{ opacity: 0, y: 18 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{    opacity: 0, y: -10 }}
              transition={{ duration: 0.22, ease: "easeInOut" }}>
              <Routes location={{ pathname }} key={pathname}>
                <Route path="/"           element={<Welcome />} />
                <Route path="/scan/email" element={<Protected><ScanEmail /></Protected>} />
                <Route path="/scan/url"   element={<Protected><ScanUrl /></Protected>} />
                <Route path="/scan/image" element={<Protected><ScanImage /></Protected>} />
                <Route path="/batch"      element={<Protected><BatchLedger /></Protected>} />
                <Route path="/chat"       element={<Protected><AnalystChat /></Protected>} />
                <Route path="/history"    element={<Protected><ScanHistory /></Protected>} />
                <Route path="/analytics"  element={<Protected><Analytics /></Protected>} />
                <Route path="/brand"      element={<Protected><BrandProtection /></Protected>} />
                <Route path="/kit"        element={<Protected><PhishingKit /></Protected>} />
                <Route path="/oauth"      element={<Protected><OAuthDetector /></Protected>} />
                <Route path="/mobile"     element={<Protected><MobilePhishing /></Protected>} />
                <Route path="/vishing"    element={<Protected><VishingAnalyzer /></Protected>} />
                <Route path="/sandbox"    element={<Protected><BrowserSandbox /></Protected>} />
                <Route path="/admin"      element={<Protected><AdminPanel /></Protected>} />
              </Routes>
            </motion.div>
          </AnimatePresence>
          </main>
        </div>
      </>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <AppRoutes />
      </BrowserRouter>
    </AuthProvider>
  );
}
