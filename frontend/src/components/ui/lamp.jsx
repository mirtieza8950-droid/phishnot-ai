"use client";
import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { cn } from "@/lib/utils";

// ── Helpers ───────────────────────────────────────────────────────────────────
function hexToRgb(hex) {
  const m = hex.match(/^#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i);
  return m ? [parseInt(m[1],16), parseInt(m[2],16), parseInt(m[3],16)] : [148,163,174];
}

// ── Color config ──────────────────────────────────────────────────────────────
const VERDICT_COLORS = {
  "verdict-phishing":   "#ef4444",
  "verdict-suspicious": "#ef4444",
  "verdict-spam":       "#f97316",
  "verdict-ham":        "#22c55e",
  "verdict-legitimate": "#22c55e",
};
const CYCLE    = ["#ffffff", "#22c55e", "#ef4444", "#f97316"];
const CYCLE_MS = 2600;

// ── Module-level singleton — ONE timer, ONE color, all hooks in sync ──────────
const _subs     = new Set();
let   _color    = CYCLE[0];
let   _timer    = null;
let   _idx      = 0;

function _emit(c)    { _color = c; _subs.forEach(fn => fn(c)); }
function _stop()     { if (_timer) { clearInterval(_timer); _timer = null; } }
function _start()    {
  if (_timer) return;
  _timer = setInterval(() => { _idx = (_idx + 1) % CYCLE.length; _emit(CYCLE[_idx]); }, CYCLE_MS);
}

// One global MutationObserver to handle verdict detection for ALL components
let _obs = null;
function _ensureObs() {
  if (_obs) return;
  function check() {
    for (const [cls, col] of Object.entries(VERDICT_COLORS)) {
      if (document.body.classList.contains(cls)) { _stop(); _emit(col); return; }
    }
    _start();
  }
  check();
  _obs = new MutationObserver(check);
  _obs.observe(document.body, { attributes: true, attributeFilter: ["class"] });
}

// ── Hook — returns shared color, subscribes to module state ──────────────────
export function useLampColor() {
  const [color, setColor] = useState(_color);
  useEffect(() => {
    _subs.add(setColor);
    setColor(_color);            // sync immediately if we joined mid-cycle
    _ensureObs();
    return () => _subs.delete(setColor);
  }, []);
  return color;
}

// ── AmbientGlow — full-page radial gradient, cross-fades on color change ──────
export function AmbientGlow() {
  const color = useLampColor();
  const [r, g, b] = hexToRgb(color);
  return (
    <AnimatePresence mode="sync">
      <motion.div
        key={color}
        className="pointer-events-none fixed inset-0"
        style={{
          zIndex: 1,
          background: `radial-gradient(ellipse 120% 60% at 50% 0%,
            rgba(${r},${g},${b},0.22) 0%,
            rgba(${r},${g},${b},0.10) 35%,
            rgba(${r},${g},${b},0.03) 60%,
            transparent 75%)`,
        }}
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        transition={{ duration: 1.4, ease: "easeInOut" }}
      />
    </AnimatePresence>
  );
}

// ── LampColorSync — live <style> tag for glass-card + feature-card RGB glow ──
export function LampColorSync() {
  const color = useLampColor();
  useEffect(() => {
    const [r, g, b] = hexToRgb(color);
    let el = document.getElementById('_lamp_glass_css');
    if (!el) { el = document.createElement('style'); el.id = '_lamp_glass_css'; document.head.appendChild(el); }
    el.textContent = `
      .glass-card {
        box-shadow: 0 4px 28px rgba(0,0,0,0.35), inset 0 1px 0 rgba(255,255,255,0.08),
          0 0 80px 0 rgba(${r},${g},${b},0.15), inset 0 0 30px 0 rgba(${r},${g},${b},0.08) !important;
        border-color: rgba(${r},${g},${b},0.18) !important;
      }
    `;
  }, [color]);
  return null;
}

// ── LampVisual — pure visual, zero solid background divs ─────────────────────
// Line sits at the very top edge of the container. Beams fan downward from
// top-center. Container CSS mask fades everything at the bottom.
// No scaleY transform, no inset:auto, no cover divs — nothing creates a block.
function LampVisual({ color }) {
  const [r, g, b] = hexToRgb(color);
  return (
    <div
      className="w-full h-full relative"
      style={{
        maskImage: "linear-gradient(to bottom, black 0%, black 40%, transparent 85%)",
        WebkitMaskImage: "linear-gradient(to bottom, black 0%, black 40%, transparent 85%)",
      }}>

      {/* Left conic beam — origin at top-center of its element = page top-center */}
      <AnimatePresence mode="sync">
        <motion.div key={`lb-${color}`}
          initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
          transition={{ duration: 1.2 }}
          style={{
            position: "absolute", top: 0, right: "50%",
            width: "min(30rem, 52vw)", height: "55%",
            backgroundImage: `conic-gradient(from 70deg at center top,
              rgba(${r},${g},${b},0.65) 0deg,
              transparent 55deg, transparent 360deg)`,
          }}
        />
      </AnimatePresence>

      {/* Right conic beam */}
      <AnimatePresence mode="sync">
        <motion.div key={`rb-${color}`}
          initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
          transition={{ duration: 1.2 }}
          style={{
            position: "absolute", top: 0, left: "50%",
            width: "min(30rem, 52vw)", height: "55%",
            backgroundImage: `conic-gradient(from 290deg at center top,
              transparent 0deg, transparent 305deg,
              rgba(${r},${g},${b},0.65) 360deg)`,
          }}
        />
      </AnimatePresence>

      {/* Outer glow blob — centered horizontally, slightly above top edge */}
      <motion.div
        animate={{ background: color }} transition={{ duration: 1.5 }}
        style={{
          position: "absolute", top: "-40px", left: "50%",
          transform: "translateX(-50%)",
          width: "min(28rem, 80vw)", height: "90px",
          borderRadius: "50%", opacity: 0.45, filter: "blur(32px)", background: color,
        }}
      />

      {/* Inner tight glow */}
      <motion.div
        animate={{ background: color }} transition={{ duration: 1.5 }}
        style={{
          position: "absolute", top: "-24px", left: "50%",
          transform: "translateX(-50%)",
          width: "min(14rem, 50vw)", height: "60px",
          borderRadius: "50%", opacity: 0.7, filter: "blur(16px)", background: color,
        }}
      />

      {/* The glowing line — sits at the very top */}
      <motion.div
        animate={{
          background: color,
          boxShadow: `0 0 22px 6px rgba(${r},${g},${b},0.75),
                      0 0 50px 14px rgba(${r},${g},${b},0.35)`,
        }}
        transition={{ duration: 1.5 }}
        style={{
          position: "absolute", top: 0, left: "50%",
          transform: "translateX(-50%)",
          width: "min(30rem, 90vw)", height: "2px", background: color,
        }}
      />
    </div>
  );
}

// ── LampBackground — fixed, all pages except homepage + chat ─────────────────
export function LampBackground() {
  const color = useLampColor();
  return (
    <div className="pointer-events-none fixed inset-x-0 top-0 z-[2]"
         style={{ height: "55vh" }}>
      <LampVisual color={color} />
    </div>
  );
}

// ── HeroLampOverlay — absolute inside hero, above heading ────────────────────
export function HeroLampOverlay() {
  const color = useLampColor();
  return (
    <div className="absolute inset-x-0 top-0 pointer-events-none"
         style={{ height: "240px" }}>
      <LampVisual color={color} />
    </div>
  );
}

// ── LampContainer / DynamicLampContainer — kept for compatibility ─────────────
export const LampContainer = ({ children, className, color = "#94a3b8" }) => (
  <div className={cn("relative flex min-h-[78vh] flex-col items-center justify-center overflow-hidden w-full z-0", className)}>
    <div className="absolute inset-x-0 top-0" style={{ height: "260px" }}>
      <LampVisual color={color} />
    </div>
    <div className="relative z-50 flex flex-col items-center px-5 w-full">
      {children}
    </div>
  </div>
);

export function DynamicLampContainer({ children, className }) {
  const color = useLampColor();
  return <LampContainer color={color} className={className}>{children}</LampContainer>;
}
