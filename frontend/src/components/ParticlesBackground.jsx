import { useEffect, useRef } from 'react';

const VERDICT_COLORS = {
  'verdict-phishing': '#ff3333',
  'verdict-suspicious': '#ff5544',
  'verdict-spam': '#ff9500',
  'verdict-ham': '#22c55e',
  'verdict-legitimate': '#22c55e',
};

function getColor() {
  for (const [cls, color] of Object.entries(VERDICT_COLORS)) {
    if (document.body.classList.contains(cls)) return color;
  }
  return '#6c63ff';
}

function buildConfig(color) {
  return {
    particles: {
      number: { value: 75, density: { enable: true, value_area: 900 } },
      color: { value: color },
      shape: { type: 'circle' },
      opacity: { value: 0.5, random: true },
      size: { value: 3, random: true },
      line_linked: { enable: true, distance: 140, color, opacity: 0.35, width: 1 },
      move: { enable: true, speed: 1.4, random: true, out_mode: 'out' },
    },
    interactivity: {
      detect_on: 'canvas',
      events: { onhover: { enable: true, mode: 'grab' }, onclick: { enable: false } },
      modes: { grab: { distance: 120, line_linked: { opacity: 0.7 } } },
    },
    retina_detect: true,
  };
}

function destroyParticles() {
  if (window.pJSDom && window.pJSDom.length > 0) {
    try { window.pJSDom[0].pJS.fn.vendors.destroypJS(); } catch (_) {}
    window.pJSDom = [];
  }
}

function initParticles(color) {
  if (window.particlesJS) {
    destroyParticles();
    window.particlesJS('particles-js', buildConfig(color));
  }
}

export default function ParticlesBackground() {
  const colorRef = useRef(null);

  useEffect(() => {
    const init = () => {
      const color = getColor();
      colorRef.current = color;
      initParticles(color);
    };

    // Wait for particlesJS to load if not yet available
    if (window.particlesJS) {
      init();
    } else {
      const timer = setInterval(() => {
        if (window.particlesJS) { clearInterval(timer); init(); }
      }, 200);
    }

    const observer = new MutationObserver(() => {
      const color = getColor();
      if (color !== colorRef.current) {
        colorRef.current = color;
        initParticles(color);
      }
    });
    observer.observe(document.body, { attributes: true, attributeFilter: ['class'] });
    return () => { observer.disconnect(); destroyParticles(); };
  }, []);

  return (
    <div id="particles-js" className="fixed inset-0 z-0 pointer-events-none"
      style={{ backgroundColor: '#080a0f' }} />
  );
}
