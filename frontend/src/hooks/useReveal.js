import { useCallback } from 'react';

// Callback-ref: React calls this with the DOM node the moment it mounts,
// even for conditionally-rendered elements. Fixes the opacity-0-forever bug
// that occurred when useEffect fired before the element existed in the DOM.
export function useReveal() {
  return useCallback((node) => {
    if (node) requestAnimationFrame(() => node.classList.add('reveal'));
  }, []);
}
