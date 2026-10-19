import { useState, useEffect, useRef } from 'react';
import { lookupThreatIntel } from '../api/phishguard';

/**
 * Auto-fetches threat intel for a URL when it changes.
 * Skips if the URL is the same as the last fetch.
 */
export function useThreatIntel(url) {
  const [data,    setData]    = useState(null);
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState('');
  const lastUrl = useRef(null);

  useEffect(() => {
    if (!url || url === lastUrl.current) return;
    lastUrl.current = url;
    setLoading(true);
    setData(null);
    setError('');
    lookupThreatIntel(url)
      .then(setData)
      .catch(e => setError(e.message || 'Threat intel lookup failed'))
      .finally(() => setLoading(false));
  }, [url]);

  return { data, loading, error };
}
