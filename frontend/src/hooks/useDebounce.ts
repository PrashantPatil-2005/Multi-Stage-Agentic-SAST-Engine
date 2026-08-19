import { useEffect, useState } from "react";

/** Debounce a value by `delay` ms. Returns the stale value until the delay
    elapses without further changes. */
export function useDebounce<T>(value: T, delay: number): T {
  const [debounced, setDebounced] = useState(value);

  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(timer);
  }, [value, delay]);

  return debounced;
}
