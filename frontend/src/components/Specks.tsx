import { useEffect, useMemo, useRef } from 'react';

interface Speck { left: number; top: number; size: number; amber: boolean; dur: number; delay: number }

/** A few slowly drifting paper specks behind the landing hero. They lean away from the cursor, like dust when you wave
 *  a hand over a page. Decorative only: hidden from screen readers and still for people who turn off motion. */
export default function Specks({ count = 26 }: { count?: number }) {
  const box = useRef<HTMLDivElement>(null);
  const specks = useMemo<Speck[]>(() => {
    let seed = 7;
    const rand = () => ((seed = (seed * 16807) % 2147483647) / 2147483647);
    return Array.from({ length: count }, (_, i) => ({
      left: rand() * 100, top: rand() * 100, size: 3 + rand() * 6, amber: i % 5 === 0, dur: 9 + rand() * 10, delay: -rand() * 12,
    }));
  }, [count]);

  useEffect(() => {
    const el = box.current;
    if (!el || window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) return;
    const dots = Array.from(el.children) as HTMLElement[];
    let frame = 0;
    let mx = -9999, my = -9999;
    const paint = () => {
      frame = 0;
      for (const d of dots) {
        const r = d.getBoundingClientRect();
        const dx = r.left + r.width / 2 - mx, dy = r.top + r.height / 2 - my;
        const dist = Math.hypot(dx, dy);
        const push = dist < 140 ? (140 - dist) / 140 : 0;
        d.style.transform = push ? `translate(${(dx / (dist || 1)) * push * 34}px, ${(dy / (dist || 1)) * push * 34}px)` : '';
      }
    };
    const onMove = (e: PointerEvent) => {
      mx = e.clientX; my = e.clientY;
      if (!frame) frame = window.requestAnimationFrame(paint);
    };
    window.addEventListener('pointermove', onMove, { passive: true });
    return () => {
      window.removeEventListener('pointermove', onMove);
      if (frame) window.cancelAnimationFrame(frame);
    };
  }, []);

  return (
    <div className="lp-specks" ref={box} aria-hidden="true">
      {specks.map((s, i) => (
        <span key={i} className={s.amber ? 'a' : undefined}
          style={{ left: `${s.left}%`, top: `${s.top}%`, width: s.size, height: s.size,
            animation: `drift ${s.dur}s ease-in-out ${s.delay}s infinite` }} />
      ))}
    </div>
  );
}
