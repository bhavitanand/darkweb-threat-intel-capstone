import { useEffect, useState } from 'react';

const KEY = 'darklens.intro-seen';
const EYE = 'M18 60 C 58 12, 142 12, 182 60 C 142 108, 58 108, 18 60 Z';

function seen(): boolean {
  try {
    return window.sessionStorage.getItem(KEY) === '1';
  } catch {
    return false;
  }
}

function markSeen() {
  try {
    window.sessionStorage.setItem(KEY, '1');
  } catch {
    /* storage blocked: the intro may play again, which is harmless */
  }
}

/** The ink eye that opens, looks around and blinks before the page appears. Once per browser tab session, about two
 *  seconds, and skippable with Esc or the Skip button. */
export default function Loader() {
  const [phase, setPhase] = useState<'show' | 'leaving' | 'gone'>(() => (seen() ? 'gone' : 'show'));

  useEffect(() => {
    if (phase !== 'show') return;
    markSeen();
    const t = window.setTimeout(() => setPhase('leaving'), 2050);
    return () => window.clearTimeout(t);
  }, [phase]);

  useEffect(() => {
    if (phase !== 'leaving') return;
    const t = window.setTimeout(() => setPhase('gone'), 520);
    return () => window.clearTimeout(t);
  }, [phase]);

  useEffect(() => {
    if (phase === 'gone') return;
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setPhase('leaving');
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [phase]);

  if (phase === 'gone') return null;
  return (
    <div className={`loader${phase === 'leaving' ? ' done' : ''}`} role="status" aria-label="DarkLens is opening">
      <div className="loader-inner">
        <svg viewBox="0 0 200 120" aria-hidden="true">
          <defs>
            <clipPath id="eye-clip">
              <path d={EYE} />
            </clipPath>
          </defs>
          <g className="eye-open">
            <g clipPath="url(#eye-clip)">
              <rect x="0" y="0" width="200" height="120" fill="#fffdf8" />
              <g className="eye-look">
                <circle className="eye-iris" cx="100" cy="60" r="27" />
                <circle className="eye-pupil" cx="100" cy="60" r="11" />
                <circle className="eye-glint" cx="108" cy="52" r="4.5" />
              </g>
            </g>
            <path className="eye-lid eye-draw" d={EYE} />
          </g>
          <g className="eye-draw" style={{ animationDelay: '0.25s' }}>
            <line className="eye-lash" x1="62" y1="25" x2="55" y2="13" />
            <line className="eye-lash" x1="100" y1="18" x2="100" y2="5" />
            <line className="eye-lash" x1="138" y1="25" x2="145" y2="13" />
          </g>
        </svg>
        <div className="loader-word">DarkLens</div>
        <div className="loader-sub">Reading the dark web for you</div>
      </div>
      <button type="button" className="btn btn-ghost btn-sm loader-skip" onClick={() => setPhase('leaving')}>Skip</button>
    </div>
  );
}
