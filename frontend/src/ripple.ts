/** A soft amber ripple from the point of a tap or click on buttons, pills and alert rows: a small touch response that
 *  tells you the press registered. One listener for the whole page. It stays inside the pressed element, so it never moves the page. */
const TARGETS = '.btn, .pill, .alert-row, .src-link';

export function installRipple(root: Document = document): () => void {
  const onDown = (e: PointerEvent) => {
    const el = (e.target as Element | null)?.closest<HTMLElement>(TARGETS);
    if (!el || (el as HTMLButtonElement).disabled) return;
    const box = el.getBoundingClientRect();
    const size = Math.max(box.width, box.height) * 2.2;
    const dot = document.createElement('span');
    dot.className = 'ripple';
    dot.style.width = dot.style.height = `${size}px`;
    dot.style.left = `${e.clientX - box.left - size / 2}px`;
    dot.style.top = `${e.clientY - box.top - size / 2}px`;
    el.appendChild(dot);
    window.setTimeout(() => dot.remove(), 650);
  };
  root.addEventListener('pointerdown', onDown);
  return () => root.removeEventListener('pointerdown', onDown);
}
