// Staggered entrance transitions, animated counters, desktop 3D card tilt, and drawer/swipe controls

import { animate, stagger } from 'motion';

let lastAnimatedRouteKey = '';
let tiltDelegatedBound = false;
let escapeKeyBound = false;
let activeTiltCard: HTMLElement | null = null;
const countupRafs = new WeakMap<HTMLElement, number>();

export function prefersReducedMotion(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
  );
}

function animateCountupElement(el: HTMLElement, target: number): void {
  const prevRaf = countupRafs.get(el);
  if (prevRaf !== undefined) {
    window.cancelAnimationFrame(prevRaf);
  }
  if (prefersReducedMotion() || !Number.isFinite(target) || target === 0) {
    el.textContent = String(target);
    return;
  }
  const duration = 520;
  const startTime = performance.now();
  const startVal = 0;

  const step = (now: number) => {
    const t = Math.min(1, (now - startTime) / duration);
    // Ease out cubic
    const eased = 1 - Math.pow(1 - t, 3);
    const cur = Math.round(startVal + (target - startVal) * eased);
    el.textContent = String(cur);
    if (t < 1) {
      const id = window.requestAnimationFrame(step);
      countupRafs.set(el, id);
    } else {
      el.textContent = String(target);
      countupRafs.delete(el);
    }
  };
  const id = window.requestAnimationFrame(step);
  countupRafs.set(el, id);
}

export function runMotionEnhancements(routeKey: string): void {
  const routeChanged = routeKey !== lastAnimatedRouteKey;
  if (!routeChanged) return;
  lastAnimatedRouteKey = routeKey;

  const reduced = prefersReducedMotion();

  if (!reduced) {
    const cards = Array.from(document.querySelectorAll<HTMLElement>('.card-anim'));
    if (cards.length > 0) {
      try {
        animate(
          cards.slice(0, 14),
          { opacity: [0.35, 1], y: [10, 0] },
          { duration: 0.28, delay: stagger(0.035), ease: [0.16, 1, 0.3, 1] }
        );
      } catch {
        // Fallback safely if Web Animations API is unavailable
      }
    }
  }

  document.querySelectorAll<HTMLElement>('[data-countup]').forEach((el) => {
    const raw = Number(el.dataset.countup);
    if (Number.isFinite(raw)) {
      animateCountupElement(el, raw);
    }
  });
}

export function bindTiltCards(): void {
  if (tiltDelegatedBound || typeof document === 'undefined') return;
  tiltDelegatedBound = true;

  const canTilt =
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(hover: hover) and (pointer: fine)').matches;
  if (!canTilt) return;

  document.addEventListener(
    'pointermove',
    (e: PointerEvent) => {
      if (prefersReducedMotion()) return;
      const target = e.target as HTMLElement | null;
      const card = target ? (target.closest('.tilt-card') as HTMLElement | null) : null;
      if (activeTiltCard && activeTiltCard !== card) {
        activeTiltCard.style.removeProperty('--rx');
        activeTiltCard.style.removeProperty('--ry');
        activeTiltCard = null;
      }
      if (!card) return;
      activeTiltCard = card;
      const rect = card.getBoundingClientRect();
      if (rect.width <= 0 || rect.height <= 0) return;
      const nx = ((e.clientX - rect.left) / rect.width - 0.5) * 2;
      const ny = ((e.clientY - rect.top) / rect.height - 0.5) * 2;
      const maxDeg = 3.2;
      card.style.setProperty('--rx', `${(-ny * maxDeg).toFixed(2)}deg`);
      card.style.setProperty('--ry', `${(nx * maxDeg).toFixed(2)}deg`);
    },
    { passive: true }
  );

  document.addEventListener(
    'pointerleave',
    () => {
      if (activeTiltCard) {
        activeTiltCard.style.removeProperty('--rx');
        activeTiltCard.style.removeProperty('--ry');
        activeTiltCard = null;
      }
    },
    { passive: true }
  );
}

export function bindEscapeDrawerHandler(onEscape: () => boolean): void {
  if (escapeKeyBound || typeof document === 'undefined') return;
  escapeKeyBound = true;
  document.addEventListener('keydown', (e: KeyboardEvent) => {
    if (e.key === 'Escape') {
      if (onEscape()) {
        e.preventDefault();
      }
    }
  });
}

export function scrollSwipeStrip(stripId: string, direction: -1 | 1): void {
  const el = document.getElementById(stripId);
  if (!el) return;
  const step = Math.max(220, Math.round(el.clientWidth * 0.72));
  el.scrollBy({
    left: direction * step,
    behavior: prefersReducedMotion() ? 'auto' : 'smooth',
  });
}
