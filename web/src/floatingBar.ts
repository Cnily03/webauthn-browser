import { useLayoutEffect, useRef, useState, type KeyboardEvent, type PointerEvent } from 'react';

interface Position { x: number; y: number }
export function clampBarPosition(position: Position, width: number, height: number, viewportWidth: number, viewportHeight: number): Position {
  return {
    x: Math.max(8, Math.min(position.x, Math.max(8, viewportWidth - width - 8))),
    y: Math.max(8, Math.min(position.y, Math.max(8, viewportHeight - height - 8))),
  };
}
export function useFloatingBar(enabled: boolean, layoutKey?: unknown) {
  const paperRef = useRef<HTMLDivElement | null>(null);
  const moved = useRef(false);
  const positionRef = useRef<Position | null>(null);
  const [position, setPosition] = useState<Position | null>(null);
  const drag = useRef<{id: number; x: number; y: number; origin: Position} | null>(null);
  const place = (next: Position) => {
    const bounds = paperRef.current?.getBoundingClientRect();
    if (!bounds) return;
    const clamped = clampBarPosition(next, bounds.width, bounds.height, window.innerWidth, window.innerHeight);
    positionRef.current = clamped; setPosition(clamped);
  };
  useLayoutEffect(() => {
    if (!enabled) { positionRef.current = null; moved.current = false; setPosition(null); drag.current = null; return; }
    const resize = () => {
      const bounds = paperRef.current?.getBoundingClientRect();
      if (bounds) place(moved.current && positionRef.current ? positionRef.current : {x: 16, y: window.innerHeight - bounds.height - 16});
    };
    resize(); window.addEventListener('resize', resize);
    const observer = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(resize) : null;
    if (paperRef.current) observer?.observe(paperRef.current);
    return () => { drag.current = null; observer?.disconnect(); window.removeEventListener('resize', resize); };
  }, [enabled, layoutKey]);
  const onPointerDown = (event: PointerEvent<HTMLButtonElement>) => {
    if (!enabled || event.button !== 0 || event.isPrimary === false) return;
    const bounds = paperRef.current?.getBoundingClientRect();
    if (!bounds) return;
    moved.current = true;
    drag.current = {id: event.pointerId, x: event.clientX, y: event.clientY, origin: positionRef.current ?? {x: bounds.left, y: bounds.top}};
    try { event.currentTarget.setPointerCapture?.(event.pointerId); }
    catch { drag.current = null; return; }
    event.preventDefault();
  };
  const onPointerMove = (event: PointerEvent<HTMLButtonElement>) => {
    const current = drag.current;
    if (!current || current.id !== event.pointerId) return;
    place({x: current.origin.x + event.clientX - current.x, y: current.origin.y + event.clientY - current.y});
  };
  const onPointerEnd = (event: PointerEvent<HTMLButtonElement>) => {
    if (drag.current?.id !== event.pointerId) return;
    drag.current = null;
    try { if (event.currentTarget.hasPointerCapture?.(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId); }
    catch { /* A cancelled pointer may already have released capture. */ }
  };
  const onKeyDown = (event: KeyboardEvent<HTMLButtonElement>) => {
    const direction = {ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1]}[event.key];
    if (!enabled || !direction || !positionRef.current) return;
    event.preventDefault(); event.stopPropagation();
    moved.current = true;
    const step = event.shiftKey ? 1 : 10;
    place({x: positionRef.current.x + direction[0] * step, y: positionRef.current.y + direction[1] * step});
  };
  return {paperRef, position, handleProps: {onPointerDown, onPointerMove, onPointerUp: onPointerEnd, onPointerCancel: onPointerEnd,
    onLostPointerCapture: (event: PointerEvent<HTMLButtonElement>) => { if (drag.current?.id === event.pointerId) drag.current = null; }, onKeyDown}};
}
