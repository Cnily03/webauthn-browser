import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { clampBarPosition, useFloatingBar } from './floatingBar';

const originalViewport = {width: window.innerWidth, height: window.innerHeight};
function viewport(width: number, height: number) {
  Object.defineProperty(window, 'innerWidth', {configurable: true, value: width});
  Object.defineProperty(window, 'innerHeight', {configurable: true, value: height});
}
function pointer(target: Element, type: string, x: number, y: number, id = 1, button = 0) {
  const event = new Event(type, {bubbles: true, cancelable: true});
  Object.assign(event, {clientX: x, clientY: y, pointerId: id, button, isPrimary: true});
  fireEvent(target, event);
}
function Bar({enabled = true, onConnect = vi.fn()}: {enabled?: boolean; onConnect?: () => void}) {
  const {paperRef, position, handleProps} = useFloatingBar(enabled);
  return <div ref={paperRef} data-testid="bar" style={{left: position?.x, top: position?.y}}>
    <button aria-label="Move bar" {...handleProps}>Drag</button>
    <input aria-label="Address" defaultValue="localhost:10233" />
    <button onClick={onConnect}>Connect</button>
  </div>;
}
beforeEach(() => {
  viewport(800, 600);
  vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockReturnValue({width: 320, height: 56, left: 0, top: 0, right: 320, bottom: 56, x: 0, y: 0, toJSON: () => ({})});
});
afterEach(() => { vi.restoreAllMocks(); viewport(originalViewport.width, originalViewport.height); });

describe('compact connection bar dragging', () => {
  it('clamps within the viewport even when the viewport is smaller than the bar', () => {
    expect(clampBarPosition({x: -20, y: 1000}, 320, 56, 800, 600)).toEqual({x: 8, y: 536});
    expect(clampBarPosition({x: 100, y: 100}, 320, 56, 100, 40)).toEqual({x: 8, y: 8});
  });
  it('starts bottom-left and captures only the active handle pointer while clamping movement', () => {
    render(<Bar />); const bar = screen.getByTestId('bar'); const handle = screen.getByRole('button', {name: 'Move bar'});
    const capture = vi.fn(); const release = vi.fn();
    Object.assign(handle, {setPointerCapture: capture, hasPointerCapture: () => true, releasePointerCapture: release});
    expect(bar).toHaveStyle({left: '16px', top: '528px'});
    pointer(handle, 'pointerdown', 100, 100); expect(capture).toHaveBeenCalledWith(1);
    pointer(handle, 'pointermove', 10000, 10000, 2); expect(bar).toHaveStyle({left: '16px', top: '528px'});
    pointer(handle, 'pointermove', 10000, 10000); expect(bar).toHaveStyle({left: '472px', top: '536px'});
    pointer(handle, 'pointermove', -10000, -10000); expect(bar).toHaveStyle({left: '8px', top: '8px'});
    pointer(handle, 'pointerup', -10000, -10000); expect(release).toHaveBeenCalledWith(1);
    pointer(handle, 'pointermove', 500, 500); expect(bar).toHaveStyle({left: '8px', top: '8px'});
  });
  it('supports keyboard movement and fine adjustment without changing placement on unrelated keys', () => {
    render(<Bar />); const bar = screen.getByTestId('bar'); const handle = screen.getByRole('button', {name: 'Move bar'});
    fireEvent.keyDown(handle, {key: 'ArrowLeft'}); fireEvent.keyDown(handle, {key: 'ArrowUp'});
    expect(bar).toHaveStyle({left: '8px', top: '518px'});
    fireEvent.keyDown(handle, {key: 'ArrowLeft', shiftKey: true}); expect(bar).toHaveStyle({left: '8px'});
    fireEvent.keyDown(handle, {key: 'Enter'}); expect(bar).toHaveStyle({left: '8px', top: '518px'});
  });
  it('clamps on viewport resize without resetting an already moved bar', () => {
    render(<Bar />); const bar = screen.getByTestId('bar');
    const handle = screen.getByRole('button', {name: 'Move bar'});
    pointer(handle, 'pointerdown', 0, 0); pointer(handle, 'pointermove', 300, 0); pointer(handle, 'pointerup', 300, 0);
    act(() => { viewport(400, 200); window.dispatchEvent(new Event('resize')); });
    expect(bar).toHaveStyle({left: '72px', top: '136px'});
    act(() => { viewport(1200, 900); window.dispatchEvent(new Event('resize')); });
    expect(bar).toHaveStyle({left: '72px', top: '136px'});
  });
  it('never starts dragging from the input, action buttons, or a secondary pointer button', () => {
    const connect = vi.fn(); render(<Bar onConnect={connect} />); const bar = screen.getByTestId('bar');
    for (const control of [screen.getByLabelText('Address'), screen.getByRole('button', {name: 'Connect'})]) {
      pointer(control, 'pointerdown', 0, 0); pointer(control, 'pointermove', -10000, -10000); pointer(control, 'pointerup', -10000, -10000);
    }
    const handle = screen.getByRole('button', {name: 'Move bar'}); pointer(handle, 'pointerdown', 0, 0, 1, 2); pointer(handle, 'pointermove', -10000, -10000);
    fireEvent.change(screen.getByLabelText('Address'), {target: {value: 'localhost:19000'}}); fireEvent.click(screen.getByRole('button', {name: 'Connect'}));
    expect(connect).toHaveBeenCalledOnce(); expect(screen.getByLabelText('Address')).toHaveValue('localhost:19000');
    expect(bar).toHaveStyle({left: '16px', top: '528px'});
  });
  it('handles pointer capture and release failures without leaving a drag active', () => {
    render(<Bar />); const handle = screen.getByRole('button', {name: 'Move bar'}); const bar = screen.getByTestId('bar');
    Object.assign(handle, {setPointerCapture: () => { throw new Error('pointer ended'); }});
    expect(() => pointer(handle, 'pointerdown', 0, 0)).not.toThrow(); pointer(handle, 'pointermove', -10000, -10000);
    expect(bar).toHaveStyle({left: '16px', top: '528px'});
    Object.assign(handle, {setPointerCapture: vi.fn(), hasPointerCapture: () => true, releasePointerCapture: () => { throw new Error('capture already released'); }});
    pointer(handle, 'pointerdown', 0, 0); expect(() => pointer(handle, 'pointerup', 0, 0)).not.toThrow(); pointer(handle, 'pointermove', -10000, -10000);
    expect(bar).toHaveStyle({left: '16px', top: '528px'});
  });
  it.each(['pointercancel', 'lostpointercapture'])('ends dragging on %s and removes resize behavior after leaving compact mode', event => {
    const rendered = render(<Bar />); const handle = screen.getByRole('button', {name: 'Move bar'}); const bar = screen.getByTestId('bar');
    pointer(handle, 'pointerdown', 0, 0); pointer(handle, event, 0, 0); pointer(handle, 'pointermove', -10000, -10000);
    expect(bar).toHaveStyle({left: '16px', top: '528px'});
    rendered.rerender(<Bar enabled={false} />); expect(bar.style.left).toBe(''); expect(bar.style.top).toBe('');
    act(() => { viewport(400, 200); window.dispatchEvent(new Event('resize')); });
    expect(bar.style.left).toBe(''); expect(bar.style.top).toBe('');
  });
});
