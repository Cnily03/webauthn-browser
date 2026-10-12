import { act, fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { useLocalNavigationToast } from './LocalNavigationToast';
import type { LocalNavigationEvent } from './localNavigation';
const callbacks = vi.hoisted(() => [] as (() => void)[]);
vi.mock('@mui/material', async load => {
  const actual = await load<typeof import('@mui/material')>();
  return {...actual, Snackbar: (props: {slotProps: {transition: {entered: () => void}}; message: string; action: React.ReactNode; onMouseEnter: () => void; onMouseLeave: () => void}) => {
    callbacks.push(props.slotProps.transition.entered);
    return <div onMouseEnter={props.onMouseEnter} onMouseLeave={props.onMouseLeave}>{props.message}{props.action}</div>;
  }};
});
let receive!: ReturnType<typeof useLocalNavigationToast>['receive'];
function Harness() {const current = useLocalNavigationToast(); receive = current.receive; return current.toast;}
let sequence = 0;
const notice = (): LocalNavigationEvent => ({id: `transition-test:${++sequence}`, url: 'http://localhost:1234/test', remaining_ms: 1000, mode_generation: 1});
beforeEach(() => {vi.useFakeTimers(); callbacks.length = 0;});
it('ignores a replaced entry callback and arms the current display only once', () => {
  render(<Harness />); act(() => receive(notice())); const oldEntered = callbacks.at(-1)!;
  act(() => receive(notice())); const entered = callbacks.at(-1)!;
  act(() => {oldEntered(); vi.advanceTimersByTime(10000);}); expect(screen.getByText(/^在本机浏览器打开/)).toBeInTheDocument();
  act(() => {entered(); vi.advanceTimersByTime(4000); entered(); vi.advanceTimersByTime(999);}); expect(screen.getByText(/^在本机浏览器打开/)).toBeInTheDocument();
  act(() => vi.advanceTimersByTime(1)); expect(screen.queryByText(/^在本机浏览器打开/)).toBeNull();
});
it('does not arm a cleared or unmounted entry callback', () => {
  const view = render(<Harness />); act(() => receive(notice())); const cleared = callbacks.at(-1)!;
  fireEvent.click(screen.getByRole('button', {name: '取消'})); act(() => {cleared(); vi.advanceTimersByTime(10000);}); expect(screen.queryByText(/^在本机浏览器打开/)).toBeNull();
  act(() => receive(notice())); const unmounted = callbacks.at(-1)!; view.unmount(); act(() => {unmounted(); vi.advanceTimersByTime(10000);}); expect(screen.queryByText(/^在本机浏览器打开/)).toBeNull();
});
