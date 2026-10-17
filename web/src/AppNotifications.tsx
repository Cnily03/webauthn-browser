import { createContext, useCallback, useState } from 'react';
import { Alert, Snackbar } from '@mui/material';

export type Notify = (message: string, error?: boolean) => void;
export const AppNotificationContext = createContext<Notify | null>(null);

export function useAppNotification() {
  const [notice, setNotice] = useState({message: '', error: false, id: 0, open: false});
  const notify = useCallback<Notify>((message, error = false) => setNotice(previous => message
    ? {message, error, id: previous.id + 1, open: true}
    : {...previous, open: false}), []);
  // Retain content through exit and ignore callbacks from superseded notices.
  const close = (id: number) => setNotice(current => current.id === id ? {...current, open: false} : current);
  const exited = (id: number) => setNotice(current => current.id === id && !current.open ? {...current, message: ''} : current);
  const snackbar = <Snackbar key={notice.id} open={notice.open} autoHideDuration={notice.error ? null : 3000}
    onClose={(_, reason) => {if (reason !== 'clickaway') close(notice.id);}}
    slotProps={{transition: {onExited: () => exited(notice.id)}}}
    anchorOrigin={{vertical: 'bottom', horizontal: 'center'}}><Alert severity={notice.error ? 'error' : 'success'} variant="filled" onClose={() => close(notice.id)} sx={{width: '100%'}}>{notice.message}</Alert></Snackbar>;
  return {notify, snackbar};
}
