import { createTheme } from '@mui/material/styles';

export const theme = createTheme({
  // Use Material UI's built-in light palette, spacing, shape and breakpoints.
  cssVariables: true,
  typography: {
    h1: { fontSize: '2rem', fontWeight: 600, letterSpacing: '-.04em' },
    h2: { fontSize: '1.3rem', fontWeight: 600, letterSpacing: '-.025em' },
    h3: { fontSize: '1rem', fontWeight: 600 },
    h4: { fontSize: '1rem', fontWeight: 600 },
  },
  components: {
    MuiButton: { defaultProps: { disableElevation: true, size: 'small' } },
    MuiPaper: { defaultProps: { elevation: 0 } },
    MuiAppBar: { defaultProps: { elevation: 0, color: 'default' } },
    MuiTextField: { defaultProps: { size: 'small', fullWidth: true, variant: 'outlined' } },
    MuiSelect: { styleOverrides: { select: { display: 'flex', alignItems: 'center', gap: 8, '& .MuiSvgIcon-root': { flexShrink: 0 } } } },
    MuiPopover: { styleOverrides: { paper: ({ theme }) => ({ boxShadow: 'none', border: `1px solid ${theme.palette.divider}` }) } },
    MuiMenuItem: { styleOverrides: { root: { gap: 8, minHeight: 40 } } },
    MuiSvgIcon: { styleOverrides: { root: { verticalAlign: 'middle' } } },
    MuiIconButton: { defaultProps: { size: 'small' } },
    MuiChip: { defaultProps: { size: 'small' } },
    MuiAccordion: { defaultProps: { elevation: 1 } },
    MuiDialog: { styleOverrides: { paper: ({ theme }) => ({ border: `1px solid ${theme.palette.divider}`, boxShadow: 'none' }) } },
    MuiDialogTitle: { styleOverrides: { root: { padding: '24px 24px 12px' } } },
    MuiDialogActions: { styleOverrides: { root: { padding: '16px 24px 24px', gap: 8 } } },
    MuiAlert: { styleOverrides: { root: { alignItems: 'center' }, icon: { alignItems: 'center' } } },
    MuiTooltip: { defaultProps: { arrow: true } },
  },
});
export default theme;
