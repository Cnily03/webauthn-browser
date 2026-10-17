import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { AppBar, Box, IconButton, Menu, MenuItem, Stack, Toolbar, Tooltip } from '@mui/material';
import { alpha } from '@mui/material/styles';
import AccountCircleOutlinedIcon from '@mui/icons-material/AccountCircleOutlined';
import AddIcon from '@mui/icons-material/Add';
import CircleIcon from '@mui/icons-material/Circle';
import DeleteOutlineIcon from '@mui/icons-material/DeleteOutlined';
import KeyboardDoubleArrowLeftIcon from '@mui/icons-material/KeyboardDoubleArrowLeft';
import KeyboardDoubleArrowRightIcon from '@mui/icons-material/KeyboardDoubleArrowRight';
import { canonicalProfileName, forgetProfile, prepareProfileChooser, savedProfiles, type PublicBrowserProfile, type NavigateProfile, type ProfileStatus } from './profiles';
import { request, setCsrfToken } from './api';
import type { AppStatus } from './types';

// This is the authenticated document's selected profile, not engine ownership
// or the most recently remembered profile from another tab.
interface ProfileNavigationState {
  profiles: PublicBrowserProfile[];
  activeProfileName: string | null;
  profileStatuses: Record<string, ProfileStatus>;
  notifyError: (message: string) => void;
  navigateDocument: (path: string) => void;
  navigateProfile: NavigateProfile;
}
export const ProfileNavigationContext = createContext<ProfileNavigationState | null>(null);

function ProfileMenu({profiles, activeProfileName, profileStatuses, notifyError, navigateDocument, navigateProfile, visible}: ProfileNavigationState & {visible: boolean}) {
  const [anchor, setAnchor] = useState<HTMLElement | null>(null);
  const [hovered, setHovered] = useState<string | null>(null);
  const [hoveredStatus, setHoveredStatus] = useState<string | null>(null);
  const [focused, setFocused] = useState<string | null>(null);
  const [pending, setPending] = useState<string | null>(null);
  const [armed, setArmed] = useState<string | null>(null);
  const arm = useRef<{name: string; deadline: number} | null>(null);
  const armTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const resetArm = () => {clearTimeout(armTimer.current); arm.current = null; setArmed(null);};
  const [, setRevision] = useState(0);
  const pendingRef = useRef<string | null>(null);
  const mounted = useRef(true);
  const rows = useRef(new Map<string, HTMLElement>());
  const add = useRef<HTMLLIElement>(null);
  const nextFocus = useRef<string | null | undefined>(undefined);
  useEffect(() => {
    if (pending === null && nextFocus.current !== undefined) {
      (nextFocus.current ? rows.current.get(nextFocus.current) : add.current)?.focus();
      nextFocus.current = undefined;
    }
  }, [pending]);
  useEffect(() => {mounted.current = true; return () => {mounted.current = false;};}, []);
  // Public discovery can omit disabled/deleted profiles. The local hint remains
  // until the user explicitly forgets it; only a successful entry is current.
  const activeName = activeProfileName === null ? null : canonicalProfileName(activeProfileName);
  const entries = savedProfiles().map(saved => profiles.find(profile => canonicalProfileName(profile.name) === canonicalProfileName(saved.name)) ?? saved);
  const active = profiles.find(profile => canonicalProfileName(profile.name) === activeName);
  if (active && !entries.some(profile => canonicalProfileName(profile.name) === activeName)) entries.unshift(active);
  const close = () => {resetArm(); setHovered(null); setHoveredStatus(null); setFocused(null); setAnchor(null);};
  useEffect(() => {if (!visible) close();}, [visible]);
  useEffect(() => {if (armed === activeName) resetArm();}, [activeName, armed]);
  useEffect(() => {
    const hide = () => {resetArm(); setHovered(null); setHoveredStatus(null); setFocused(null); setAnchor(null);};
    window.addEventListener('pagehide', hide);
    return () => {clearTimeout(armTimer.current); window.removeEventListener('pagehide', hide);};
  }, []);
  const select = async (profile: Pick<PublicBrowserProfile, 'name'>) => {
    const name = canonicalProfileName(profile.name);
    if (name === activeName || pendingRef.current) return;
    resetArm();
    if (!profiles.some(candidate => canonicalProfileName(candidate.name) === name && candidate.effective_enabled)) {
      close(); notifyError('浏览器配置不存在或已停用。'); return;
    }
    pendingRef.current = name; setPending(name);
    try {await navigateProfile({name: profile.name}); if (mounted.current) close();}
    catch (failure) {if (mounted.current) {close(); notifyError(failure instanceof Error ? failure.message : '切换配置失败。');}}
    finally {pendingRef.current = null; if (mounted.current) setPending(null);}
  };
  const confirmForget = (profileName: string) => {
    const name = canonicalProfileName(profileName);
    if (name === activeName || pendingRef.current) return;
    if (arm.current?.name === name && Date.now() < arm.current.deadline) {resetArm(); void forget(profileName); return;}
    resetArm(); arm.current = {name, deadline: Date.now() + 3000}; setArmed(name);
    armTimer.current = setTimeout(resetArm, 3000);
  };
  const forget = async (profileName: string) => {
    const name = canonicalProfileName(profileName);
    if (name === activeName || pendingRef.current) return;
    pendingRef.current = name; setPending(name);
    const nextName = entries[entries.findIndex(profile => canonicalProfileName(profile.name) === name) + 1]?.name;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);
    try {
      // Explicit URLs never inherit another profile's viewer headers. Refresh
      // global CSRF first so expired/deleted hints can also clear their cookie.
      const status = await request<AppStatus>('/api/status', 'GET', undefined, {scope: 'global', signal: controller.signal});
      setCsrfToken(status.csrf_token);
      await request(`/p/${encodeURIComponent(name)}/api/logout`, 'POST', {scope: 'vnc'}, {signal: controller.signal});
      if (!forgetProfile(name)) throw new Error('登录凭据已清除，但无法移除本地配置记录。');
      if (mounted.current) {
        setRevision(value => value + 1);
        nextFocus.current = nextName === undefined ? null : canonicalProfileName(nextName);
      }
    } catch (failure) {
      if (mounted.current) {close(); notifyError(failure instanceof Error ? failure.message : '移除配置失败，请重试。');}
    } finally {
      clearTimeout(timeout); pendingRef.current = null;
      if (mounted.current) setPending(null);
    }
  };
  return <>
    <Tooltip title="浏览器配置"><IconButton id="profile-menu-trigger" aria-label="浏览器配置" color="inherit" size="small"
      aria-haspopup="menu" aria-expanded={Boolean(anchor)} aria-controls={anchor ? 'profile-menu' : undefined}
      onClick={event => setAnchor(event.currentTarget)} sx={{flexShrink: 0, width: 32, height: 32}}><AccountCircleOutlinedIcon fontSize="small" /></IconButton></Tooltip>
    <Menu id="profile-menu" anchorEl={anchor} open={Boolean(anchor)} onClose={close} slotProps={{list: {'aria-labelledby': 'profile-menu-trigger'}}}>
      {entries.map(profile => {
        const name = canonicalProfileName(profile.name);
        const current = name === activeName;
        const unavailable = !profiles.some(candidate => canonicalProfileName(candidate.name) === name && candidate.effective_enabled);
        const removeVisible = !current && (hovered === name || focused === name || armed === name);
        const status = current ? '当前配置' : unavailable ? '配置不存在或已停用' : profileStatuses[name] === 'auth_invalid' ? '配置认证失效' : '';
        const statusColor = current ? 'success' : unavailable ? 'error' : 'warning';
        const showStatus = Boolean(anchor) && (hoveredStatus === name || (hovered === null && focused === name));
        return <MenuItem key={name} ref={element => {if (element) rows.current.set(name, element); else rows.current.delete(name);}}
          disabled={pending !== null} aria-label={`${profile.name}${status ? ` ${status}` : ''}`} aria-current={current ? 'true' : undefined}
          aria-describedby={status && showStatus ? `profile-status-${name}` : undefined}
          onMouseEnter={() => {if (arm.current && arm.current.name !== name) resetArm(); setHovered(name);}} onMouseLeave={() => setHovered(null)} onFocus={() => {if (arm.current && arm.current.name !== name) resetArm(); setFocused(name);}}
          onBlur={event => {if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setFocused(null);}}
          onKeyDown={event => {if (event.target === event.currentTarget && ['Delete', 'Backspace'].includes(event.key)) {event.preventDefault(); if (!current && !event.repeat) confirmForget(profile.name);}}}
          onClick={() => {if (!current) void select(profile);}}
          sx={{gap: 1, minWidth: 200, maxWidth: 'calc(100vw - 32px)'}}>
          <Box sx={{width: 28, height: 28, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0}}>
            {removeVisible ? <Tooltip title="移除此配置"><IconButton aria-label={`移除配置 ${profile.name}`} size="small" tabIndex={-1} disabled={pending !== null} color={armed === name ? 'error' : 'inherit'} aria-pressed={armed === name}
              onClick={event => {event.preventDefault(); event.stopPropagation(); confirmForget(profile.name);}} sx={{width: 28, height: 28}}><DeleteOutlineIcon fontSize="small" /></IconButton></Tooltip>
              : <AccountCircleOutlinedIcon fontSize="small" />}
          </Box>
          <Box component="span" sx={{flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', color: 'inherit', textDecoration: 'none'}}>{profile.name}</Box>
          <Box sx={{width: 18, height: 18, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0}}>{status &&
            <Tooltip id={`profile-status-${name}`} title={status} placement="right" open={showStatus} disableHoverListener disableFocusListener disableTouchListener disableInteractive>
              <CircleIcon role="img" aria-label={status} aria-hidden={undefined} color={statusColor} onMouseEnter={() => setHoveredStatus(name)} onMouseLeave={() => setHoveredStatus(null)}
                sx={{fontSize: 10, borderRadius: '50%', boxShadow: theme => `0 0 0 4px ${alpha(theme.palette[statusColor].main, .12)}`}} />
            </Tooltip>}
          </Box>
        </MenuItem>;
      })}
      <MenuItem ref={add} component="li" disabled={pending !== null} aria-label="登录其他配置" onClick={() => {try {prepareProfileChooser(); close(); navigateDocument('/');} catch (failure) {close(); notifyError(failure instanceof Error ? failure.message : '无法打开登录页面。');}}} sx={{gap: 1}}>
        <AddIcon fontSize="small" sx={{width: 28, flexShrink: 0}} /><Box component="span">登录其他配置</Box>
      </MenuItem>
    </Menu>
  </>;
}

export function NavigationBar({children, collapsible = false, collapsed = false, onToggle}: {children?: ReactNode; collapsible?: boolean; collapsed?: boolean; onToggle?: () => void}) {
  const profileNavigation = useContext(ProfileNavigationContext);
  if (!profileNavigation && !children) return null;
  return <AppBar position="fixed" className={`topbar${collapsed ? ' collapsed' : ''}`} sx={{
    top: {xs: 8, sm: 12}, left: {xs: 8, sm: 16}, right: 'auto', width: 'auto', maxWidth: 'calc(100vw - 16px)',
    border: 1, borderColor: 'divider', borderRadius: 1, bgcolor: 'background.paper', color: 'text.secondary',
  }}>
    <Toolbar variant="dense" disableGutters className="topbar-toolbar" sx={{minHeight: '40px !important', px: .5, gap: .5}}>
      {children && <>
        <Tooltip title={!collapsible ? '' : collapsed ? '展开导航' : '收起导航'}><IconButton className="navigation-toggle" color="inherit" size="small" disabled={!collapsible} tabIndex={!collapsible ? -1 : undefined} aria-hidden={!collapsible || undefined}
          aria-label={!collapsible ? undefined : collapsed ? '展开导航' : '收起导航'} onClick={!collapsible ? undefined : onToggle} aria-expanded={!collapsible ? undefined : !collapsed} aria-controls={!collapsible ? undefined : 'navigation-group'}
          sx={{flexShrink: 0, width: 32, height: 32, visibility: !collapsible ? 'hidden' : 'visible'}}>{collapsed ? <KeyboardDoubleArrowRightIcon fontSize="small" /> : <KeyboardDoubleArrowLeftIcon fontSize="small" />}</IconButton></Tooltip>
        <Stack id="navigation-group" className="navigation-group" direction="row" hidden={collapsed} sx={{minWidth: 0, alignItems: 'center', overflowX: 'auto', '& nav': {flexShrink: 0}}}>
          {profileNavigation && <ProfileMenu {...profileNavigation} visible={!collapsed} />}
          {children}
        </Stack>
      </>}
    </Toolbar>
  </AppBar>;
}
