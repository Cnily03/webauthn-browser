import { useEffect, useState } from 'react';
import { Alert, Box, Button, CircularProgress, Link, Paper, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Typography } from '@mui/material';
import { ApiError, request } from './api';

interface DownloadFile { name: string; url: string; size: number; created_at: string | null }
const sizeUnits = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
function formatSize(size: number) {
  const unit = size === 0 ? 0 : Math.min(Math.floor(Math.log(size) / Math.log(1024)), sizeUnits.length - 1);
  return `${new Intl.NumberFormat('zh-CN', {maximumFractionDigits: 1}).format(size / 1024 ** unit)} ${sizeUnits[unit]}`;
}
function displayName(name: string) {
  return /[^\s\u0000-\u001f\u007f]/u.test(name) ? name : JSON.stringify(name).replaceAll(' ', '\\u0020');
}
function CreationTime({value}: {value: string | null}) {
  const date = value === null ? null : new Date(value);
  if (!date || !Number.isFinite(date.getTime())) return <>—</>;
  return <time dateTime={value!} title={value!}>{new Intl.DateTimeFormat('zh-CN', {
    year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23',
  }).format(date)}</time>;
}
function readFiles(value: unknown): DownloadFile[] {
  if (!value || typeof value !== 'object' || !('files' in value) || !Array.isArray(value.files)) throw new Error('无法读取下载列表。');
  return value.files.map(file => {
    if (!file || typeof file !== 'object' || typeof file.name !== 'string' || typeof file.url !== 'string'
      || !/^\/downloads\/[^/?#\\]+$/.test(file.url) || new URL(file.url, window.location.origin).pathname !== file.url
      || !Number.isSafeInteger(file.size) || file.size < 0 || (file.created_at !== null && typeof file.created_at !== 'string')) throw new Error('无法读取下载列表。');
    return {name: file.name, url: file.url, size: file.size, created_at: file.created_at};
  });
}

export default function Downloads({onUnauthorized}: {onUnauthorized: () => void}) {
  const [files, setFiles] = useState<DownloadFile[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [version, setVersion] = useState(0);
  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    setLoading(true); setError('');
    void request<unknown>('/api/downloads', 'GET', undefined, {signal: controller.signal})
      .then(value => { if (active) setFiles(readFiles(value)); })
      .catch(error => {
        if (!active) return;
        if (error instanceof ApiError && error.status === 401) { onUnauthorized(); return; }
        setError(error instanceof Error ? error.message : '无法读取下载列表。');
      }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; controller.abort(); };
  }, [onUnauthorized, version]);
  return <Box className="downloads-page">
    <Typography variant="h1" sx={{mb: 3}}>下载</Typography>
    {loading ? <Stack role="status" aria-label="正在读取下载列表" direction="row" spacing={2} sx={{alignItems: 'center', py: 4}}><CircularProgress size={22} /><Typography variant="body2">正在读取…</Typography></Stack>
      : error ? <Alert severity="error" action={<Button onClick={() => setVersion(value => value + 1)}>重试</Button>}>{error}</Alert>
      : <TableContainer component={Paper} variant="outlined"><Table size="small" aria-label="下载文件">
        <TableHead><TableRow><TableCell>文件名</TableCell><TableCell sx={{whiteSpace: 'nowrap'}}>创建时间</TableCell><TableCell align="right" sx={{whiteSpace: 'nowrap'}}>大小</TableCell></TableRow></TableHead>
        <TableBody>{files.length ? files.map(file => <TableRow key={file.url} hover>
          <TableCell sx={{overflowWrap: 'anywhere', minWidth: 160}}><Link href={file.url} download underline="hover" sx={{whiteSpace: 'break-spaces'}}>{displayName(file.name)}</Link></TableCell>
          <TableCell sx={{whiteSpace: 'nowrap'}}><CreationTime value={file.created_at} /></TableCell>
          <TableCell align="right" sx={{whiteSpace: 'nowrap'}}>{formatSize(file.size)}</TableCell>
        </TableRow>) : <TableRow><TableCell colSpan={3} align="center" sx={{py: 4, color: 'text.secondary'}}>暂无文件</TableCell></TableRow>}</TableBody>
      </Table></TableContainer>}
  </Box>;
}
