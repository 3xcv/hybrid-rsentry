import React, { useState, useEffect } from 'react';

function stamp() {
  const d = new Date();
  const p = n => String(n).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}`;
}

export default function StatusBar({ connected }) {
  const [time, setTime] = useState(stamp());
  const [hostCount, setHostCount] = useState(null);
  const [eventRate, setEventRate] = useState(null);
  const [sensorMode, setSensorMode] = useState('eBPF');

  useEffect(() => {
    const t = setInterval(() => setTime(stamp()), 30000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    let cancelled = false;
    const fetchHosts = async () => {
      try {
        const res = await fetch('/api/hosts');
        if (!res.ok) return;
        const data = await res.json();
        if (!cancelled) setHostCount(Array.isArray(data) ? data.length : null);
      } catch (_) {}
    };
    fetchHosts();
    const t = setInterval(fetchHosts, 60000);
    return () => { cancelled = true; clearInterval(t); };
  }, []);

  useEffect(() => {
    let cancelled = false;
    const fetchEps = async () => {
      try {
        const since = new Date(Date.now() - 60000).toISOString();
        const res = await fetch(`/api/events?since=${since}&limit=1000`);
        if (!res.ok) return;
        const data = await res.json();
        if (!cancelled) setEventRate(Array.isArray(data) ? (data.length / 60).toFixed(2) : null);
      } catch (_) {}
    };
    fetchEps();
    const t = setInterval(fetchEps, 15000);
    return () => { cancelled = true; clearInterval(t); };
  }, []);

  useEffect(() => {
    const fetchHealth = async () => {
      try {
        const res = await fetch('/health');
        if (!res.ok) return;
        const data = await res.json();
        if (data.sensor_backend) setSensorMode(data.sensor_backend === 'ebpf' ? 'eBPF' : 'inotify');
      } catch (_) {}
    };
    fetchHealth();
  }, []);

  return (
    <footer style={{ height: 24, flexShrink: 0, display: 'flex', alignItems: 'center', gap: 16, padding: '0 14px', background: 'var(--panel)', borderTop: '1px solid var(--border)', fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--muted)' }}>
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
        <span style={{ width: 7, height: 7, borderRadius: '50%', background: connected ? 'var(--ok)' : 'var(--crit)', display: 'inline-block' }} />
        {hostCount ?? 1} agent{(hostCount ?? 1) !== 1 ? 's' : ''} reporting
      </span>
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
        <span style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--ok)', display: 'inline-block' }} />
        ingest {eventRate ?? '—'} EPS
      </span>
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, background: 'var(--panel-2)', border: '1px solid var(--border)', borderRadius: 4, padding: '1px 7px', color: 'var(--accent)', fontSize: 10, letterSpacing: '0.04em' }}>
        <i className="fa-solid fa-microchip" style={{ fontSize: 9 }} />
        {sensorMode}
      </span>
      {!connected && (
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
          <span style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--high)', display: 'inline-block' }} />
          WebSocket disconnected
        </span>
      )}
      <span style={{ flex: 1 }} />
      <span>last refreshed {time}</span>
      <span>cluster: rsentry-prod · v2.2.0</span>
    </footer>
  );
}
