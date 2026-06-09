import React, { useEffect, useState, useCallback } from 'react';
import { getHosts } from '../api/client';
import api from '../api/client';

function StatCard({ label, value, color, sub }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl px-5 py-4 flex-1 min-w-0">
      <p className="text-gray-500 text-xs uppercase tracking-wider mb-1">{label}</p>
      <p className={`text-2xl font-bold ${color}`}>{value}</p>
      {sub && <p className="text-gray-600 text-xs mt-0.5">{sub}</p>}
    </div>
  );
}

export default function StatsBar({ liveAlert, liveEvent }) {
  const [stats, setStats] = useState({
    total: '-', critical: '-', high: '-', medium: '-', hosts: '-', contained: '-',
  });

  const fetchStats = useCallback(async () => {
    try {
      const [countsRes, hostsRes] = await Promise.all([
        api.get('/api/alerts/counts'),
        getHosts({ limit: 100 }),
      ]);
      const counts = countsRes.data;
      const hosts = hostsRes.data;
      setStats({
        total:     counts.TOTAL_24H    ?? 0,
        critical:  counts.CRITICAL_24H ?? 0,
        high:      counts.HIGH_24H     ?? 0,
        medium:    counts.MEDIUM_24H   ?? 0,
        hosts:     hosts.length,
        contained: hosts.filter((h) => h.is_contained).length,
      });
    } catch (_) {}
  }, []);

  useEffect(() => {
    fetchStats();
    const t = setInterval(fetchStats, 5000);
    return () => clearInterval(t);
  }, [fetchStats]);

  useEffect(() => { if (liveAlert) fetchStats(); }, [liveAlert, fetchStats]);
  useEffect(() => { if (liveEvent) fetchStats(); }, [liveEvent, fetchStats]);

  return (
    <div className="flex gap-4 mb-6 flex-wrap">
      <StatCard label="Alerts (24h)"   value={stats.total}    color="text-white"       sub="last 24 hours" />
      <StatCard label="Critical (24h)" value={stats.critical} color="text-red-400"     sub="immediate action" />
      <StatCard label="High (24h)"    value={stats.high}     color="text-orange-400"  sub="investigate now" />
      <StatCard label="Medium (24h)"  value={stats.medium}   color="text-yellow-400"  sub="monitor closely" />
      <StatCard label="Active Hosts"  value={stats.hosts}    color="text-indigo-400" />
      <StatCard
        label="Contained"
        value={stats.contained}
        color={stats.contained > 0 ? 'text-red-400' : 'text-green-400'}
        sub={stats.contained > 0 ? 'hosts isolated' : 'all hosts free'}
      />
    </div>
  );
}
