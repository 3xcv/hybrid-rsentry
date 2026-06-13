import React, { useEffect, useState } from 'react';

function Section({ title, icon, items, mono = true }) {
  const [open, setOpen] = useState(true);
  return (
    <div style={{ marginBottom: 20, background: 'var(--panel)', border: '1px solid var(--border)', borderRadius: 8 }}>
      <button
        onClick={() => setOpen(v => !v)}
        style={{ width: '100%', display: 'flex', alignItems: 'center', gap: 10, padding: '10px 14px', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text)', fontSize: 13, fontWeight: 600, fontFamily: 'var(--sans)', textAlign: 'left' }}>
        <i className={`fa-solid fa-${icon}`} style={{ color: 'var(--accent)', fontSize: 12, width: 16 }} />
        {title}
        <span style={{ fontSize: 11, color: 'var(--muted)', fontWeight: 400, marginLeft: 4 }}>({items.length})</span>
        <i className={`fa-solid fa-chevron-${open ? 'up' : 'down'}`} style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--muted)' }} />
      </button>
      {open && (
        <div style={{ padding: '0 14px 14px', display: 'flex', flexWrap: 'wrap', gap: 6 }}>
          {items.map(item => (
            <span key={item} style={{
              fontFamily: mono ? 'var(--mono)' : 'var(--sans)',
              fontSize: 11,
              background: 'var(--bg)',
              border: '1px solid var(--border)',
              borderRadius: 4,
              padding: '2px 8px',
              color: 'var(--text-2)',
            }}>
              {item}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

export default function ExceptionsPage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetch('/api/exceptions')
      .then(r => r.json())
      .then(d => { setData(d); setLoading(false); })
      .catch(e => { setError(String(e)); setLoading(false); });
  }, []);

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: 24, background: 'var(--bg)' }}>
      <div style={{ marginBottom: 20 }}>
        <h2 style={{ color: 'var(--text)', fontSize: 18, fontWeight: 600, fontFamily: 'var(--sans)', margin: 0 }}>Exception Rules</h2>
        <p style={{ color: 'var(--muted)', fontSize: 13, marginTop: 4, fontFamily: 'var(--sans)' }}>
          Read-only view of whitelist rules from <code style={{ fontFamily: 'var(--mono)', fontSize: 11 }}>agent/exceptions.py</code>.
          These suppress false positives from known-safe processes and paths.
        </p>
        <div style={{ marginTop: 10, padding: '8px 12px', background: 'var(--panel)', border: '1px solid var(--border)', borderRadius: 6, fontSize: 12, color: 'var(--muted)', fontFamily: 'var(--sans)' }}>
          <i className="fa-solid fa-circle-info" style={{ color: 'var(--accent)', marginRight: 7 }} />
          To add or remove rules, edit <code style={{ fontFamily: 'var(--mono)' }}>agent/exceptions.py</code> and restart the agent.
          Temp-dir overrides apply: suspicious extensions in <code style={{ fontFamily: 'var(--mono)' }}>/tmp/</code> are never whitelisted.
        </div>
      </div>

      {loading && <p style={{ color: 'var(--muted)', fontFamily: 'var(--mono)', fontSize: 13 }}>Loading exceptions…</p>}
      {error   && <p style={{ color: 'var(--crit)', fontFamily: 'var(--mono)', fontSize: 13 }}>Error: {error}</p>}

      {data && (
        <>
          <Section title="Whitelisted Processes" icon="microchip"  items={data.processes} />
          <Section title="Whitelisted Path Prefixes" icon="folder" items={data.path_prefixes} />
          <Section title="Whitelisted Extensions" icon="file"     items={data.extensions} />
          <Section title="Temp Dir Prefixes (smart override)" icon="triangle-exclamation" items={data.temp_dir_prefixes} />
          <Section title="Suspicious Extensions in Temp (never whitelisted)" icon="shield-halved" items={data.suspicious_extensions_in_temp} />
        </>
      )}
    </div>
  );
}
