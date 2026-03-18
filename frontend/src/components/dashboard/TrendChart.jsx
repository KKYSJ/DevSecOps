import React from 'react';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer
} from 'recharts';

const CustomTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    return (
      <div style={{
        background: '#1f2937',
        border: '1px solid #374151',
        padding: '8px 12px',
        borderRadius: 6,
        color: '#fff',
        fontSize: 12,
      }}>
        <div style={{ fontWeight: 700, marginBottom: 4 }}>{label}</div>
        {payload.map(p => (
          <div key={p.name} style={{ color: p.color }}>{p.name}: {p.value}</div>
        ))}
      </div>
    );
  }
  return null;
};

export default function TrendChart({ data = [], lines = [] }) {
  if (!data || data.length === 0) {
    return (
      <div style={{ color: '#9ca3af', textAlign: 'center', padding: 40 }}>
        데이터 없음
      </div>
    );
  }

  const defaultLines = lines.length > 0 ? lines : [
    { key: 'critical', color: '#dc2626', label: 'CRITICAL' },
    { key: 'high', color: '#ea580c', label: 'HIGH' },
    { key: 'medium', color: '#d97706', label: 'MEDIUM' },
  ];

  return (
    <ResponsiveContainer width="100%" height={250}>
      <LineChart data={data} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
        <XAxis dataKey="name" tick={{ fill: '#9ca3af', fontSize: 12 }} axisLine={false} tickLine={false} />
        <YAxis tick={{ fill: '#9ca3af', fontSize: 12 }} axisLine={false} tickLine={false} allowDecimals={false} />
        <Tooltip content={<CustomTooltip />} />
        <Legend formatter={(v) => <span style={{ color: '#9ca3af', fontSize: 11 }}>{v}</span>} />
        {defaultLines.map(l => (
          <Line
            key={l.key}
            type="monotone"
            dataKey={l.key}
            stroke={l.color}
            strokeWidth={2}
            dot={{ fill: l.color, r: 3 }}
            name={l.label}
          />
        ))}
      </LineChart>
    </ResponsiveContainer>
  );
}
