import React, { useState, useEffect } from 'react';

const FALLBACK_DATA = {
  obligations: [
    { id: "obl_1", title: "Timely Incident Logging", description: "All reported phishing incidents must be logged with valid timestamps." },
    { id: "obl_2", title: "Severity Classification", description: "Every security report must have a defined severity level (High, Medium, Low)." },
    { id: "obl_3", title: "Automated and Manual Source Tracking", description: "Reports must clearly indicate whether they originated from automated scans or manual employee reports." },
    { id: "obl_4", title: "Incident Response Within 48 Hours", description: "High-severity incidents must be resolved within 48 hours of being reported." },
    { id: "obl_5", title: "Active Monitoring", description: "Automated scanning must have produced reports within the last 30 days." }
  ],
  statuses: [
    { obligation_id: "obl_1", status: "met", detail: "All reports have valid timestamps." },
    { obligation_id: "obl_2", status: "at risk", detail: "1 report missing verified severity level." },
    { obligation_id: "obl_3", status: "met", detail: "All reports specify automatic or employee source." },
    { obligation_id: "obl_4", status: "unmet", detail: "2 high-severity incidents unresolved after 48 hours." },
    { obligation_id: "obl_5", status: "met", detail: "Automated scanning active within last 30 days." }
  ]
};

export default function App() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [usingFallback, setUsingFallback] = useState(false);

  const fetchCompliance = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/compliance-status');
      if (!res.ok) {
        throw new Error(`Server returned HTTP ${res.status}`);
      }
      const json = await res.json();
      setData(json);
      setUsingFallback(false);
    } catch (err) {
      console.warn("Backend unavailable or unseeded, using mock data:", err);
      setData(FALLBACK_DATA);
      setUsingFallback(true);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCompliance();
  }, []);

  const getStatusBadge = (status) => {
    switch (status?.toLowerCase()) {
      case 'met':
        return <span className="px-3 py-1 text-xs font-semibold rounded-full bg-emerald-100 text-emerald-800 border border-emerald-300">MET</span>;
      case 'at risk':
        return <span className="px-3 py-1 text-xs font-semibold rounded-full bg-amber-100 text-amber-800 border border-amber-300">AT RISK</span>;
      case 'unmet':
        return <span className="px-3 py-1 text-xs font-semibold rounded-full bg-rose-100 text-rose-800 border border-rose-300">UNMET</span>;
      default:
        return <span className="px-3 py-1 text-xs font-semibold rounded-full bg-gray-100 text-gray-800">UNKNOWN</span>;
    }
  };

  const statusMap = new Map((data?.statuses || []).map(s => [s.obligation_id, s]));

  return (
    <div className="min-h-screen bg-slate-50 text-slate-800">
      <header className="bg-slate-900 text-white shadow-md">
        <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold tracking-tight">EthioSecure — Analyst Portal</h1>
            <p className="text-xs text-slate-400">Security Operations & Compliance Readiness</p>
          </div>
          <button
            onClick={fetchCompliance}
            className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 rounded text-xs font-medium transition"
          >
            Refresh Status
          </button>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-6 py-8">
        {usingFallback && (
          <div className="mb-6 p-4 rounded-lg bg-amber-50 border border-amber-200 text-amber-900 text-sm flex items-start justify-between">
            <div>
              <p className="font-semibold">Displaying Preview / Fallback Data</p>
              <p className="text-xs text-amber-700 mt-1">
                Backend connection returned: <code>{error}</code> (expected while waiting on <code>schema.sql</code>).
              </p>
            </div>
            <span className="text-xs font-bold uppercase tracking-wide bg-amber-200 text-amber-800 px-2 py-0.5 rounded">Mock Mode</span>
          </div>
        )}

        <div className="mb-6">
          <h2 className="text-lg font-semibold text-slate-900">Compliance Readiness Obligations</h2>
          <p className="text-sm text-slate-500">Live adherence monitoring evaluated against security incident logs.</p>
        </div>

        {loading ? (
          <div className="p-8 text-center text-slate-500">Evaluating compliance obligations...</div>
        ) : (
          <div className="grid gap-4 md:grid-cols-2">
            {data?.obligations?.map((obl) => {
              const statusObj = statusMap.get(obl.id);
              return (
                <div key={obl.id} className="bg-white p-5 rounded-xl border border-slate-200 shadow-xs flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between gap-4 mb-2">
                      <span className="text-xs font-mono font-semibold text-slate-400 uppercase">{obl.id}</span>
                      {getStatusBadge(statusObj?.status)}
                    </div>
                    <h3 className="font-medium text-slate-900 text-base">{obl.title}</h3>
                    <p className="text-xs text-slate-600 mt-1">{obl.description}</p>
                  </div>
                  <div className="mt-4 pt-3 border-t border-slate-100 text-xs">
                    <span className="font-semibold text-slate-500">Result: </span>
                    <span className="text-slate-700">{statusObj?.detail || "No evaluation details provided."}</span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </main>
    </div>
  );
}
