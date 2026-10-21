import React, { useCallback, useEffect, useState } from "react";

function Inbox({ onSelectSample }) {
  const [receivedEmails, setReceivedEmails] = useState([]);
  const [receivedLoading, setReceivedLoading] = useState(true);
  const [receivedError, setReceivedError] = useState("");
  const [expandedEmail, setExpandedEmail] = useState(null);

  const loadReceivedEmails = useCallback(async () => {
    setReceivedLoading(true);
    setReceivedError("");
    try {
      const response = await fetch("/inbound-emails?limit=50");
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || `Inbox request failed (${response.status}).`);
      if (!Array.isArray(data)) throw new Error("The inbox returned an unexpected response.");
      setReceivedEmails(data);
    } catch (error) {
      setReceivedError(error.message || "Could not load received emails.");
    } finally {
      setReceivedLoading(false);
    }
  }, []);

  useEffect(() => { loadReceivedEmails(); }, [loadReceivedEmails]);

  const emails = [
    {
      id: 1,
      sender: "hr@ethiosecure-bank.com",
      subject: "Urgent: Verify Your Payroll Account",
      preview: "Your payroll account requires immediate verification to avoid salary suspension. Please follow the link below to verify your credentials.",
      link: "https://payroll-verify.ethiosecure-bank.internal-auth.com",
      isSuspicious: true,
      tag: "Impersonation",
    },
    {
      id: 2,
      sender: "it-support@company.com",
      subject: "Scheduled Maintenance Notice",
      preview: "Our IT team will be performing regular server updates this Saturday from 02:00 to 04:00 UTC. No password or personal detail updates are requested.",
      link: "",
      isSuspicious: false,
      tag: "Legitimate",
    },
    {
      id: 3,
      sender: "billing@telebirr-service.com",
      subject: "Invoice Payment Failed - Action Required",
      preview: "We were unable to process your transaction of 4,500 ETB. Click here immediately to settle your bill and avoid termination of service.",
      link: "https://telebirr-pay-recovery.net/portal",
      isSuspicious: true,
      tag: "Financial Phish",
    },
  ];

  return (
    <section className="space-y-4">
      <div className="rounded-xl border border-emerald-200 bg-white p-4">
        <div className="mb-3 flex items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-bold text-stone-900">Emails received by PhishWatch</h2>
            <p className="mt-1 text-xs text-stone-500">Messages delivered through the configured Resend inbox. New messages appear after the webhook saves them.</p>
          </div>
          <button type="button" onClick={loadReceivedEmails} disabled={receivedLoading} className="shrink-0 rounded-lg bg-emerald-700 px-3 py-2 text-xs font-bold text-white disabled:opacity-60">
            {receivedLoading ? "Refreshing…" : "Refresh"}
          </button>
        </div>

        {receivedError && <p role="alert" className="rounded-lg bg-red-50 p-3 text-xs text-red-700">{receivedError}</p>}
        {!receivedError && receivedLoading && <p className="text-xs text-stone-500">Loading received messages…</p>}
        {!receivedError && !receivedLoading && receivedEmails.length === 0 && (
          <p className="rounded-lg bg-stone-50 p-3 text-xs text-stone-600">No Resend emails have been received yet. Send a message to the configured receiving address, then refresh.</p>
        )}

        <div className="space-y-3">
          {receivedEmails.map((email) => {
            const auth = email.sender_authentication?.results || {};
            const isExpanded = expandedEmail === email.id;
            return (
              <article key={email.id} className="rounded-xl border border-stone-200 p-3">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div className="min-w-0">
                    <p className="break-all text-xs font-semibold text-stone-700">{email.sender_actual || "Unknown sender"}</p>
                    <h3 className="mt-1 text-sm font-bold text-stone-900">{email.subject || "(no subject)"}</h3>
                    <p className="mt-1 text-[11px] text-stone-500">Received {email.created_at ? new Date(email.created_at).toLocaleString() : "time unavailable"} · Report #{email.id}</p>
                  </div>
                  <span className={`rounded-full px-2 py-1 text-[11px] font-bold ${email.severity === "high" ? "bg-red-100 text-red-800" : email.severity === "medium" ? "bg-amber-100 text-amber-800" : "bg-emerald-100 text-emerald-800"}`}>
                    {email.severity || "Unknown"} risk · {email.risk_score ?? "—"}/100
                  </span>
                </div>
                <div className="mt-3 flex flex-wrap gap-2 text-[11px]">
                  {["spf", "dkim", "dmarc"].map((method) => (
                    <span key={method} className="rounded-md bg-stone-100 px-2 py-1 text-stone-700">{method.toUpperCase()}: {auth[method] || "not available"}</span>
                  ))}
                </div>
                <button type="button" aria-expanded={isExpanded} onClick={() => setExpandedEmail(isExpanded ? null : email.id)} className="mt-3 text-xs font-bold text-emerald-800">
                  {isExpanded ? "Hide message and analysis" : "View message and analysis"}
                </button>
                {isExpanded && (
                  <div className="mt-3 space-y-3 border-t border-stone-100 pt-3">
                    <div><h4 className="text-xs font-bold text-stone-700">Message body</h4><pre className="mt-1 whitespace-pre-wrap break-words rounded-lg bg-stone-50 p-3 text-xs text-stone-700">{email.message_body || "No message body captured."}</pre></div>
                    {email.attachment_filename && <p className="text-xs text-stone-600">Attachment: {email.attachment_filename} (filename recorded; content is not displayed here)</p>}
                    <div><h4 className="text-xs font-bold text-stone-700">Detection reasons and coverage</h4><ul className="mt-1 list-disc space-y-1 pl-5 text-xs leading-relaxed text-stone-600">{(email.reasons || []).map((reason, index) => <li key={`${index}-${reason}`}>{reason}</li>)}</ul></div>
                    <p className="text-[11px] text-stone-500">SPF/DKIM/DMARC values are reported by the receiving mail system and were not independently verified by PhishWatch.</p>
                  </div>
                )}
              </article>
            );
          })}
        </div>
      </div>

      {/* Contextual Training Banner */}
      <div className="bg-amber-50 border border-amber-200 rounded-xl p-3.5 flex items-start gap-3">
        <span className="text-xl">💡</span>
        <div className="text-xs text-amber-900 leading-relaxed">
          <strong>Interactive Training Simulation:</strong> These are simulated incoming emails. Tap <strong>"Report to SOC"</strong> on any suspicious item to instantly push it into the analyzer form.
        </div>
      </div>

      <div className="space-y-3">
        {emails.map((email) => (
          <article
            key={email.id}
            className={`bg-white rounded-xl p-4 border transition-all ${
              email.isSuspicious
                ? "border-amber-300 shadow-sm"
                : "border-stone-200"
            }`}
          >
            <div className="flex items-center justify-between gap-2 mb-2">
              <span className="text-xs font-mono font-semibold text-stone-600 truncate max-w-[200px] sm:max-w-xs">
                {email.sender}
              </span>
              <span
                className={`text-[11px] font-bold px-2 py-0.5 rounded-full ${
                  email.isSuspicious
                    ? "bg-amber-100 text-amber-800"
                    : "bg-stone-100 text-stone-600"
                }`}
              >
                {email.tag}
              </span>
            </div>

            <h3 className="text-sm font-bold text-stone-900 mb-1 leading-snug">
              {email.subject}
            </h3>

            <p className="text-xs text-stone-500 line-clamp-2 mb-3">
              {email.preview}
            </p>

            <div className="flex items-center justify-between pt-2 border-t border-stone-100">
              <span className="text-[11px] text-stone-400 font-medium">
                {email.isSuspicious ? "⚠ Action needed" : "✓ Normal notice"}
              </span>
              <button
                type="button"
                onClick={() => onSelectSample(email)}
                className={`text-xs font-bold px-3 py-1.5 rounded-lg transition-colors ${
                  email.isSuspicious
                    ? "bg-amber-600 hover:bg-amber-700 text-white"
                    : "bg-stone-100 hover:bg-stone-200 text-stone-700"
                }`}
              >
                {email.isSuspicious ? "Report to SOC →" : "Test Scan →"}
              </button>
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}

export default Inbox;
