import React, { useState } from "react";

const INITIAL_FORM = {
  sender_claimed: "",
  sender_actual: "",
  subject: "",
  link: "",
  message_body: "",
};

export default function ReportForm() {
  const [formData, setFormData] = useState(INITIAL_FORM);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const getSeverityStyles = (severity = "safe") => {
    switch (severity.toLowerCase()) {
      case "high":
        return "bg-red-50 text-red-700 border-red-200";
      case "medium":
        return "bg-amber-50 text-amber-700 border-amber-200";
      default:
        return "bg-emerald-50 text-emerald-700 border-emerald-200";
    }
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const response = await fetch("/reports", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sender_claimed: formData.sender_claimed,
          sender_actual: formData.sender_actual,
          subject: formData.subject,
          link: formData.link,
          body: formData.message_body,
        }),
      });

      if (!response.ok) {
        throw new Error(`Server returned ${response.status}`);
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      setError(err.message || "Failed to submit report");
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    setFormData(INITIAL_FORM);
    setResult(null);
    setError(null);
  };

  if (result) {
    const hasLink = Boolean(result.link && result.link.trim());
    const hasAttachment = Boolean(result.attachment_filename && result.attachment_filename.trim());
    const isSuspicious = result.risk_score >= 40 || result.verdict?.toLowerCase() === "phishing";

    return (
      <section className="bg-white rounded-2xl shadow-sm border border-stone-200 overflow-hidden">
        <div className="bg-emerald-700 px-6 py-4">
          <h2 className="text-lg font-semibold text-white">
            Report Submitted Successfully
          </h2>
          <p className="text-emerald-100 text-sm mt-1">
            Automated multi-layer analysis completed
          </p>
        </div>

        <div className="p-6 space-y-6">
          {/* Top Score Banner */}
          <div className="flex flex-wrap items-center justify-between gap-3 p-4 bg-stone-50 rounded-xl border border-stone-200">
            <div className="flex items-center gap-3">
              <span className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-bold tracking-wide border uppercase ${getSeverityStyles(result.severity)}`}>
                {result.severity || "SAFE"} RISK
              </span>
              <span className="text-stone-700 text-sm">
                Verdict: <strong className="text-stone-900 capitalize">{result.verdict}</strong>
              </span>
            </div>
            <span className="text-stone-600 text-sm font-medium">
              Risk Score: <span className="text-stone-900 font-bold">{result.risk_score}</span> / 100
            </span>
          </div>

          {/* Breakdown Cards */}
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-stone-500 mb-3">
              Detection Layer Breakdown
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {/* Layer 1: Text & Content Check */}
              <div className="p-3 bg-stone-50 rounded-lg border border-stone-200 text-sm">
                <div className="flex items-center justify-between mb-1">
                  <span className="font-medium text-stone-700">Content & Sender</span>
                  <span className={`text-xs px-2 py-0.5 rounded font-semibold ${isSuspicious ? "bg-amber-100 text-amber-800" : "bg-emerald-100 text-emerald-800"}`}>
                    {isSuspicious ? "Flagged" : "Normal"}
                  </span>
                </div>
                <p className="text-xs text-stone-500">Heuristics, lure keywords, domain verification.</p>
              </div>

              {/* Layer 2: Safe Browsing Link Check */}
              <div className="p-3 bg-stone-50 rounded-lg border border-stone-200 text-sm">
                <div className="flex items-center justify-between mb-1">
                  <span className="font-medium text-stone-700">Link Scanner</span>
                  <span className={`text-xs px-2 py-0.5 rounded font-semibold ${hasLink ? (isSuspicious ? "bg-red-100 text-red-800" : "bg-emerald-100 text-emerald-800") : "bg-stone-200 text-stone-600"}`}>
                    {hasLink ? (isSuspicious ? "Suspicious" : "Clean") : "No URL"}
                  </span>
                </div>
                <p className="text-xs text-stone-500 font-mono truncate">
                  {hasLink ? result.link : "No external URL submitted"}
                </p>
              </div>

              {/* Layer 3: File Attachment Check */}
              <div className="p-3 bg-stone-50 rounded-lg border border-stone-200 text-sm">
                <div className="flex items-center justify-between mb-1">
                  <span className="font-medium text-stone-700">Attachment</span>
                  <span className={`text-xs px-2 py-0.5 rounded font-semibold ${hasAttachment ? "bg-emerald-100 text-emerald-800" : "bg-stone-200 text-stone-600"}`}>
                    {hasAttachment ? "Inspected" : "None"}
                  </span>
                </div>
                <p className="text-xs text-stone-500 font-mono truncate">
                  {hasAttachment ? result.attachment_filename : "No attachment included"}
                </p>
              </div>
            </div>
          </div>

          {/* Triggered Reasons */}
          {result.reasons && result.reasons.length > 0 && (
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-stone-500 mb-2">
                Flagged Signals ({result.reasons.length})
              </h3>
              <ul className="space-y-1.5">
                {result.reasons.map((reason, index) => (
                  <li
                    key={index}
                    className="text-xs text-stone-700 bg-red-50/50 rounded-md px-3 py-2 border border-red-100 flex items-start gap-2"
                  >
                    <span className="text-red-500 font-bold">•</span>
                    <span>{reason}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <button
            onClick={handleReset}
            className="w-full sm:w-auto bg-emerald-700 hover:bg-emerald-800 text-white font-medium px-5 py-2.5 rounded-lg text-sm transition shadow-sm"
          >
            Report Another Email
          </button>
        </div>
      </section>
    );
  }

  return (
    <section className="bg-white rounded-2xl shadow-sm border border-stone-200 overflow-hidden">
      <div className="bg-emerald-800 px-6 py-4">
        <h2 className="text-lg font-semibold text-white">Report a Suspicious Email</h2>
        <p className="text-emerald-100 text-sm mt-1">Help protect your institution — it only takes a minute</p>
      </div>

      <form onSubmit={handleSubmit} className="p-6 space-y-4">
        <div>
          <label className="block text-xs font-semibold uppercase tracking-wider text-stone-600 mb-1">
            Claimed Sender (who it says it's from)
          </label>
          <input
            type="text"
            name="sender_claimed"
            value={formData.sender_claimed}
            onChange={handleChange}
            placeholder="e.g. IT Support <support@company.com>"
            className="w-full px-3 py-2 rounded-lg border border-stone-300 text-sm focus:outline-none focus:ring-2 focus:ring-emerald-500"
            required
          />
        </div>

        <div>
          <label className="block text-xs font-semibold uppercase tracking-wider text-stone-600 mb-1">
            Real Sender Address
          </label>
          <input
            type="text"
            name="sender_actual"
            value={formData.sender_actual}
            onChange={handleChange}
            placeholder="e.g. attacker@malicious-domain.com"
            className="w-full px-3 py-2 rounded-lg border border-stone-300 text-sm focus:outline-none focus:ring-2 focus:ring-emerald-500"
            required
          />
        </div>

        <div>
          <label className="block text-xs font-semibold uppercase tracking-wider text-stone-600 mb-1">
            Subject
          </label>
          <input
            type="text"
            name="subject"
            value={formData.subject}
            onChange={handleChange}
            placeholder="Email subject line"
            className="w-full px-3 py-2 rounded-lg border border-stone-300 text-sm focus:outline-none focus:ring-2 focus:ring-emerald-500"
            required
          />
        </div>

        <div>
          <label className="block text-xs font-semibold uppercase tracking-wider text-stone-600 mb-1">
            Suspicious Link (if any)
          </label>
          <input
            type="url"
            name="link"
            value={formData.link}
            onChange={handleChange}
            placeholder="https://..."
            className="w-full px-3 py-2 rounded-lg border border-stone-300 text-sm focus:outline-none focus:ring-2 focus:ring-emerald-500"
          />
        </div>

        <div>
          <label className="block text-xs font-semibold uppercase tracking-wider text-stone-600 mb-1">
            Message Body
          </label>
          <textarea
            name="message_body"
            rows="4"
            value={formData.message_body}
            onChange={handleChange}
            placeholder="Paste the email content or suspicious message here..."
            className="w-full px-3 py-2 rounded-lg border border-stone-300 text-sm focus:outline-none focus:ring-2 focus:ring-emerald-500"
            required
          />
        </div>

        {error && (
          <div className="p-3 bg-red-50 text-red-700 border border-red-200 rounded-lg text-sm">
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={loading}
          className="w-full sm:w-auto bg-emerald-700 hover:bg-emerald-800 disabled:bg-stone-300 text-white font-medium px-6 py-2.5 rounded-lg text-sm transition shadow-sm"
        >
          {loading ? "Analyzing Email..." : "Submit Report"}
        </button>
      </form>
    </section>
  );
}
