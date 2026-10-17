import React, { useState, useEffect } from "react";

const INITIAL_FORM = {
  sender_claimed: "",
  sender_actual: "",
  subject: "",
  link: "",
  message_body: "",
};

export default function ReportForm({ initialData }) {
  const [formData, setFormData] = useState(INITIAL_FORM);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (initialData) {
      setFormData(initialData);
      setResult(null);
      setError(null);
    }
  }, [initialData]);

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
    setResult(null);

    try {
      const response = await fetch("/inbox/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formData),
      });

      if (!response.ok) {
        throw new Error(`Server returned error code ${response.status}`);
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      setError(err.message || "Failed to submit report. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-white rounded-2xl shadow-sm border border-stone-200 overflow-hidden">
      {/* Compact Header */}
      <div className="bg-emerald-800 text-white p-4 sm:p-5">
        <h2 className="text-base sm:text-lg font-bold">Report a Suspicious Email</h2>
        <p className="text-xs text-emerald-100 font-medium mt-0.5">
          Submit suspicious headers, sender info, or lure links for automated SOC triage.
        </p>
      </div>

      <div className="p-4 sm:p-6">
        {error && (
          <div className="mb-4 p-3 bg-red-50 border border-red-200 text-red-700 rounded-xl text-xs font-semibold">
            {error}
          </div>
        )}

        {result ? (
          <div className="space-y-4">
            <div className={`p-4 rounded-xl border ${getSeverityStyles(result.severity)}`}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-extrabold uppercase tracking-wider">
                  Verdict: {result.verdict || "Completed"}
                </span>
                <span className="text-xs font-extrabold px-2.5 py-0.5 rounded-full bg-white/70 border border-current">
                  Risk Score: {result.risk_score ?? 0} / 100
                </span>
              </div>
              <p className="text-xs font-medium leading-relaxed">
                {result.summary || "Your submission was evaluated by automated heuristics and logged directly to the analyst queue."}
              </p>
            </div>

            <button
              type="button"
              onClick={() => {
                setResult(null);
                setFormData(INITIAL_FORM);
              }}
              className="w-full py-2.5 bg-stone-100 hover:bg-stone-200 text-stone-800 text-xs font-bold rounded-xl transition"
            >
              ↺ Report Another Email
            </button>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-3.5">
            {/* Sender row (compact side-by-side on tablet/desktop) */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-bold text-stone-700 mb-1">
                  Claimed Sender
                </label>
                <input
                  type="text"
                  name="sender_claimed"
                  value={formData.sender_claimed}
                  onChange={handleChange}
                  placeholder="e.g. IT Helpdesk"
                  className="w-full px-3 py-2 text-xs border border-stone-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-emerald-600 focus:border-transparent font-medium"
                />
              </div>

              <div>
                <label className="block text-xs font-bold text-stone-700 mb-1">
                  Actual Sender Email *
                </label>
                <input
                  type="email"
                  name="sender_actual"
                  required
                  value={formData.sender_actual}
                  onChange={handleChange}
                  placeholder="e.g. attacker@malicious-domain.com"
                  className="w-full px-3 py-2 text-xs border border-stone-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-emerald-600 focus:border-transparent font-medium"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-bold text-stone-700 mb-1">
                Subject Line *
              </label>
              <input
                type="text"
                name="subject"
                required
                value={formData.subject}
                onChange={handleChange}
                placeholder="e.g. Urgent: Account Verification Required"
                className="w-full px-3 py-2 text-xs border border-stone-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-emerald-600 focus:border-transparent font-medium"
              />
            </div>

            <div>
              <label className="block text-xs font-bold text-stone-700 mb-1">
                Suspicious Link (If Any)
              </label>
              <input
                type="text"
                name="link"
                value={formData.link}
                onChange={handleChange}
                placeholder="e.g. https://login-recovery.net/session"
                className="w-full px-3 py-2 text-xs border border-stone-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-emerald-600 focus:border-transparent font-medium"
              />
            </div>

            <div>
              <label className="block text-xs font-bold text-stone-700 mb-1">
                Message Body *
              </label>
              <textarea
                name="message_body"
                required
                rows="4"
                value={formData.message_body}
                onChange={handleChange}
                placeholder="Paste the email content or suspicious message here..."
                className="w-full px-3 py-2 text-xs border border-stone-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-emerald-600 focus:border-transparent font-medium"
              ></textarea>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full mt-2 py-3 bg-emerald-700 hover:bg-emerald-800 disabled:bg-emerald-400 text-white font-bold text-xs sm:text-sm rounded-xl shadow-sm transition"
            >
              {loading ? "Analyzing Threats & Submitting..." : "Submit Incident Report"}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
