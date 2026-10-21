import React, { useEffect, useState } from "react";

const INITIAL_FORM = {
  sender_claimed: "",
  sender_actual: "",
  subject: "",
  link: "",
  message_body: "",
  authentication_results: "",
};

const MAX_FILE_BYTES = 10 * 1024 * 1024;

export default function ReportForm({ initialData }) {
  const [formData, setFormData] = useState(INITIAL_FORM);
  const [attachment, setAttachment] = useState(null);
  const [shareWithVirusTotal, setShareWithVirusTotal] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (initialData) {
      setFormData((previous) => ({ ...previous, ...initialData }));
      setResult(null);
      setError(null);
    }
  }, [initialData]);

  const getSeverityStyles = (severity = "low") => {
    switch (severity.toLowerCase()) {
      case "high":
        return "bg-red-50 text-red-700 border-red-200";
      case "medium":
        return "bg-amber-50 text-amber-700 border-amber-200";
      default:
        return "bg-emerald-50 text-emerald-700 border-emerald-200";
    }
  };

  const handleChange = (event) => {
    const { name, value } = event.target;
    setFormData((previous) => ({ ...previous, [name]: value }));
  };

  const handleAttachment = (event) => {
    const file = event.target.files?.[0] || null;
    setError(null);
    if (file && file.size > MAX_FILE_BYTES) {
      setAttachment(null);
      event.target.value = "";
      setError("Attachments must be 10 MB or smaller.");
      return;
    }
    setAttachment(file);
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const payload = new FormData();
      Object.entries(formData).forEach(([key, value]) => payload.append(key, value));
      if (attachment) payload.append("attachment", attachment);
      if (shareWithVirusTotal) payload.append("share_with_virustotal", "true");

      const response = await fetch("/reports", { method: "POST", body: payload });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(data.error || `Could not submit the report (HTTP ${response.status}).`);
      }
      setResult(data);
    } catch (err) {
      setError(err.message || "Failed to submit report. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const startAnotherReport = () => {
    setResult(null);
    setError(null);
    setFormData(INITIAL_FORM);
    setAttachment(null);
    setShareWithVirusTotal(false);
  };

  return (
    <div className="overflow-hidden rounded-2xl border border-stone-200 bg-white shadow-sm">
      <div className="bg-emerald-800 p-4 text-white sm:p-5">
        <h2 className="text-base font-bold sm:text-lg">Report a Suspicious Email</h2>
        <p className="mt-0.5 text-xs font-medium text-emerald-100">
          Submit the message and optional attachment for automated security triage.
        </p>
      </div>

      <div className="p-4 sm:p-6">
        {error && (
          <div role="alert" className="mb-4 rounded-xl border border-red-200 bg-red-50 p-3 text-xs font-semibold text-red-700">
            {error}
          </div>
        )}

        {result ? (
          <div className="space-y-4">
            <div className={`rounded-xl border p-4 ${getSeverityStyles(result.severity)}`}>
              <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                <span className="text-xs font-extrabold uppercase tracking-wider">
                  {result.verdict || "Report submitted"}
                </span>
                <span className="rounded-full border border-current bg-white/70 px-2.5 py-0.5 text-xs font-extrabold">
                  Risk score: {result.risk_score ?? "—"} / 100
                </span>
              </div>
              <p className="text-xs font-medium leading-relaxed">
                Report #{result.id} was saved for analyst review. Automated checks can miss threats; a low score does not guarantee that a message is safe.
              </p>
            </div>

            {Array.isArray(result.reasons) && result.reasons.length > 0 && (
              <section aria-label="Detection results" className="rounded-xl border border-stone-200 bg-stone-50 p-4">
                <h3 className="mb-2 text-xs font-bold text-stone-800">Checks and coverage</h3>
                <ul className="space-y-2 text-xs leading-relaxed text-stone-700">
                  {result.reasons.map((reason, index) => <li key={`${index}-${reason}`}>{reason}</li>)}
                </ul>
              </section>
            )}

            <section aria-label="Sender authentication results" className="rounded-xl border border-stone-200 bg-white p-4">
              <h3 className="mb-2 text-xs font-bold text-stone-800">Sender authentication</h3>
              <div className="grid grid-cols-3 gap-2 text-xs">
                {["spf", "dkim", "dmarc"].map((method) => (
                  <div key={method} className="rounded-lg bg-stone-50 p-2">
                    <span className="block font-bold uppercase text-stone-600">{method}</span>
                    <span className="mt-1 block break-words text-stone-800">{result.sender_authentication?.results?.[method] || "not available"}</span>
                  </div>
                ))}
              </div>
              <p className="mt-2 text-[11px] leading-relaxed text-stone-500">
                Source: {result.sender_authentication?.source || "not supplied or not parseable"}. These reported header values are not independently verified by PhishWatch.
              </p>
            </section>

            <button type="button" onClick={startAnotherReport} className="w-full rounded-xl bg-stone-100 py-2.5 text-xs font-bold text-stone-800 transition hover:bg-stone-200">
              ↺ Report Another Email
            </button>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-3.5">
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div>
                <label htmlFor="sender_claimed" className="mb-1 block text-xs font-bold text-stone-700">Claimed sender or organization</label>
                <input id="sender_claimed" type="text" name="sender_claimed" value={formData.sender_claimed} onChange={handleChange} placeholder="e.g. IT Helpdesk" className="w-full rounded-lg border border-stone-300 px-3 py-2 text-xs font-medium focus:border-transparent focus:outline-none focus:ring-2 focus:ring-emerald-600" />
              </div>
              <div>
                <label htmlFor="sender_actual" className="mb-1 block text-xs font-bold text-stone-700">Actual sender email</label>
                <input id="sender_actual" type="email" name="sender_actual" value={formData.sender_actual} onChange={handleChange} placeholder="e.g. sender@example.com" className="w-full rounded-lg border border-stone-300 px-3 py-2 text-xs font-medium focus:border-transparent focus:outline-none focus:ring-2 focus:ring-emerald-600" />
              </div>
            </div>

            <div>
              <label htmlFor="subject" className="mb-1 block text-xs font-bold text-stone-700">Subject line</label>
              <input id="subject" type="text" name="subject" value={formData.subject} onChange={handleChange} placeholder="e.g. Urgent: Account Verification Required" className="w-full rounded-lg border border-stone-300 px-3 py-2 text-xs font-medium focus:border-transparent focus:outline-none focus:ring-2 focus:ring-emerald-600" />
            </div>

            <div>
              <label htmlFor="link" className="mb-1 block text-xs font-bold text-stone-700">Suspicious link, if present</label>
              <input id="link" type="url" name="link" value={formData.link} onChange={handleChange} placeholder="https://example.com/..." className="w-full rounded-lg border border-stone-300 px-3 py-2 text-xs font-medium focus:border-transparent focus:outline-none focus:ring-2 focus:ring-emerald-600" />
              <p className="mt-1 text-[11px] text-stone-500">Links are checked by configured reputation services. The URL may be shared with those services.</p>
            </div>

            <div>
              <label htmlFor="message_body" className="mb-1 block text-xs font-bold text-stone-700">Email message</label>
              <textarea id="message_body" name="message_body" rows="4" value={formData.message_body} onChange={handleChange} placeholder="Paste the email text here..." className="w-full rounded-lg border border-stone-300 px-3 py-2 text-xs font-medium focus:border-transparent focus:outline-none focus:ring-2 focus:ring-emerald-600" />
            </div>

            <div>
              <label htmlFor="authentication_results" className="mb-1 block text-xs font-bold text-stone-700">Authentication-Results header, if available</label>
              <textarea id="authentication_results" name="authentication_results" rows="2" value={formData.authentication_results} onChange={handleChange} placeholder="Paste the Authentication-Results header from the original email" className="w-full rounded-lg border border-stone-300 px-3 py-2 text-xs font-medium focus:border-transparent focus:outline-none focus:ring-2 focus:ring-emerald-600" />
              <p className="mt-1 text-[11px] text-stone-500">This is reported evidence from the receiving mail system, not an independent PhishWatch verification.</p>
            </div>

            <div className="rounded-xl border border-stone-200 p-3">
              <label htmlFor="attachment" className="mb-1 block text-xs font-bold text-stone-700">Optional attachment</label>
              <input id="attachment" type="file" onChange={handleAttachment} className="block w-full text-xs text-stone-600 file:mr-3 file:rounded-lg file:border-0 file:bg-stone-100 file:px-3 file:py-2 file:text-xs file:font-semibold file:text-stone-800 hover:file:bg-stone-200" />
              <p className="mt-1 text-[11px] text-stone-500">Maximum 10 MB. The file is analyzed temporarily; PhishWatch does not save its contents in the report database. Without upload consent, VirusTotal receives only a hash lookup.</p>
              {attachment && (
                <label htmlFor="share_with_virustotal" className="mt-3 flex cursor-pointer items-start gap-2 text-xs leading-relaxed text-stone-700">
                  <input id="share_with_virustotal" type="checkbox" checked={shareWithVirusTotal} onChange={(event) => setShareWithVirusTotal(event.target.checked)} className="mt-0.5 accent-emerald-700" />
                  <span>I consent to sending this file to VirusTotal for analysis. This may share the sample with VirusTotal and its security partners. Upload also requires the backend administrator to enable it.</span>
                </label>
              )}
            </div>

            <button type="submit" disabled={loading} className="mt-2 w-full rounded-xl bg-emerald-700 py-3 text-xs font-bold text-white shadow-sm transition hover:bg-emerald-800 disabled:bg-emerald-400 sm:text-sm">
              {loading ? "Analyzing and submitting…" : "Submit Incident Report"}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
