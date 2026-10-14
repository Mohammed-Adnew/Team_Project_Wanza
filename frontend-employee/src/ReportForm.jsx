import { useState } from "react";

function ReportForm() {
  const [formData, setFormData] = useState({
    claimedSender: "",
    realSender: "",
    subject: "",
    link: "",
    messageBody: "",
  });

  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  // ============================================
  // TEMPORARY MOCK FLAG
  // Change this to false when the real backend is reachable
  // ============================================
  const USE_MOCK = true;

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError(null);
    setResult(null);

    // ---------- MOCK MODE (current) ----------
    if (USE_MOCK) {
      // Simulate network delay
      await new Promise((resolve) => setTimeout(resolve, 1100));

      const mockResult = {
        severity: "high",
        verdict: "Phishing",
        risk_score: 87,
        reasons: [
          "Urgent language detected (“within 24 hours”, “account will be suspended”)",
          "Sender domain does not match claimed organization",
          "Suspicious shortened link (bit.ly)",
          "Requests for credentials / password confirmation",
        ],
      };

      setResult(mockResult);
      setIsLoading(false);
      return;
    }

    // ---------- REAL BACKEND CALL (for later) ----------
    const payload = {
      sender_claimed: formData.claimedSender,
      sender_actual: formData.realSender,
      subject: formData.subject,
      message_body: formData.messageBody,
      link: formData.link || null,
      source: "employee",
    };

    try {
      // Change this URL later when you have the correct backend address
      const response = await fetch("http://10.22.194.110:5000/reports", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Something went wrong");
      }

      setResult(data);
    } catch (err) {
      setError(err.message || "Failed to submit report. Is the backend running?");
    } finally {
      setIsLoading(false);
    }
  };

  const handleReset = () => {
    setFormData({
      claimedSender: "",
      realSender: "",
      subject: "",
      link: "",
      messageBody: "",
    });
    setResult(null);
    setError(null);
  };

  const getSeverityStyles = (severity) => {
    switch (severity) {
      case "high":
        return "bg-red-100 text-red-800 border-red-200";
      case "medium":
        return "bg-amber-100 text-amber-800 border-amber-200";
      case "low":
        return "bg-green-100 text-green-800 border-green-200";
      default:
        return "bg-stone-100 text-stone-800 border-stone-200";
    }
  };

  // ========== RESULT SCREEN ==========
  if (result) {
    return (
      <section className="bg-white rounded-2xl shadow-sm border border-stone-200 overflow-hidden">
        <div className="bg-green-700 px-6 py-4">
          <h2 className="text-lg font-semibold text-white">
            Report Submitted Successfully
          </h2>
          <p className="text-green-100 text-sm mt-1">
            Here is the analysis of the email you reported
          </p>
        </div>

        <div className="p-6 space-y-5">
          <div className="flex flex-wrap items-center gap-3">
            <span
              className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium border ${getSeverityStyles(
                result.severity
              )}`}
            >
              {result.severity?.toUpperCase()} RISK
            </span>
            <span className="text-stone-600 text-sm">
              Verdict: <strong className="text-stone-800">{result.verdict}</strong>
            </span>
            <span className="text-stone-500 text-sm">
              Score: {result.risk_score}/100
            </span>
          </div>

          {result.reasons && result.reasons.length > 0 && (
            <div>
              <h3 className="text-sm font-medium text-stone-700 mb-2">
                Why this was flagged:
              </h3>
              <ul className="space-y-2">
                {result.reasons.map((reason, index) => (
                  <li
                    key={index}
                    className="text-sm text-stone-600 bg-stone-50 rounded-lg px-3 py-2 border border-stone-100"
                  >
                    {reason}
                  </li>
                ))}
              </ul>
            </div>
          )}

          <button
            onClick={handleReset}
            className="mt-4 bg-green-700 hover:bg-green-800 text-white font-medium px-5 py-2.5 rounded-lg transition"
          >
            Report Another Email
          </button>
        </div>
      </section>
    );
  }

  // ========== FORM ==========
  return (
    <section className="bg-white rounded-2xl shadow-sm border border-stone-200 overflow-hidden">
      <div className="bg-green-700 px-6 py-4">
        <h2 className="text-lg font-semibold text-white">
          Report a Suspicious Email
        </h2>
        <p className="text-green-100 text-sm mt-1">
          Help protect your institution — it only takes a minute
        </p>
      </div>

      <form onSubmit={handleSubmit} className="p-6 space-y-5">
        <div>
          <label className="block text-sm font-medium text-stone-700 mb-1.5">
            Claimed Sender <span className="text-stone-400">(who it says it’s from)</span>
          </label>
          <input
            type="text"
            name="claimedSender"
            value={formData.claimedSender}
            onChange={handleChange}
            placeholder="e.g. Commercial Bank of Ethiopia or Telebirr Support"
            className="w-full rounded-lg border border-stone-300 px-3.5 py-2.5 text-stone-800 placeholder:text-stone-400 focus:outline-none focus:ring-2 focus:ring-green-600 focus:border-transparent transition"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-stone-700 mb-1.5">
            Real Sender Address
          </label>
          <input
            type="text"
            name="realSender"
            value={formData.realSender}
            onChange={handleChange}
            placeholder="e.g. alerts@cbe-secure-verify.com"
            className="w-full rounded-lg border border-stone-300 px-3.5 py-2.5 text-stone-800 placeholder:text-stone-400 focus:outline-none focus:ring-2 focus:ring-green-600 focus:border-transparent transition"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-stone-700 mb-1.5">
            Subject
          </label>
          <input
            type="text"
            name="subject"
            value={formData.subject}
            onChange={handleChange}
            placeholder="Email subject line"
            required
            className="w-full rounded-lg border border-stone-300 px-3.5 py-2.5 text-stone-800 placeholder:text-stone-400 focus:outline-none focus:ring-2 focus:ring-green-600 focus:border-transparent transition"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-stone-700 mb-1.5">
            Suspicious Link <span className="text-stone-400">(if any)</span>
          </label>
          <input
            type="text"
            name="link"
            value={formData.link}
            onChange={handleChange}
            placeholder="Paste the full link here"
            className="w-full rounded-lg border border-stone-300 px-3.5 py-2.5 text-stone-800 placeholder:text-stone-400 focus:outline-none focus:ring-2 focus:ring-green-600 focus:border-transparent transition"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-stone-700 mb-1.5">
            Message Body
          </label>
          <textarea
            name="messageBody"
            value={formData.messageBody}
            onChange={handleChange}
            rows="4"
            placeholder="Paste the full email content here..."
            required
            className="w-full rounded-lg border border-stone-300 px-3.5 py-2.5 text-stone-800 placeholder:text-stone-400 focus:outline-none focus:ring-2 focus:ring-green-600 focus:border-transparent transition resize-none"
          />
        </div>

        {error && (
          <div className="text-sm text-red-700 bg-red-50 border border-red-200 rounded-lg px-4 py-3">
            {error}
          </div>
        )}

        <div className="pt-2">
          <button
            type="submit"
            disabled={isLoading}
            className="w-full sm:w-auto bg-green-700 hover:bg-green-800 disabled:bg-green-400 text-white font-medium px-6 py-2.5 rounded-lg transition shadow-sm focus:outline-none focus:ring-2 focus:ring-green-600 focus:ring-offset-2"
          >
            {isLoading ? "Analyzing email..." : "Submit Report"}
          </button>
        </div>
      </form>
    </section>
  );
}

export default ReportForm;