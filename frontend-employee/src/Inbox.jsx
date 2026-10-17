import React from "react";

function Inbox({ onSelectSample }) {
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
