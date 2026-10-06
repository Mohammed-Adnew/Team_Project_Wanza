function Inbox() {
  const emails = [
    {
      id: 1,
      sender: "hr@ethiosecure-bank.com",
      subject: "Urgent: Verify Your Payroll Account",
      preview:
        "Your payroll account requires immediate verification to avoid suspension...",
      isSuspicious: true,
    },
    {
      id: 2,
      sender: "it-support@company.com",
      subject: "Scheduled Maintenance Notice",
      preview:
        "Our IT team will be performing scheduled maintenance this weekend...",
      isSuspicious: false,
    },
    {
      id: 3,
      sender: "billing@telebirr-service.com",
      subject: "Invoice Payment Failed - Action Required",
      preview:
        "We were unable to process your last payment. Click here to update...",
      isSuspicious: true,
    },
  ];

  return (
    <section>
      <div className="flex items-center justify-between mb-5">
        <h2 className="text-lg font-semibold text-stone-800">Your Inbox</h2>
        <span className="text-xs text-stone-400">Sample emails</span>
      </div>

      <div className="space-y-3">
        {emails.map((email) => (
          <div
            key={email.id}
            className={`bg-white rounded-xl border p-4 shadow-sm hover:shadow transition-shadow ${
              email.isSuspicious
                ? "border-amber-200 border-l-4 border-l-amber-500"
                : "border-stone-200"
            }`}
          >
            <div className="flex justify-between items-start gap-3">
              <div className="min-w-0">
                <p className="text-xs text-stone-500 truncate">
                  {email.sender}
                </p>
                <p className="font-medium text-stone-800 mt-0.5">
                  {email.subject}
                </p>
                <p className="text-sm text-stone-600 mt-1 line-clamp-1">
                  {email.preview}
                </p>
              </div>

              {email.isSuspicious && (
                <span className="shrink-0 text-xs font-medium bg-amber-50 text-amber-700 px-2.5 py-1 rounded-full border border-amber-200">
                  Suspicious
                </span>
              )}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

export default Inbox;
