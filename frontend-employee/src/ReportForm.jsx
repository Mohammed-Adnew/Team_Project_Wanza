import { useState } from "react";

function ReportForm() {
  const [formData, setFormData] = useState({
    claimedSender: "",
    realSender: "",
    subject: "",
    link: "",
    messageBody: "",
  });

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    console.log("Form data ready to send later:", formData);

    alert(
      `Report captured!\n\n` +
        `Claimed Sender: ${formData.claimedSender}\n` +
        `Real Sender: ${formData.realSender}\n` +
        `Subject: ${formData.subject}\n` +
        `Link: ${formData.link}\n` +
        `Message: ${formData.messageBody.substring(0, 50)}...`,
    );
  };

  return (
    <section className="bg-white rounded-2xl shadow-sm border border-stone-200 overflow-hidden">
      {/* Form Header */}
      <div className="bg-green-700 px-6 py-4">
        <h2 className="text-lg font-semibold text-white">
          Report a Suspicious Email
        </h2>
        <p className="text-green-100 text-sm mt-1">
          Help protect your institution — it only takes a minute
        </p>
      </div>

      {/* Form Body */}
      <form onSubmit={handleSubmit} className="p-6 space-y-5">
        <div>
          <label className="block text-sm font-medium text-stone-700 mb-1.5">
            Claimed Sender{" "}
            <span className="text-stone-400">(who it says it’s from)</span>
          </label>
          <input
            type="text"
            name="claimedSender"
            value={formData.claimedSender}
            onChange={handleChange}
            placeholder="e.g. HR Department or Telebirr Support"
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
            placeholder="e.g. hr@fake-domain.com"
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
            className="w-full rounded-lg border border-stone-300 px-3.5 py-2.5 text-stone-800 placeholder:text-stone-400 focus:outline-none focus:ring-2 focus:ring-green-600 focus:border-transparent transition resize-none"
          />
        </div>

        <div className="pt-2">
          <button
            type="submit"
            className="w-full sm:w-auto bg-green-700 hover:bg-green-800 text-white font-medium px-6 py-2.5 rounded-lg transition shadow-sm hover:shadow focus:outline-none focus:ring-2 focus:ring-green-600 focus:ring-offset-2"
          >
            Submit Report
          </button>
        </div>
      </form>
    </section>
  );
}

export default ReportForm;
