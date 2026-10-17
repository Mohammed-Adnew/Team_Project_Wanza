import React, { useState } from "react";
import Inbox from "./Inbox";
import ReportForm from "./ReportForm";

function App() {
  const [activeTab, setActiveTab] = useState("report");
  const [prefilledData, setPrefilledData] = useState(null);

  const handleSelectSample = (sampleEmail) => {
    setPrefilledData({
      sender_claimed: sampleEmail.sender,
      sender_actual: sampleEmail.sender,
      subject: sampleEmail.subject,
      link: sampleEmail.link || "https://secure-portal-verify.com/login",
      message_body: sampleEmail.preview,
    });
    setActiveTab("report");
  };

  return (
    <div className="min-h-screen bg-stone-50 text-stone-800">
      {/* Header */}
      <header className="bg-white border-b border-stone-200 shadow-sm sticky top-0 z-50">
        <div className="container mx-auto px-4 py-3 max-w-2xl">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="flex flex-col w-1.5 h-7 rounded-sm overflow-hidden">
                <div className="h-1/3 bg-green-600"></div>
                <div className="h-1/3 bg-yellow-400"></div>
                <div className="h-1/3 bg-red-600"></div>
              </div>
              <div>
                <h1 className="text-base sm:text-lg font-bold tracking-tight text-stone-900 leading-tight">
                  EthioSecure – Phish Watch
                </h1>
                <p className="text-xs text-stone-500 font-medium">Employee Reporting Portal</p>
              </div>
            </div>

            <span className="text-xs font-semibold px-2.5 py-1 bg-emerald-50 text-emerald-700 border border-emerald-200 rounded-full">
              ● Secure Gateway
            </span>
          </div>

          {/* Clean Mobile-First Navigation Tabs */}
          <div className="flex gap-2 mt-3 pt-2 border-t border-stone-100">
            <button
              onClick={() => setActiveTab("report")}
              className={`flex-1 py-2 text-xs sm:text-sm font-bold rounded-lg transition-all ${
                activeTab === "report"
                  ? "bg-emerald-700 text-white shadow-sm"
                  : "bg-stone-100 text-stone-600 hover:bg-stone-200"
              }`}
            >
              ✍ Report Email
            </button>
            <button
              onClick={() => setActiveTab("inbox")}
              className={`flex-1 py-2 text-xs sm:text-sm font-bold rounded-lg transition-all flex items-center justify-center gap-1.5 ${
                activeTab === "inbox"
                  ? "bg-emerald-700 text-white shadow-sm"
                  : "bg-stone-100 text-stone-600 hover:bg-stone-200"
              }`}
            >
              📥 Training Inbox
              <span className={`text-[10px] px-1.5 py-0.5 rounded-full font-bold ${
                activeTab === "inbox" ? "bg-emerald-800 text-emerald-100" : "bg-stone-300 text-stone-700"
              }`}>
                3
              </span>
            </button>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="container mx-auto px-4 py-4 max-w-2xl">
        {activeTab === "report" ? (
          <ReportForm initialData={prefilledData} />
        ) : (
          <Inbox onSelectSample={handleSelectSample} />
        )}
      </main>

      <footer className="text-center text-xs text-stone-400 py-6 border-t border-stone-200 mt-8">
        Built for Ethiopian Institutions • EthioSecure SOC Integration
      </footer>
    </div>
  );
}

export default App;
