import Inbox from "./Inbox";
import ReportForm from "./ReportForm";

function App() {
  return (
    <div className="min-h-screen bg-stone-50 text-stone-800">
      {/* Header */}
      <header className="bg-white border-b border-stone-200 shadow-sm">
        <div className="container mx-auto px-4 py-4 max-w-3xl">
          <div className="flex items-center gap-3">
            {/* Small Ethiopian flag accent */}
            <div className="flex flex-col w-1.5 h-8 rounded-sm overflow-hidden">
              <div className="h-1/3 bg-green-600"></div>
              <div className="h-1/3 bg-yellow-400"></div>
              <div className="h-1/3 bg-red-600"></div>
            </div>

            <div>
              <h1 className="text-xl font-bold tracking-tight text-stone-900">
                EthioSecure – Phish Watch
              </h1>
              <p className="text-sm text-stone-500">
                Employee Reporting Portal
              </p>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-8 max-w-3xl">
        <Inbox />
        <div className="mt-10">
          <ReportForm />
        </div>
      </main>

      {/* Footer */}
      <footer className="text-center text-sm text-stone-400 py-6 border-t border-stone-200">
        Built for Ethiopian institutions • Phish Watch
      </footer>
    </div>
  );
}

export default App;
