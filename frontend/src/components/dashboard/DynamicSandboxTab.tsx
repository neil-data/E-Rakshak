import * as React from "react";
import { Terminal, Activity, Cpu, FlaskConical, AlertTriangle } from "lucide-react";
import { ThreatCase } from "./types";

interface DynamicSandboxTabProps {
  activeCase: ThreatCase;
}

export function DynamicSandboxTab({ activeCase }: DynamicSandboxTabProps) {
  const [logs, setLogs] = React.useState<string[]>([
    "[SYSTEM] Dynamic analysis sandbox engine initializing...",
    `[SYSTEM] Case loaded: ${activeCase.id} — ${activeCase.name}`,
  ]);

  const [inputVal, setInputVal] = React.useState("");
  const bottomRef = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputVal.trim()) return;
    const command = inputVal.trim();
    setLogs(prev => [...prev, `$ ${command}`, "[SYSTEM] Command queued for sandbox execution. Sandbox integration pending."]);
    setInputVal("");
  };

  // Honest backend state: the pipeline records what actually happened, which
  // is "not configured" when no sandbox endpoint is set (never a fake timer).
  const dyn: any = activeCase.sandboxResult ?? null;
  const status = dyn?.status ?? "not_configured";
  const isConfigured = dyn?.available === true;
  const statusLabel: Record<string, string> = {
    not_configured: "NOT CONFIGURED",
    submitted: "SUBMITTED",
    failed: "SUBMISSION FAILED",
    completed: "ANALYSIS COMPLETE",
  };
  const sandboxStatus = status in statusLabel ? statusLabel[status] : status.toUpperCase();
  const sandboxConfigured = isConfigured || ["submitted", "failed", "completed"].includes(status);

  return (
    <div className="space-y-6">

      {/* Header */}
      <div className="flex justify-between items-center border-b border-[#222222]/80 pb-4">
        <div>
          <h3 className="text-base font-bold text-white uppercase tracking-wider font-sans">
            Dynamic Sandbox Detonation
          </h3>
          <p className="text-[11px] text-[#A0A0A0] font-light">
            {sandboxConfigured
              ? (dyn?.message ?? "Runtime behavior capture from the configured sandbox environment.")
              : "No sandbox is configured — the backend honestly reports dynamic analysis as unavailable. Static findings remain available in the Static Analysis tab."}
          </p>
        </div>
        <div className={`flex items-center gap-2 font-mono text-[10px] px-3 py-1 rounded border ${
          status === "completed"
            ? "bg-[#16ff4d]/10 border-[#16ff4d]/20 text-[#16ff4d]"
            : status === "submitted"
            ? "bg-[#00c2ff]/10 border-[#00c2ff]/20 text-[#00c2ff]"
            : status === "failed"
            ? "bg-[#ff4040]/10 border-[#ff4040]/20 text-[#ff4040]"
            : "bg-[#f4b400]/10 border-[#f4b400]/20 text-[#f4b400]"
        }`}>
          <Activity className="w-3.5 h-3.5" />
          {sandboxStatus}
        </div>
      </div>

      {/* Terminal — real backend state when available, capability notice otherwise */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">

        {/* Terminal stub — shows system messages, accepts future commands */}
        <div className="lg:col-span-8 bg-[#111111] border border-[#222222] rounded-lg overflow-hidden flex flex-col shadow-lg">
          <div className="bg-[#171717] px-4 py-3 border-b border-[#222222] flex items-center justify-between">
            <span className="text-[10px] font-mono text-[#A0A0A0] uppercase font-bold tracking-wider flex items-center gap-2">
              <Terminal className="w-3.5 h-3.5 text-[#16ff4d]" />
              SANDBOX TERMINAL // {activeCase.id}
            </span>
          </div>

          <div className="p-5 font-mono text-[11px] h-[340px] overflow-y-auto space-y-2 bg-[#090909] text-[#A0A0A0] select-text">
            {dyn && (
              <div className="leading-relaxed pl-2 border-l-2 border-[#222222] text-[#A0A0A0] mb-4">
                <span className="text-[#00c2ff] font-bold">[DYNAMIC]</span> status={dyn.status} available={dyn.available ? "true" : "false"}
                <br />
                <span className="text-[#00c2ff] font-bold">[DYNAMIC]</span> {dyn.message}
                {dyn.task_id ? <><br /><span className="text-[#00c2ff] font-bold">[DYNAMIC]</span> task_id={dyn.task_id}</> : null}
                {dyn.sandbox_url ? <><br /><span className="text-[#00c2ff] font-bold">[DYNAMIC]</span> sandbox={dyn.sandbox_url}</> : null}
              </div>
            )}
            {logs.map((log, index) => {
              const isSystem = log.includes("[SYSTEM]");
              const isUser = log.startsWith("$");
              return (
                <div key={index} className={`leading-relaxed pl-2 border-l-2 ${
                  isSystem ? "border-[#00c2ff]/40 text-[#00c2ff]" :
                  isUser ? "border-[#16ff4d]/40 text-[#16ff4d] font-bold" :
                  "border-[#222222] text-[#A0A0A0]"
                }`}>
                  {log}
                </div>
              );
            })}
            <div className="flex items-center gap-1 text-[#16ff4d] text-[11px] font-mono">
              <span>$ awaiting instructions_</span>
              <span className="w-1.5 h-3 bg-[#16ff4d] animate-pulse inline-block" />
            </div>
            <div ref={bottomRef} />
          </div>

          <form
            onSubmit={handleSubmit}
            className="p-3 bg-[#111111] border-t border-[#222222] flex items-center gap-3"
          >
            <span className="text-xs font-mono text-[#16ff4d] font-bold ml-2">$</span>
            <input
              type="text"
              value={inputVal}
              onChange={(e) => setInputVal(e.target.value)}
              placeholder="Enter analyst directive..."
              className="flex-1 bg-transparent border-none text-xs font-mono text-white focus:outline-none placeholder:text-[#6F6F6F]"
            />
            <button
              type="submit"
              className="bg-[#16ff4d] hover:bg-[#16ff4d]/90 text-[#090909] font-mono text-[10px] uppercase font-bold px-3 py-1.5 rounded transition-all shrink-0 active:scale-95"
            >
              EXEC
            </button>
          </form>
        </div>

        {/* Right rail — truthful status / capability notice */}
        <div className="lg:col-span-4 space-y-4">
          {dyn ? (
            <div className="bg-[#111111] border border-[#222222] rounded-lg p-5 space-y-3 font-mono text-[11px]">
              <span className="text-[10px] text-[#6F6F6F] uppercase tracking-widest block border-b border-[#222222]/60 pb-2">
                DYNAMIC STATUS
              </span>
              <div className="space-y-2 text-[#A0A0A0]">
                <p><span className="text-white font-bold">STATE:</span> {status.toUpperCase()}</p>
                {dyn.duration_seconds !== undefined && (
                  <p><span className="text-white font-bold">DURATION:</span> {dyn.duration_seconds}s</p>
                )}
                {dyn.network_connections !== undefined && (
                  <p><span className="text-white font-bold">NET CONNECTIONS:</span> {dyn.network_connections}</p>
                )}
                {dyn.file_drops !== undefined && (
                  <p><span className="text-white font-bold">FILE DROPS:</span> {dyn.file_drops}</p>
                )}
                {dyn.registry_writes !== undefined && (
                  <p><span className="text-white font-bold">REGISTRY WRITES:</span> {dyn.registry_writes}</p>
                )}
              </div>
            </div>
          ) : (
            <div className="bg-[#111111] border border-[#f4b400]/30 rounded-lg p-5 space-y-3">
              <div className="flex items-center gap-2 text-[#f4b400] font-mono text-[10px] font-bold uppercase tracking-wider">
                <AlertTriangle className="w-4 h-4" />
                NO DYNAMIC STATE
              </div>
              <p className="text-[#A0A0A0] font-sans text-xs leading-relaxed">
                This case has no dynamic-analysis result recorded. When a sandbox endpoint is
                configured (SANDBOX_API_URL / CAPE_API_URL), the pipeline submits the sample and
                this panel surfaces the honest submission state.
              </p>
            </div>
          )}

          <div className="bg-[#111111] border border-[#222222] rounded-lg p-5 space-y-3 font-mono text-[11px]">
            <span className="text-[10px] text-[#6F6F6F] uppercase tracking-widest block border-b border-[#222222]/60 pb-2">
              CASE CONTEXT
            </span>
            <div className="space-y-2 text-[#A0A0A0]">
              <p><span className="text-white font-bold">FILE:</span> {activeCase.name}</p>
              <p><span className="text-white font-bold">TYPE:</span> {activeCase.type}</p>
              <p><span className="text-white font-bold">RISK:</span> <span className="text-[#ff4040]">{activeCase.riskScore}/100</span></p>
              <p><span className="text-white font-bold">STATUS:</span> {activeCase.status.replace("_", " ")}</p>
            </div>
          </div>

          <div className="bg-[#111111] border border-[#222222] rounded-lg p-5 space-y-3 font-mono text-[11px]">
            <span className="text-[10px] text-[#6F6F6F] uppercase tracking-widest block border-b border-[#222222]/60 pb-2">
              SANDBOX CAPABILITIES
            </span>
            <div className="space-y-1.5 text-[#6F6F6F] text-[10px]">
              <p className="flex items-center gap-2"><Cpu className="w-3 h-3 text-[#00c2ff]" /> Isolated detonation environment</p>
              <p className="flex items-center gap-2"><Terminal className="w-3 h-3 text-[#00c2ff]" /> Syscall & API trace capture</p>
              <p className="flex items-center gap-2"><FlaskConical className="w-3 h-3 text-[#00c2ff]" /> Network stream capture</p>
              <p className="flex items-center gap-2"><Activity className="w-3 h-3 text-[#00c2ff]" /> Behavioral artifact collection</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}