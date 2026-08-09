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
    "[SYSTEM] Note: Dynamic detonation is a planned capability.",
    "[SYSTEM] Static analysis results are available in the Static Analysis tab.",
    "[SYSTEM] Sandbox status: AWAITING_INTEGRATION",
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
    setLogs(prev => [...prev, `$ ${command}`, `[SYSTEM] Command queued for sandbox execution. Dynamic sandbox integration pending.`]);
    setInputVal("");
  };

  // Sandbox not yet live — show real status based on case
  const sandboxStatus = activeCase.sandboxResult ? "COMPLETED" : "NOT_SUBMITTED";
  const sandboxData: any = activeCase.sandboxResult ?? null;

  return (
    <div className="space-y-6">

      {/* Header */}
      <div className="flex justify-between items-center border-b border-[#222222]/80 pb-4">
        <div>
          <h3 className="text-base font-bold text-white uppercase tracking-wider font-sans">
            Dynamic Sandbox Detonation
          </h3>
          <p className="text-[11px] text-[#A0A0A0] font-light">
            {sandboxData ? "Live runtime behavior capture from isolated sandbox environment." : "Submit binary for dynamic detonation in an air-gapped KVM hypervisor environment."}
          </p>
        </div>
        <div className={`flex items-center gap-2 font-mono text-[10px] px-3 py-1 rounded border ${
          sandboxStatus === "COMPLETED"
            ? "bg-[#16ff4d]/10 border-[#16ff4d]/20 text-[#16ff4d]"
            : "bg-[#f4b400]/10 border-[#f4b400]/20 text-[#f4b400]"
        }`}>
          <Activity className="w-3.5 h-3.5" />
          {sandboxStatus === "COMPLETED" ? "ANALYSIS COMPLETE" : "AWAITING SUBMISSION"}
        </div>
      </div>

      {/* If we have real sandbox data from the backend, show it */}
      {sandboxData ? (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">

          {/* Behavior log from real data */}
          <div className="lg:col-span-8 bg-[#111111] border border-[#222222] rounded-lg overflow-hidden flex flex-col shadow-lg">
            <div className="bg-[#171717] px-4 py-3 border-b border-[#222222] flex items-center gap-2">
              <Terminal className="w-3.5 h-3.5 text-[#16ff4d]" />
              <span className="text-[10px] font-mono text-[#A0A0A0] uppercase font-bold tracking-wider">
                SANDBOX BEHAVIOR LOG
              </span>
            </div>
            <div className="p-5 font-mono text-[11px] h-[340px] overflow-y-auto space-y-2 bg-[#090909] text-[#A0A0A0] select-text">
              {(sandboxData.behavior_log ?? []).map((entry: any, i: number) => (
                <div key={i} className={`leading-relaxed pl-2 border-l-2 ${
                  entry.severity === "CRITICAL" ? "border-[#ff4040]/60 text-[#ff4040]" :
                  entry.severity === "HIGH" ? "border-[#f4b400]/60 text-[#f4b400]" :
                  "border-[#222222] text-[#A0A0A0]"
                }`}>
                  {entry.message ?? entry}
                </div>
              ))}
              <div ref={bottomRef} />
            </div>
          </div>

          {/* Summary stats from sandbox */}
          <div className="lg:col-span-4 space-y-4">
            <div className="bg-[#111111] border border-[#222222] rounded-lg p-5 space-y-3 font-mono text-[11px]">
              <span className="text-[10px] text-[#6F6F6F] uppercase tracking-widest block border-b border-[#222222]/60 pb-2">
                SANDBOX SUMMARY
              </span>
              <div className="space-y-2 text-[#A0A0A0]">
                {sandboxData.duration_seconds !== undefined && (
                  <p><span className="text-white font-bold">DURATION:</span> {sandboxData.duration_seconds}s</p>
                )}
                {sandboxData.network_connections !== undefined && (
                  <p><span className="text-white font-bold">NET CONNECTIONS:</span> {sandboxData.network_connections}</p>
                )}
                {sandboxData.file_drops !== undefined && (
                  <p><span className="text-white font-bold">FILE DROPS:</span> {sandboxData.file_drops}</p>
                )}
                {sandboxData.registry_writes !== undefined && (
                  <p><span className="text-white font-bold">REGISTRY WRITES:</span> {sandboxData.registry_writes}</p>
                )}
              </div>
            </div>
          </div>
        </div>
      ) : (
        /* No sandbox data — show capability notice + terminal stub */
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

          {/* Capability notice */}
          <div className="lg:col-span-4 space-y-4">
            <div className="bg-[#111111] border border-[#f4b400]/30 rounded-lg p-5 space-y-3">
              <div className="flex items-center gap-2 text-[#f4b400] font-mono text-[10px] font-bold uppercase tracking-wider">
                <AlertTriangle className="w-4 h-4" />
                NOT YET SUBMITTED
              </div>
              <p className="text-[#A0A0A0] font-sans text-xs leading-relaxed">
                This case has not been detonated in the dynamic sandbox. Dynamic analysis produces real-time API call traces, network stream logs, registry hooks, and behavioral artifacts.
              </p>
            </div>
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
                <p className="flex items-center gap-2"><Cpu className="w-3 h-3 text-[#00c2ff]" /> KVM hypervisor isolation</p>
                <p className="flex items-center gap-2"><Terminal className="w-3 h-3 text-[#00c2ff]" /> Syscall & API trace capture</p>
                <p className="flex items-center gap-2"><FlaskConical className="w-3 h-3 text-[#00c2ff]" /> Network stream honeypot</p>
                <p className="flex items-center gap-2"><Activity className="w-3 h-3 text-[#00c2ff]" /> Real-time memory monitoring</p>
              </div>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
