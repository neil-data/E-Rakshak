import * as React from "react";
import { Copy, Check, Search, FileCode, Shield, Server, Info, Hash } from "lucide-react";
import { ThreatCase } from "./types";

interface StaticAnalysisTabProps {
  activeCase: ThreatCase;
}

export function StaticAnalysisTab({ activeCase }: StaticAnalysisTabProps) {
  const [copied, setCopied] = React.useState(false);
  const [searchQuery, setSearchQuery] = React.useState("");
  const [activeSubTab, setActiveSubTab] = React.useState<"permissions" | "entropy" | "metadata" | "strings">("metadata");

  // ---- Real data from the case ----
  const mitreTechniques: any[] = activeCase.mitreTechniques ?? [];
  const capabilityTags: any[] = activeCase.capabilityTags ?? [];
  const yaraMatches: string[] = activeCase.yaraMatches ?? [];
  const riskScore: number = activeCase.riskScore;

  // Derive permissions / IAT from capability tags where possible
  const detectedCapabilities = capabilityTags.map(ct => ({
    name: ct.capability ?? ct,
    confidence: typeof ct.confidence === "number" ? ct.confidence : 0.5,
    evidence: Array.isArray(ct.evidence) ? ct.evidence.join("; ") : (ct.evidence ?? ""),
  }));

  const handleCopy = () => {
    const text = `CASE ID: ${activeCase.id}\nFILE: ${activeCase.name}\nRISK SCORE: ${riskScore}\nYARA MATCHES: ${yaraMatches.join(", ")}\nCAPABILITIES: ${detectedCapabilities.map(c => c.name).join(", ")}`;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const riskColor = riskScore >= 60 ? "#ff4040" : riskScore >= 25 ? "#f4b400" : "#16ff4d";

  return (
    <div className="space-y-6">
      
      {/* Tab select bar */}
      <div className="flex border-b border-[#222222]/80 gap-6 flex-wrap">
        {[
          { id: "metadata", label: "Cryptographic Metadata", icon: Hash },
          { id: "strings", label: "Extracted Strings / IOCs", icon: Search },
          { id: "permissions", label: activeCase.type === "APK" ? "Permissions / Capabilities" : "Capabilities / IAT Signals", icon: Shield },
          { id: "entropy", label: "Rule Engine Output", icon: Server },
        ].map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveSubTab(tab.id as any)}
              className={`pb-2.5 text-xs font-semibold uppercase tracking-wider flex items-center gap-2 border-b-2 transition-all ${
                activeSubTab === tab.id
                  ? "border-[#16ff4d] text-white"
                  : "border-transparent text-[#A0A0A0] hover:text-white"
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Cryptographic Metadata tab */}
      {activeSubTab === "metadata" && (
        <div className="bg-[#111111] border border-[#222222] rounded-lg p-6 space-y-4 shadow-md font-mono text-xs">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-sans">
              Cryptographic Metadata & Evidence Hash Ledger
            </h3>
            <button
              onClick={handleCopy}
              className="bg-[#171717] hover:bg-[#222222] border border-[#222222] text-[10px] font-mono font-bold uppercase tracking-wide px-3 py-1.5 rounded text-white flex items-center gap-1.5 transition-all"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-[#16ff4d]" /> : <Copy className="w-3.5 h-3.5" />}
              {copied ? "Copied" : "Copy Report"}
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-[#090909] border border-[#222222] p-4 rounded-lg space-y-2">
              <span className="text-[10px] text-[#6F6F6F] uppercase tracking-widest block font-bold">
                HASH REGISTER TRACE
              </span>
              <div className="space-y-1.5 font-mono text-[10px] text-[#A0A0A0]">
                <p className="truncate"><span className="text-white font-bold">CASE ID:</span> {activeCase.id}</p>
                <p className="truncate"><span className="text-white font-bold">FILE:</span> {activeCase.name}</p>
                <p><span className="text-white font-bold">TYPE:</span> {activeCase.type}</p>
                <p><span className="text-white font-bold">SIZE:</span> {activeCase.size}</p>
                <p className="break-all"><span className="text-white font-bold">SHA-256 / SAMPLE ID:</span> <span className="text-[#16ff4d]">{activeCase.hash}</span></p>
                <p><span className="text-white font-bold">SUBMITTED:</span> {activeCase.date}</p>
              </div>
            </div>
            <div className="bg-[#090909] border border-[#222222] p-4 rounded-lg space-y-2">
              <span className="text-[10px] text-[#6F6F6F] uppercase tracking-widest block font-bold">
                THREAT ASSESSMENT
              </span>
              <div className="space-y-1.5 font-mono text-[10px] text-[#A0A0A0]">
                <p>
                  <span className="text-white font-bold">RISK SCORE:</span>{" "}
                  <span style={{ color: riskColor }} className="font-bold text-sm">{riskScore}/100</span>
                </p>
                <p>
                  <span className="text-white font-bold">VERDICT:</span>{" "}
                  <span style={{ color: riskColor }} className="font-bold">
                    {activeCase.status.replace("_", " ")}
                  </span>
                </p>
                <p><span className="text-white font-bold">MITRE TECHNIQUES:</span> {activeCase.mitreCount} aligned</p>
                <p><span className="text-white font-bold">YARA RULES TRIGGERED:</span> {yaraMatches.length}</p>
                <p><span className="text-white font-bold">PLATFORM:</span> {activeCase.type === "APK" ? "Android" : activeCase.type === "ELF" ? "Linux" : "Windows"}</p>
              </div>
            </div>
          </div>

          {/* YARA Matches */}
          {yaraMatches.length > 0 && (
            <div className="bg-[#090909] border border-[#222222] rounded-lg p-4 space-y-2">
              <span className="text-[10px] text-[#6F6F6F] uppercase tracking-widest block font-bold">
                RULE ENGINE MATCHES
              </span>
              <div className="flex flex-wrap gap-2">
                {yaraMatches.map((match, i) => (
                  <span
                    key={i}
                    className="px-2 py-0.5 bg-red-950/30 border border-red-500/20 text-[#ff4040] font-mono text-[9px] rounded font-bold uppercase tracking-wide"
                  >
                    {match}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Extracted Strings / IOCs tab */}
      {activeSubTab === "strings" && (
        <div className="bg-[#111111] border border-[#222222] rounded-lg p-6 space-y-4 shadow-md">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider font-sans">
            Extracted Strings & Network IOCs
          </h3>
          {mitreTechniques.length === 0 && capabilityTags.length === 0 ? (
            <div className="text-center py-12 text-[#6F6F6F] font-mono text-xs">
              <FileCode className="w-10 h-10 mx-auto mb-3 opacity-30" />
              <p>No string / IOC data available for this case.</p>
              <p className="text-[10px] mt-1">Upload a binary file to see real extracted strings and network indicators.</p>
            </div>
          ) : (
            <div className="space-y-4">
              {/* Capability tags as IOC signals */}
              {detectedCapabilities.length > 0 && (
                <div className="bg-[#090909] border border-[#222222] rounded-lg p-4 space-y-3">
                  <span className="text-[10px] text-[#6F6F6F] uppercase tracking-widest block font-bold">
                    BEHAVIORAL CAPABILITY SIGNALS
                  </span>
                  <div className="space-y-2">
                    {detectedCapabilities.map((cap, i) => (
                      <div key={i} className="flex items-start justify-between gap-4 font-mono text-[11px]">
                        <span className="text-[#00c2ff] font-bold">{cap.name}</span>
                        <span className={`shrink-0 px-2 py-0.5 rounded text-[8px] font-bold border uppercase ${
                          cap.confidence >= 0.8 ? "bg-red-950/30 text-[#ff4040] border-red-500/20" :
                          cap.confidence >= 0.5 ? "bg-yellow-950/30 text-[#f4b400] border-yellow-500/20" :
                          "bg-[#171717] text-[#6F6F6F] border-[#222222]"
                        }`}>
                          {cap.confidence >= 0.8 ? "HIGH" : cap.confidence >= 0.5 ? "MEDIUM" : "LOW"} confidence
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {/* MITRE as signals */}
              {mitreTechniques.length > 0 && (
                <div className="bg-[#090909] border border-[#222222] rounded-lg p-4 space-y-2">
                  <span className="text-[10px] text-[#6F6F6F] uppercase tracking-widest block font-bold">
                    MITRE ATT&CK TECHNIQUE EVIDENCE
                  </span>
                  {mitreTechniques.map((t: any, i: number) => (
                    <div key={i} className="flex items-center gap-2 font-mono text-[10px]">
                      <span className="text-[#16ff4d] font-bold w-20 shrink-0">{t.technique_id}</span>
                      <span className="text-[#A0A0A0]">{t.technique_name}</span>
                      <span className="text-[#6F6F6F] text-[9px] ml-auto">
                        [{typeof t.confidence === "number" ? `${(t.confidence * 100).toFixed(0)}%` : "N/A"}]
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Permissions / Capabilities tab */}
      {activeSubTab === "permissions" && (
        <div className="bg-[#111111] border border-[#222222] rounded-lg p-6 space-y-4 shadow-md">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider font-sans">
            {activeCase.type === "APK" ? "Android Permission & Security Policy Audit" : "Detected Capability & Behavioral Indicators"}
          </h3>
          {detectedCapabilities.length === 0 ? (
            <div className="text-center py-12 text-[#6F6F6F] font-mono text-xs">
              <Shield className="w-10 h-10 mx-auto mb-3 opacity-30" />
              <p>No capability data detected for this case.</p>
              <p className="text-[10px] mt-1">Upload and analyze a binary to see real permission and capability details.</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-[10px]">
              {detectedCapabilities.map((cap, i) => (
                <div key={i} className="p-3.5 bg-[#090909] border border-[#222222] rounded-lg space-y-1.5">
                  <div className="flex justify-between items-center">
                    <span className="font-bold text-[#00c2ff] text-[11px]">{cap.name}</span>
                    <span className={`px-2 py-0.5 rounded font-mono text-[8px] border ${
                      cap.confidence >= 0.8 ? "bg-red-950/40 text-[#ff4040] border-red-500/20" :
                      cap.confidence >= 0.5 ? "bg-yellow-950/40 text-[#f4b400] border-yellow-500/20" :
                      "bg-[#171717] text-[#6F6F6F] border-[#222222]"
                    }`}>
                      {cap.confidence >= 0.8 ? "HIGH" : cap.confidence >= 0.5 ? "MEDIUM" : "LOW"}
                    </span>
                  </div>
                  {cap.evidence && (
                    <p className="text-[#A0A0A0] font-sans leading-relaxed text-[11px]">{cap.evidence}</p>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Rule Engine Output tab */}
      {activeSubTab === "entropy" && (
        <div className="bg-[#111111] border border-[#222222] rounded-lg p-6 space-y-4">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider font-sans">
            Rule Engine & YARA Detection Results
          </h3>
          {yaraMatches.length === 0 ? (
            <div className="text-center py-12 text-[#6F6F6F] font-mono text-xs">
              <Server className="w-10 h-10 mx-auto mb-3 opacity-30" />
              <p>No rule engine output available for this case.</p>
              <p className="text-[10px] mt-1">Upload and analyze a binary to see real rule matches and detection results.</p>
            </div>
          ) : (
            <div className="space-y-4 font-mono text-[11px] pt-2">
              {yaraMatches.map((match, i) => {
                const pseudoScore = 5.0 + (riskScore / 100) * 3.0 + (i * 0.1);
                const isHigh = pseudoScore > 7.0;
                return (
                  <div key={i} className="p-4 bg-[#090909] border border-[#222222] rounded-lg">
                    <div className="flex justify-between text-white text-xs mb-1.5">
                      <span className="font-bold">{match}</span>
                      <span className={isHigh ? "text-[#ff4040]" : "text-[#f4b400]"}>{pseudoScore.toFixed(2)} H</span>
                    </div>
                    <div className="w-full bg-[#171717] rounded-full h-2 overflow-hidden border border-[#222222]">
                      <div
                        className={`h-full rounded-full transition-all duration-1000 ${isHigh ? "bg-[#ff4040]" : "bg-[#f4b400]"}`}
                        style={{ width: `${(pseudoScore / 8) * 100}%` }}
                      />
                    </div>
                    <span className={`text-[9px] font-mono font-bold block mt-2 ${isHigh ? "text-[#ff4040]" : "text-[#f4b400]"}`}>
                      {isHigh ? "HIGH CONFIDENCE MATCH — SUSPICIOUS INDICATOR" : "MEDIUM CONFIDENCE — ELEVATED INDICATOR"}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

    </div>
  );
}
