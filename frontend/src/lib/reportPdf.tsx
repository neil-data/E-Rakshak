import html2canvas from "html2canvas";
import { jsPDF } from "jspdf";
import type { ThreatCase } from "../components/dashboard/types";
import type { CurrentUser } from "./api";

type Language = "en" | "gu";

const gu = {
  title: "ફોરેન્સિક વિશ્લેષણ અહેવાલ", sample: "નમૂનાની માહિતી", threat: "જોખમ મૂલ્યાંકન",
  ai: "AI વિશ્લેષણ", static: "સ્ટેટિક વિશ્લેષણ", dynamic: "ડાયનેમિક વિશ્લેષણ",
  network: "નેટવર્ક ઇન્ટેલિજન્સ", geo: "જીઓ-IP એટ્રિબ્યુશન", mitre: "MITRE ATT&CK",
  capability: "ક્ષમતાઓ અને ભલામણો", custody: "પુરાવા શૉંખલા",
  unavailable: "ઉપલબ્ધ નથી", disclaimer: "જીઓ-IP અંદાજિત ભૌગોલિક માહિતી છે; તે ચોક્કસ ભૌતિક સ્થાન નથી.",
  status: "સેન્ડબોક્સ સ્થિતિ", available: "ઉપલબ્ધ", details: "વિગતો", location: "સ્થળ", ispAsn: "ISP / ASN", flags: "ફ્લેગ્સ", yes: "હા", no: "ના",
};

const en = {
  title: "Forensic Analysis Report", sample: "Sample Information", threat: "Threat Assessment",
  ai: "AI Analysis", static: "Static Analysis", dynamic: "Dynamic Analysis",
  network: "Network Intelligence", geo: "Geo-IP Attribution", mitre: "MITRE ATT&CK",
  capability: "Capabilities & Recommendations", custody: "Chain of Custody",
  unavailable: "Not available", disclaimer: "Geo-IP is an approximate geographic estimate and not an exact physical location.",
  status: "Sandbox status", available: "Available", details: "Details", location: "Location", ispAsn: "ISP / ASN", flags: "Flags", yes: "Yes", no: "No",
};

const escapeHtml = (value: unknown) => String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[char]!));
const value = (item: unknown, fallback: string) => item === null || item === undefined || item === "" ? fallback : String(item);
const list = (items: unknown[], fallback: string, render = (item: unknown) => value(item, fallback)) => items.length ? `<ul>${items.map(item => `<li>${render(item)}</li>`).join("")}</ul>` : `<p class="muted">${fallback}</p>`;

/**
 * Generates a static, image-based PDF.  Gujarati is shaped by the browser
 * before capture, so jsPDF never has to position Indic glyphs itself.
 */
export async function generateForensicPDF(activeCase: ThreatCase, examiner: CurrentUser | null, language: Language): Promise<void> {
  const t = language === "gu" ? gu : en;
  const unavailable = t.unavailable;
  const reportId = `ER-${activeCase.id}-${new Date().toISOString().slice(0, 10).replace(/-/g, "")}`;
  const network = activeCase.networkIndicators;
  const threat = activeCase.threatAssessment;
  const ai = activeCase.aiAnalysis;
  const dynamic = activeCase.sandboxResult ?? (activeCase as any).dynamicAnalysis ?? null;
  const isPrivateIp = (ip: string) => /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1|fc00:|fd)/.test(ip);
  const geoByIp = new Map((activeCase.geoIocs ?? []).map((record: any) => [record.ip, record]));
  for (const ip of network?.ips ?? []) {
    if (!geoByIp.has(ip)) geoByIp.set(ip, { ip });
  }
  const geoRecords = Array.from(geoByIp.values());

  // ---- Dynamic Analysis -------------------------------------------------
  const yesNo = (flag: unknown) => (flag === true ? t.yes : flag === false ? t.no : unavailable);
  const dynRows: string[] = [];
  const detailList = (label: string, items: unknown, render: (item: any) => string) => {
    if (Array.isArray(items) && items.length > 0) {
      dynRows.push(`<b>${escapeHtml(label)}:</b><ul>${items.map(render).join("")}</ul>`);
    }
  };
  const listItemText = (item: any): string => {
    if (item && typeof item === "object") {
      const keys = Object.keys(item).filter(k => item[k] != null && item[k] !== "" && !(Array.isArray(item[k]) && item[k].length === 0));
      const text = keys
        .map(k => `${k.replace(/_/g, " ")}: ${Array.isArray(item[k]) ? item[k].join(", ") : item[k]}`)
        .join(" · ");
      return `<li>${escapeHtml(text)}</li>`;
    }
    return `<li>${escapeHtml(item == null ? "—" : String(item))}</li>`;
  };
  let dynamicHtml: string;
  if (dynamic) {
    const d = dynamic as any;
    dynRows.push(`<b>${t.status}:</b> ${escapeHtml(value(d.status, unavailable))}`);
    dynRows.push(`<b>${t.available}:</b> ${escapeHtml(yesNo(d.available))}`);
    const dynMessage = value(d.message ?? d.details, "");
    if (dynMessage) dynRows.push(`<b>${t.details}:</b> ${escapeHtml(dynMessage)}`);
    if (value(d.task_id, "") !== "") dynRows.push(`<b>Task ID:</b> ${escapeHtml(d.task_id)}`);
    if (d.sandbox_url) dynRows.push(`<b>Sandbox:</b> ${escapeHtml(d.sandbox_url)}`);
    if (d.duration_seconds !== undefined) dynRows.push(`<b>Duration:</b> ${escapeHtml(String(d.duration_seconds))}s`);
    detailList("Network connections", d.network_connections, (c: any) =>
      `<li>${escapeHtml([c.dest_ip || c.ip, c.dest_port || c.port, c.protocol, c.flagged_c2 ? "(C2)" : ""].filter(Boolean).join(" "))}</li>`);
    detailList("C2 endpoints", d.c2_endpoints_detected, listItemText);
    detailList("Process tree", d.process_tree, listItemText);
    detailList("API calls", d.api_calls, listItemText);
    detailList("DNS queries", d.dns_queries, listItemText);
    detailList("Files written", d.files_written, listItemText);
    detailList("Registry changes", d.registry_changes, listItemText);
    detailList("Persistence artifacts", d.persistence_artifacts, listItemText);
    dynamicHtml = dynRows.join("<br>");
  } else {
    dynamicHtml = `<b>${t.status}:</b> ${unavailable}<br><span class="muted">${language === "gu" ? "ડાયનેમિક સેન્ડબોક્સ પરિણામ આ કેસ માટે ઉપલબ્ધ નથી." : "No dynamic sandbox result is available for this case."}</span>`;
  }

  // ---- Geo-IP attribution ------------------------------------------------
  const geoHtml = geoRecords.length
    ? `<table><tr><th>IP</th><th>${t.location}</th><th>${t.ispAsn}</th><th>${t.flags}</th></tr>${geoRecords.map((g: any) => {
        const gip = escapeHtml(g.ip ?? unavailable);
        const privateIp = g.ip && isPrivateIp(g.ip);
        const locParts = [g.city, g.region, g.country].filter(Boolean);
        if (locParts.length === 0 && g.country_iso) locParts.push(g.country_iso);
        if (locParts.length === 0 && (g.latitude != null || g.longitude != null)) locParts.push(`${g.latitude ?? "?"}, ${g.longitude ?? "?"}`);
        const loc = privateIp
          ? `<span class="muted">${language === "gu" ? "આંતરિક / ખાનગી નેટવર્ક" : "Internal / Private Network"}</span>`
          : locParts.length ? escapeHtml(locParts.join(", ")) : `<span class="muted">${escapeHtml(unavailable)}</span>`;
        const ispAsn = privateIp
          ? `<span class="muted">${language === "gu" ? "RFC 1918 / RFC 4193" : "RFC 1918 / RFC 4193"}</span>`
          : [g.isp || g.asn_org, g.asn != null ? `AS${g.asn}` : ""].filter(Boolean).map(escapeHtml).join(" · ") || `<span class="muted">${escapeHtml(unavailable)}</span>`;
        const flags = [
          g.is_proxy === true ? "Proxy" : null,
          g.is_hosting === true ? "Hosting" : null,
          g.threat_level ? g.threat_level : null,
        ].filter(Boolean).map(escapeHtml).join(", ");
        return `<tr><td><b>${gip}</b></td><td>${loc}</td><td>${ispAsn}</td><td>${flags ? flags : "—"}</td></tr>`;
      }).join("")}</table>`
    : `<p class="muted">${t.unavailable}</p>`;
  const findings = threat?.key_findings ?? [];
  const recommendations = ai?.recommendations ?? [];
  const riskContributions = activeCase.riskExplanation?.contributions ?? [];
  const correlations = activeCase.evidenceCorrelation ?? [];
  const timeline = activeCase.evidenceTimeline ?? [];
  const iocs = activeCase.iocIntelligence ?? [];
  const correlationPage = (correlations.length || timeline.length || iocs.length) ? `
      <section class="page"><h2>Evidence Correlation &amp; Timeline</h2>
      ${correlations.length ? `<h3>Correlated findings</h3><table><tr><th>Finding</th><th>Static evidence</th><th>Dynamic evidence</th><th>State</th><th>Confidence</th></tr>${correlations.map((item: any) => `<tr><td>${escapeHtml(item.finding)}</td><td>${escapeHtml(item.static_evidence || "—")}</td><td>${escapeHtml(item.dynamic_evidence || "—")}</td><td>${escapeHtml(item.evidence_state || item.correlation || "UNKNOWN")}</td><td>${escapeHtml(value(item.confidence, unavailable))}</td></tr>`).join("")}</table>` : ""}
      ${iocs.length ? `<h3>IoC intelligence</h3><table><tr><th>Indicator</th><th>Type</th><th>Source</th><th>Classification</th><th>Confidence</th></tr>${iocs.map((item: any) => `<tr><td>${escapeHtml(item.indicator)}</td><td>${escapeHtml(item.type)}</td><td>${escapeHtml(item.source)}</td><td>${escapeHtml(item.classification)}</td><td>${escapeHtml(value(item.confidence, unavailable))}</td></tr>`).join("")}</table>` : ""}
      ${timeline.length ? `<h3>Evidence timeline</h3><table><tr><th>Timestamp</th><th>Event</th><th>Source</th><th>Indicator</th></tr>${timeline.map((item: any) => `<tr><td>${escapeHtml(item.timestamp || "—")}</td><td>${escapeHtml(item.event || "—")}</td><td>${escapeHtml(item.source || "—")}</td><td>${escapeHtml(item.indicator || "—")}</td></tr>`).join("")}</table>` : ""}
      <div class="footer"><span>${escapeHtml(reportId)}</span><span>OFFICIAL - FORENSIC USE ONLY</span></div></section>` : "";
  const body = document.createElement("div");
  body.setAttribute("aria-hidden", "true");
  body.lang = language;
  body.style.cssText = "position:fixed;left:-100000px;top:0;width:794px;background:#fff;color:#172033;z-index:-1;";
  body.innerHTML = `
    <style>
      @font-face { font-family: NotoGujarati; src: url('/fonts/NotoSansGujarati-Regular.ttf') format('truetype'); }
      * { box-sizing:border-box; } .report { font-family:${language === "gu" ? "NotoGujarati, Arial, sans-serif" : "Arial, sans-serif"}; font-size:12px; line-height:1.5; padding:42px; }
      .page { min-height:1040px; padding-bottom:54px; position:relative; page-break-after:always; } .page:last-child { page-break-after:auto; }
      .header { display:flex; gap:14px; align-items:center; border-bottom:3px solid #173b68; padding-bottom:14px; } .logo { width:52px; height:52px; object-fit:contain; } h1 { margin:0; color:#173b68; font-size:24px; } h2 { color:#173b68; font-size:16px; border-left:4px solid #d58b1a; padding-left:8px; margin:22px 0 9px; } h3 { font-size:13px; margin:14px 0 5px; }
      .meta,.grid { display:grid; grid-template-columns:repeat(2,1fr); gap:8px 18px; } .card { border:1px solid #d6dde8; border-radius:5px; padding:10px; margin:8px 0; background:#fafcff; } .label { color:#52657f; font-weight:700; } .critical { color:#a11b1b; font-weight:700; } .muted { color:#68778c; } .hash { overflow-wrap:anywhere; font-family:monospace; font-size:10px; } ul { margin:5px 0; padding-left:18px; } table { width:100%; border-collapse:collapse; font-size:11px; } th,td { border:1px solid #d6dde8; padding:6px; vertical-align:top; text-align:left; } th { background:#edf3fa; color:#173b68; } .footer { position:absolute; bottom:12px; left:0; right:0; display:flex; justify-content:space-between; border-top:1px solid #d6dde8; padding-top:7px; color:#68778c; font-size:9px; }
    </style>
    <article class="report">
      <section class="page"><div class="header"><img class="logo" src="/logo.jpeg" alt="E-Rakshak" onerror="this.remove()"><div><h1>${t.title}</h1><div>Gujarat Police Cyber Cell / E-Rakshak</div><div class="muted">Report ID: ${escapeHtml(reportId)} | Analysis ID: ${escapeHtml(activeCase.id)}</div></div></div>
      <div class="card"><b>${language === "gu" ? "વર્ગીકરણ" : "Classification"}:</b> OFFICIAL - FORENSIC USE ONLY<br><b>${language === "gu" ? "બનાવ્યાનો સમય" : "Generated"}:</b> ${escapeHtml(new Date().toISOString())}</div>
      <h2>${t.sample}</h2><div class="grid"><div><span class="label">Sample:</span> ${escapeHtml(activeCase.name)}</div><div><span class="label">Platform / type:</span> ${escapeHtml(activeCase.type)}</div><div><span class="label">Size:</span> ${escapeHtml(activeCase.size)}</div><div><span class="label">Submitted:</span> ${escapeHtml(activeCase.date)}</div></div>
      <div class="card hash"><b>SHA-256:</b> ${escapeHtml(activeCase.sha256 || activeCase.hash)}<br><b>MD5:</b> ${escapeHtml(value(activeCase.md5, unavailable))}<br><b>SHA-1:</b> ${escapeHtml(value(activeCase.sha1, unavailable))}</div>
      <h2>${t.threat}</h2><div class="card"><div class="grid"><div><span class="label">Risk score:</span> <span class="critical">${activeCase.riskScore}/100</span></div><div><span class="label">Threat level:</span> ${escapeHtml(threat?.threat_level ?? activeCase.status)}</div><div><span class="label">Verdict:</span> ${escapeHtml(threat?.verdict ?? activeCase.status)}</div><div><span class="label">Confidence:</span> ${escapeHtml(value(threat?.confidence, unavailable))}%</div></div>${riskContributions.length ? `<h3>Risk score explanation</h3><ul>${riskContributions.map(part => `<li>${escapeHtml(part.label)}: <b>+${escapeHtml(part.points)}</b></li>`).join("")}</ul>` : ""}<h3>${language === "gu" ? "મુખ્ય તારણો" : "Key findings"}</h3>${list(findings, unavailable, f => escapeHtml(f))}</div>
      <h2>${t.ai}</h2><div class="card"><b>${language === "gu" ? "કાર્યકારી સારાંશ" : "Executive summary"}:</b><p>${escapeHtml(ai?.executive_summary || activeCase.narrativeSummary || unavailable)}</p><b>${language === "gu" ? "વર્તન" : "Behaviour"}:</b><p>${escapeHtml(ai?.malware_behavior ?? unavailable)}</p><b>${language === "gu" ? "નેટવર્ક અર્થઘટન" : "Network interpretation"}:</b><p>${escapeHtml(ai?.network_interpretation ?? unavailable)}</p></div>
      <div class="footer"><span>${escapeHtml(reportId)}</span><span>OFFICIAL - FORENSIC USE ONLY</span></div></section>
      <section class="page"><h2>${t.static}</h2><div class="card"><b>Packing:</b> ${activeCase.packing?.is_packed ? `Detected${activeCase.packing.packer_name ? ` (${escapeHtml(activeCase.packing.packer_name)})` : ""}` : "Not detected"}</div><h3>YARA rules</h3>${list(activeCase.yaraMatchDetails ?? [], unavailable, (m: any) => `<b>${escapeHtml(m.rule_name)}</b> [${escapeHtml(m.severity)}] - ${escapeHtml(m.description)}`)}<h3>${language === "gu" ? "સમજાવેલ સ્ટ્રિંગ્સ" : "Explained strings"}</h3>${list(activeCase.explainedStrings ?? [], unavailable, (s: any) => `<span class="hash">${escapeHtml(s.value)}</span> - ${escapeHtml(s.explanation)}`)}
      <h2>${t.dynamic}</h2><div class="card">${dynamicHtml}</div>
      <h2>${t.network}</h2><table><tr><th>IPs</th><th>Domains</th><th>URLs</th><th>DNS queries</th></tr><tr><td>${(network?.ips ?? []).map(escapeHtml).join("<br>") || unavailable}</td><td>${(network?.domains ?? []).map(escapeHtml).join("<br>") || unavailable}</td><td>${(network?.urls ?? []).map(escapeHtml).join("<br>") || unavailable}</td><td>${(network?.dns_queries ?? []).map(escapeHtml).join("<br>") || unavailable}</td></tr></table>
      <h2>${t.geo}</h2>${list(geoRecords, unavailable, (g: any) => `<b>${escapeHtml(g.ip)}</b> - ${escapeHtml([g.city, g.region, g.country].filter(Boolean).join(", ") || unavailable)}; ISP: ${escapeHtml(g.isp || g.asn_org || unavailable)}; ASN: ${escapeHtml(g.asn ? `AS${g.asn}` : unavailable)}`)}<p class="muted"><b>Disclaimer:</b> ${t.disclaimer}</p>
      <div class="footer"><span>${escapeHtml(reportId)}</span><span>OFFICIAL - FORENSIC USE ONLY</span></div></section>
      ${correlationPage}
      <section class="page"><h2>${t.mitre}</h2><table><tr><th>Technique</th><th>Name</th><th>Confidence</th></tr>${(activeCase.mitreTechniques ?? []).map((m: any) => `<tr><td>${escapeHtml(m.technique_id)}</td><td>${escapeHtml(m.technique_name)}</td><td>${typeof m.confidence === "number" ? `${Math.round(m.confidence * 100)}%` : unavailable}</td></tr>`).join("") || `<tr><td colspan="3">${unavailable}</td></tr>`}</table>
      <h2>${t.capability}</h2>${list(activeCase.capabilityTags ?? [], unavailable, (c: any) => `<b>${escapeHtml(c.capability)}</b>: ${escapeHtml(Array.isArray(c.evidence) ? c.evidence.join("; ") : c.evidence)}`)}<h3>${language === "gu" ? "ભલામણો" : "Recommendations"}</h3>${list(recommendations, unavailable, r => escapeHtml(r))}
      <h2>${t.custody}</h2><div class="card"><p>${language === "gu" ? "આ અહેવાલ નીચેના SHA-256 એન્કર દ્વારા વિશ્લેષિત આર્ટિફેક્ટ સાથે જોડાયેલ છે." : "This report is anchored to the analysed artifact by the following SHA-256 digest."}</p><p class="hash"><b>SHA-256:</b> ${escapeHtml(activeCase.sha256 || activeCase.hash)}</p><p><b>${language === "gu" ? "પરીક્ષક" : "Examiner"}:</b> ${escapeHtml(examiner?.full_name || examiner?.email || unavailable)}<br><b>${language === "gu" ? "વિભાગ" : "Department"}:</b> ${escapeHtml(examiner?.department || unavailable)}<br><b>Timestamp:</b> ${escapeHtml(new Date().toISOString())}</p></div>
      <div class="footer"><span>${escapeHtml(reportId)}</span><span>OFFICIAL - FORENSIC USE ONLY</span></div></section>
    </article>`;
  document.body.appendChild(body);
  try {
    await document.fonts.ready;
    const pages = Array.from(body.querySelectorAll<HTMLElement>(".page"));
    const pdf = new jsPDF({ unit: "mm", format: "a4", compress: true });
    for (let index = 0; index < pages.length; index += 1) {
      const canvas = await html2canvas(pages[index], { scale: 2, useCORS: true, backgroundColor: "#ffffff", logging: false });
      if (index) pdf.addPage();
      pdf.addImage(canvas.toDataURL("image/jpeg", 0.92), "JPEG", 0, 0, 210, 297, undefined, "FAST");
      pdf.setFontSize(7); pdf.setTextColor(90); pdf.text(`${index + 1} / ${pages.length}`, 190, 291, { align: "right" });
    }
    const safeName = (activeCase.name || "forensic_report").replace(/[^\w.-]+/g, "_");
    pdf.save(`${safeName}_Forensic_Report_${language}.pdf`);
  } finally { body.remove(); }
}
