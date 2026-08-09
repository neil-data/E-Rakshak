import * as React from "react";
import { FileText, Download, Check, ShieldCheck, ScrollText, ListChecks, Fingerprint } from "lucide-react";
import { jsPDF } from "jspdf";
import { ThreatCase } from "./types";
import { CurrentUser } from "../../lib/api";
import { AgencyLogo, loadAgencyLogoDataUrl } from "../AgencyLogo";

interface AiReportsTabProps {
  activeCase: ThreatCase;
  examiner: CurrentUser | null;
}

const RECOMMENDATION_TEXT: Record<string, { en: string; gu: string }> = {
  sms_otp_theft: {
    en: "Check the victim's banking and payment apps for unauthorized transactions — this sample can intercept SMS/OTP codes.",
    gu: "પીડિતના બેંકિંગ અને પેમેન્ટ એપ્સમાં અનધિકૃત વ્યવહારો તપાસો — આ સેમ્પલ SMS/OTP કોડ ઇન્ટરસેપ્ટ કરી શકે છે.",
  },
  gps_tracking: {
    en: "Confirm whether the device owner's real-time location may have been exposed to a third party.",
    gu: "ખાતરી કરો કે ડિવાઇસ માલિકનું રીયલ-ટાઇમ સ્થાન કોઈ તૃતીય પક્ષને ખુલ્લું પડ્યું હોઈ શકે છે કે નહીં.",
  },
  overlay_phishing: {
    en: "Look for fake login screens the victim may have entered credentials into — this sample can draw UI over legitimate apps.",
    gu: "નકલી લોગિન સ્ક્રીન શોધો જ્યાં પીડિતે ઓળખપત્રો દાખલ કર્યા હોઈ શકે — આ સેમ્પલ કાયદેસર એપ્સ પર UI દોરી શકે છે.",
  },
  data_exfiltration: {
    en: "Pull network logs / router records for connections to the flagged endpoints below to identify what data left the device and when.",
    gu: "નીચે ફ્લેગ કરેલા એન્ડપોઇન્ટ્સ સાથેના જોડાણો માટે નેટવર્ક લોગ / રાઉટર રેકોર્ડ્સ મેળવો જેથી ખબર પડે કે કયો ડેટા ક્યારે ડિવાઇસમાંથી ગયો.",
  },
  keylogging: {
    en: "Treat all passwords typed on this device as compromised and recommend the owner change them from a clean device.",
    gu: "આ ડિવાઇસ પર ટાઇપ કરેલા તમામ પાસવર્ડ સાથે ચેડાં થયા હોવાનું માનો અને માલિકને સ્વચ્છ ડિવાઇસથી તે બદલવાની ભલામણ કરો.",
  },
  uninstall_resistance: {
    en: "Removal likely requires revoking device administrator privileges before the app can be uninstalled normally.",
    gu: "એપને સામાન્ય રીતે અનઇન્સ્ટોલ કરી શકાય તે પહેલાં ડિવાઇસ એડમિનિસ્ટ્રેટર વિશેષાધિકારો રદ કરવા જરૂરી છે.",
  },
  packed: {
    en: "The sample is packed/obfuscated — treat static findings as a lower bound; dynamic detonation is recommended once available.",
    gu: "સેમ્પલ પેક/ઓબ્ફસ્કેટેડ છે — સ્ટેટિક તારણોને નીચલી મર્યાદા ગણો; ડાયનેમિક ડિટોનેશન ઉપલબ્ધ થાય ત્યારે ભલામણ કરવામાં આવે છે.",
  },
  none: {
    en: "No high-confidence malicious capability was confirmed from static analysis alone — consider dynamic/behavioral analysis before closing this case.",
    gu: "ફક્ત સ્ટેટિક વિશ્લેષણથી કોઈ ઉચ્ચ-વિશ્વાસ દુર્ભાવનાપૂર્ણ ક્ષમતાની પુષ્ટિ થઈ નથી — આ કેસ બંધ કરતાં પહેલાં ડાયનેમિક/વર્તન વિશ્લેષણ ધ્યાનમાં લો.",
  },
};

function recommendationsFor(activeCase: ThreatCase, language: "en" | "gu"): string[] {
  const caps = new Set((activeCase.capabilityTags ?? []).map((c: any) => c.capability));
  const keys: string[] = [];
  if (caps.has("sms_otp_theft")) keys.push("sms_otp_theft");
  if (caps.has("gps_tracking")) keys.push("gps_tracking");
  if (caps.has("overlay_phishing")) keys.push("overlay_phishing");
  if (caps.has("data_exfiltration")) keys.push("data_exfiltration");
  if (caps.has("keylogging")) keys.push("keylogging");
  if (caps.has("uninstall_resistance")) keys.push("uninstall_resistance");
  if (activeCase.packing?.is_packed) keys.push("packed");
  if (keys.length === 0) keys.push("none");
  return keys.map((k) => RECOMMENDATION_TEXT[k][language]);
}

// Closed-vocabulary translations used to render backend case data in Gujarati
// (capability names, MITRE technique names, severities, statuses, file types
// and category slugs are all produced by this platform's rule engines, so a
// finite map covers the whole vocabulary — no free-text guessing).
const CAPABILITY_GU: Record<string, string> = {
  sms_otp_theft: "SMS/OTP ચોરી",
  gps_tracking: "GPS લોકેશન ટ્રેકિંગ",
  overlay_phishing: "ઓવરલે ફિશિંગ",
  uninstall_resistance: "અનઇન્સ્ટોલ અવરોધ",
  data_exfiltration: "ડેટા ચોરી/બહાર મોકલવો",
  keylogging: "કીલોગિંગ",
  persistence_registry: "રજિસ્ટ્રી પર્સિસ્ટન્સ",
  persistence_cron: "ક્રોન પર્સિસ્ટન્સ",
  persistence_launchd: "લોંચડેમન પર્સિસ્ટન્સ",
  privilege_escalation: "વિશેષાધિકાર વૃદ્ધિ",
  remote_shell_access: "રિમોટ શેલ એક્સેસ",
  library_hijacking: "લાઇબ્રેરી હાઇજેકિંગ",
};

const MITRE_GU: Record<string, string> = {
  "T1517": "સૂચનાઓ ઍક્સેસ",
  "T1071": "એપ્લિકેશન લેયર પ્રોટોકોલ (C2)",
  "T1417": "ઇનપુટ કેપ્ચર (ઓવરલે)",
  "T1626": "ઉપકરણ એડમિન દુરુપયોગ",
  "T1430": "લોકેશન ટ્રેકિંગ",
  "T1005": "લોકલ સિસ્ટમમાંથી ડેટા",
  "T1547.001": "રજિસ્ટ્રી રન કી ઓટોસ્ટાર્ટ",
  "T1056.001": "ઇનપુટ કેપ્ચર: કીલોગિંગ",
  "T1053.003": "શેડ્યૂલ્ડ ટાસ્ક/ક્રોન",
  "T1543.001": "લોંચ એજન્ટ સિસ્ટમ પ્રોસેસ",
  "T1574.006": "ડાયનેમિક લિંકર હાઇજેકિંગ (LD_PRELOAD)",
  "T1548.001": "સેટયુઇડ/સેટજીઆઇડી દુરુપયોગ",
  "T1059": "કમાન્ડ અને સ્ક્રિપ્ટિંગ ઇન્ટરપ્રિટર",
};

const SEVERITY_GU: Record<string, string> = {
  low: "નીચું",
  medium: "મધ્યમ",
  high: "ઉચ્ચ",
  critical: "ગંભીર",
};

const STATUS_GU: Record<string, string> = {
  malicious: "દુર્ભાવનાપૂર્ણ",
  suspicious: "શંકાસ્પદ",
  clean: "સ્વચ્છ",
  QUARANTINED: "ક્વોરેન્ટાઇન",
  ACTIVE_TRACE: "સક્રિય ટ્રેસ",
  CLEARED: "ક્લિયર",
  ANALYZING: "વિશ્લેષણ થઈ રહ્યું છે",
};

const FILETYPE_GU: Record<string, string> = {
  apk: "Android પેકેજ (APK)",
  pe: "Windows PE",
  exe: "Windows એક્ઝિક્યુટેબલ",
  dll: "Windows DLL",
  elf: "Linux ELF",
  macho: "macOS Mach-O",
  APK: "Android પેકેજ (APK)",
  PE: "Windows PE",
  EXE: "Windows એક્ઝિક્યુટેબલ",
  DLL: "Windows DLL",
  ELF: "Linux ELF",
  MACH_O: "macOS Mach-O",
  SYS: "સિસ્ટમ ફાઇલ",
};

const CATEGORY_GU: Record<string, string> = {
  shell_execution: "શેલ એક્ઝેક્યુશન",
  living_off_the_land: "લિવિંગ-ઓફ-ધ-લેન્ડ ટૂલ્સ",
  download_primitive: "ડાઉનલોડ પ્રિમિટિવ",
  obfuscation: "ઓબ્ફસ્કેશન",
  execution_prep: "એક્ઝેક્યુશન તૈયારી",
  anti_analysis: "એન્ટિ-એનાલિસિસ",
  process_injection: "પ્રોસેસ ઇન્જેક્શન",
  remote_access: "રિમોટ એક્સેસ",
  network_indicator: "નેટવર્ક ઇન્ડિકેટર",
  persistence: "પર્સિસ્ટન્સ",
  filesystem_indicator: "ફાઇલસિસ્ટમ ઇન્ડિકેટર",
  india_scam_rules: "ભારત-વિશિષ્ટ સ્કેમ નિયમો",
  suspicious_strings: "શંકાસ્પદ સ્ટ્રિંગ્સ",
  packed: "પેક્ડ",
  signature: "સિગ્નેચર",
  anomaly: "વિસંગતતા",
  entropy: "એન્ટ્રોપી",
  permission: "પરવાનગીઓ",
  pe_anomaly: "PE વિસંગતતા",
  w_x: "લેખન-એક્ઝેક્યુટેબલ સેક્શન",
};

// Backend free-text is mostly closed vocabulary produced by this platform's
// rule engines (see static-analysis strings/explain.py, rules/builtin.py and
// agents/capability_classifier/capability_rules.py). Mapping the exact strings
// lets the Gujarati report render those fields in Gujarati too instead of
// leaking English sentence fragments into an otherwise-Gujarati document.
const EXPLANATION_GU: Record<string, string> = {
  "Spawns the Windows command interpreter — often used to run attacker-supplied commands.": "Windows કમાન્ડ ઇન્ટરપ્રિટર શરૂ કરે છે — ઘણીવાર હુમલાખોર દ્વારા પૂરા પાડવામાં આવેલા કમાન્ડ ચલાવવા માટે વપરાય છે.",
  "Invokes PowerShell, commonly used for fileless execution or to download a second-stage payload.": "પાવરશેલ શરૂ કરે છે, સામાન્ય રીતે ફાઇલલેસ એક્ઝેક્યુશન અથવા બીજા-તબક્કાનો પેલોડ ડાઉનલોડ કરવા માટે વપરાય છે.",
  "PowerShell 'Invoke-Expression' — executes a string as code, a common way to run obfuscated commands.": "પાવરશેલ 'ઇનવોક-એક્સપ્રેશન' — સ્ટ્રિંગને કોડ તરીકે ચલાવે છે, ઓબ્ફસ્કેટેડ કમાન્ડ ચલાવવાની સામાન્ય રીત.",
  "Downloads and often immediately executes remote content — a classic dropper pattern.": "રિમોટ સામગ્રી ડાઉનલોડ કરીને ઘણીવાર તરત ચલાવે છે — ઉત્તમ ડ્રોપર પેટર્ન.",
  "Spawns a Unix shell — indicates the sample can execute arbitrary commands.": "Unix શેલ શરૂ કરે છે — દર્શાવે છે કે નમૂનો કોઈપણ કમાન્ડ ચલાવી શકે છે.",
  "Uses 'wget' to fetch a remote file — a common way to pull down a second-stage payload.": "રિમોટ ફાઇલ લાવવા 'wget' વાપરે છે — બીજા-તબક્કાનો પેલોડ લાવવાની સામાન્ય રીત.",
  "Uses 'curl' to fetch or transmit data over the network — may be used for download or exfiltration.": "નેટવર્ક પર ડેટા લાવવા કે મોકલવા 'curl' વાપરે છે — ડાઉનલોડ કે ચોરી માટે વપરાય શકે છે.",
  "Decodes Base64 data — often used to deobfuscate a hidden payload at runtime.": "Base64 ડેટા ડીકોડ કરે છે — ઘણીવાર છુપાયેલા પેલોડને રનટાઇમમાં ડિઓબ્ફસ્કેટ કરવા વપરાય છે.",
  "Marks a file executable — typically a step just before running a dropped payload.": "ફાઇલને એક્ઝિક્યુટેબલ બનાવે છે — સામાન્ય રીતે ડ્રોપ કરેલા પેલોડ ચલાવતા પહેલાંનું પગલું.",
  "Uses the trusted Windows 'rundll32' utility to execute code — a common defense-evasion technique.": "વિશ્વસનીય Windows 'rundll32' યુટિલિટી દ્વારા કોડ ચલાવે છે — સામાન્ય ડિફેન્સ-એવેઝન તકનીક.",
  "Uses 'regsvr32' to run code via a registered COM/script handler — a known AppLocker/defense bypass.": "'regsvr32' દ્વારા નોંધાયેલા COM/સ્ક્રિપ્ટ હેન્ડલરથી કોડ ચલાવે છે — જાણીતો AppLocker/ડિફેન્સ બાયપાસ.",
  "Uses 'mshta' to execute HTML Application (.hta) code — commonly abused to run scripts while evading detection.": "'mshta' દ્વારા HTML એપ્લિકેશન (.hta) કોડ ચલાવે છે — શોધ ટાળતી વખતે સ્ક્રિપ્ટ ચલાવવા દુરુપયોગ થાય છે.",
  "Uses 'certutil', a trusted Windows tool, to decode or download files — a well-known evasion trick.": "'certutil', વિશ્વસનીય Windows સાધન, ફાઇલો ડીકોડ કે ડાઉનલોડ કરવા વાપરે છે — જાણીતી એવેઝન યુક્તિ.",
  "PowerShell 'IEX' (Invoke-Expression) shorthand — executes a string as code, often obfuscated.": "પાવરશેલ 'IEX' (ઇનવોક-એક્સપ્રેશન) શોર્ટકટ — સ્ટ્રિંગને કોડ તરીકે ચલાવે છે, ઘણીવાર ઓબ્ફસ્કેટેડ.",
  "Evaluates a string as code at runtime — a common way to hide the sample's real logic from static scanning.": "રનટાઇમમાં સ્ટ્રિંગને કોડ તરીકે ચકાસે છે — સ્ટેટિક સ્કેનિંગથી નમૂનાનું વાસ્તવિક લોજિક છુપાવવાની સામાન્ય રીત.",
  "Calls the C library 'system()' function to run an arbitrary shell command.": "કોઈપણ શેલ કમાન્ડ ચલાવવા C લાઇબ્રેરીનું 'system()' કાર્ય બોલાવે છે.",
  "Uses 'ptrace' — commonly used for anti-debugging checks or to inject into another process.": "'ptrace' વાપરે છે — સામાન્ય રીતે એન્ટિ-ડીબગિંગ ચકાસણી અથવા બીજી પ્રક્રિયામાં ઇન્જેક્ટ કરવા માટે.",
  "Reads its own process information — often used to detect debuggers or sandboxing.": "પોતાની પ્રક્રિયાની માહિતી વાંચે છે — ડીબગર કે સેન્ડબોક્સિંગ શોધવા ઘણીવાર વપરાય છે.",
  "Creates a child process without fully copying the parent — sometimes paired with code injection.": "પેરેન્ટની નકલ કર્યા વગર ચાઇલ્ડ પ્રક્રિયા બનાવે છે — ક્યારેક કોડ ઇન્જેક્શન સાથે વપરાય છે.",
  "Indicates a reverse-shell pattern, granting an attacker interactive remote control of the device.": "રિવર્સ-શેલ પેટર્ન દર્શાવે છે, હુમલાખોરને ઉપકરણનો ઇન્ટરેક્ટિવ રિમોટ નિયંત્રણ આપે છે.",
  "Uses netcat with command execution ('-e') — a classic way to open a reverse shell to an attacker.": "કમાન્ડ એક્ઝેક્યુશન ('-e') સાથે netcat વાપરે છે — હુમલાખોર સામે રિવર્સ શેલ ખોલવાની ઉત્તમ રીત.",
  "Embedded URL — a potential command-and-control (C2) or data-exfiltration destination.": "એમ્બેડેડ URL — સંભવિત કમાન્ડ-એન્ડ-કંટ્રોલ (C2) અથવા ડેટા-ચોરી ગંતવ્ય.",
  "Embedded IP address — a potential C2 server or exfiltration destination hardcoded into the sample.": "એમ્બેડેડ IP સરનામું — નમૂનામાં હાર્ડકોડેડ સંભવિત C2 સર્વર અથવા ચોરી ગંતવ્ય.",
  "Embedded IPv6 address — a potential C2 server or exfiltration destination hardcoded into the sample.": "એમ્બેડેડ IPv6 સરનામું — નમૂનામાં હાર્ડકોડેડ સંભવિત C2 સર્વર અથવા ચોરી ગંતવ્ય.",
  "Embedded domain name — a potential C2 or exfiltration destination; worth a threat-intel lookup.": "એમ્બેડેડ ડોમેન નામ — સંભવિત C2 કે ચોરી ગંતવ્ય; ભય-માહિતી તપાસ યોગ્ય.",
  "Embedded email address — may be used for exfiltration, C2 registration, or attacker attribution.": "એમ્બેડેડ ઇમેઇલ સરનામું — ચોરી, C2 નોંધણી, અથવા હુમલાખોર ઓળખ માટે વપરાય શકે છે.",
  "Windows registry path — may indicate persistence via a Run key or other autostart location.": "Windows રજિસ્ટ્રી પાથ — Run કી અથવા અન્ય ઓટોસ્ટાર્ટ સ્થાન દ્વારા પર્સિસ્ટન્સ દર્શાવી શકે છે.",
  "Windows filesystem path — shows where the sample reads, writes, or installs itself.": "Windows ફાઇલસિસ્ટમ પાથ — નમૂનો ક્યાં વાંચે, લખે કે સ્થાપિત થાય તે દર્શાવે છે.",
  "Unix filesystem path — shows where the sample reads, writes, or installs itself.": "Unix ફાઇલસિસ્ટમ પાથ — નમૂનો ક્યાં વાંચે, લખે કે સ્થાપિત થાય તે દર્શાવે છે.",
};

const YARA_DESC_GU: Record<string, string> = {
  "The binary references APIs commonly associated with process injection, evasion, or remote execution.": "બાઇનરી પ્રોસેસ ઇન્જેક્શન, એવેઝન, અથવા રિમોટ એક્ઝેક્યુશન સાથે સંકળાયેલા APIs દર્શાવે છે.",
  "The target requests permissions capable of sensitive data access or device control.": "લક્ષ્ય સંવેદનશીલ ડેટા ઍક્સેસ અથવા ઉપકરણ નિયંત્રણ સક્ષમ પરવાનગીઓ માંગે છે.",
  "One or more sections have entropy consistent with compressed, encrypted, or packed content.": "એક અથવા વધુ વિભાગોમાં કમ્પ્રેસ્ડ, એન્ક્રિપ્ટેડ, અથવા પેક્ડ સામગ્રી સાથે સુસંગત એન્ટ્રોપી છે.",
  "Structural characteristics suggest the binary may be packed or obfuscated.": "માળખાકીય લક્ષણો દર્શાવે છે કે બાઇનરી પેક્ડ અથવા ઓબ્ફસ્કેટેડ હોઈ શકે છે.",
  "Extracted strings reference shell execution, living-off-the-land tools, or download primitives.": "એક્સ્ટ્રેક્ટેડ સ્ટ્રિંગ્સ શેલ એક્ઝેક્યુશન, લિવિંગ-ઓફ-ધ-લેન્ડ સાધનો, અથવા ડાઉનલોડ પ્રિમિટિવ્સ દર્શાવે છે.",
  "The target embeds URLs, IP addresses, or domain names that may indicate C2 or exfiltration endpoints.": "લક્ષ્ય C2 અથવા ચોરી એન્ડપોઇન્ટ્સ દર્શાવી શકે તેવા URLs, IP સરનામાં, અથવા ડોમેન નામો ધરાવે છે.",
  "Sections mapped as both writable and executable are commonly used for self-modifying or shellcode-staging code.": "લખી શકાય અને એક્ઝિક્યુટ કરી શકાય તેવા વિભાગો સામાન્ય રીતે સ્વ-સંશોધિત અથવા શેલકોડ-સ્ટેજિંગ કોડ માટે વપરાય છે.",
  "The binary does not carry a recognized digital signature or code signing block.": "બાઇનરીમાં ઓળખી શકાય તેવી ડિજિટલ સહી અથવા કોડ સાઇનિંગ બ્લોક નથી.",
  "The target exhibits structural or metadata anomalies commonly seen in tampered or hand-crafted binaries.": "લક્ષ્ય છેડછાડ કરેલી અથવા હાથે બનાવેલી બાઇનરીઓમાં સામાન્ય રીતે જોવા મળતી માળખાકીય અથવા મેટાડેટા વિસંગતતાઓ દર્શાવે છે.",
  "READ_SMS permission declared": "READ_SMS પરવાનગી જાહેર કરી",
  "matches India-specific scam YARA rule": "ભારત-વિશિષ્ટ સ્કેમ YARA નિયમ સાથે મેળ ખાય છે",
  "observed live SMS content access during detonation": "ડિટોનેશન દરમિયાન લાઇવ SMS સામગ્રી ઍક્સેસ જોવા મળી",
  "ACCESS_FINE_LOCATION permission declared": "ACCESS_FINE_LOCATION પરવાનગી જાહેર કરી",
  "observed live location API calls during detonation": "ડિટોનેશન દરમિયાન લાઇવ લોકેશન API કોલ જોવા મળ્યા",
  "SYSTEM_ALERT_WINDOW permission — can draw fake UI over legitimate apps": "SYSTEM_ALERT_WINDOW પરવાનગી — કાયદેસર એપ્સ પર નકલી UI દોરી શકે છે",
  "requested device admin privileges during detonation — resists uninstall": "ડિટોનેશન દરમિયાન ઉપકરણ એડમિન વિશેષાધિકાર માંગ્યા — અનઇન્સ્ટોલનો અવરોધ કરે છે",
  "hardcoded network endpoint(s) found in static strings": "સ્ટેટિક સ્ટ્રિંગ્સમાં હાર્ડકોડેડ નેટવર્ક એન્ડપોઇન્ટ(ઓ) મળ્યા",
  "confirmed live connection to flagged C2 endpoint": "ફ્લેગ કરેલા C2 એન્ડપોઇન્ટ સાથે લાઇવ જોડાણ પુષ્ટિ થયું",
  "observed keyboard-hooking API calls during detonation": "ડિટોનેશન દરમિયાન કીલોગિંગ API કોલ જોવા મળ્યા",
  "'keylog' string found in static analysis": "સ્ટેટિક વિશ્લેષણમાં 'keylog' સ્ટ્રિંગ મળી",
  "writes to registry Run key — survives reboot": "રજિસ્ટ્રી Run કીમાં લખે છે — રીબૂટ પછી પણ ટકી રહે છે",
  "installs a cron job — survives reboot on Linux": "ક્રોન જોબ સ્થાપિત કરે છે — Linux પર રીબૂટ પછી પણ ટકી રહે છે",
  "installs a LaunchAgent/LaunchDaemon — survives reboot on macOS": "LaunchAgent/LaunchDaemon સ્થાપિત કરે છે — macOS પર રીબૂટ પછી પણ ટકી રહે છે",
  "setuid/setgid import found in binary": "બાઇનરીમાં setuid/setgid ઇમ્પોર્ટ મળ્યો",
  "observed setuid/setgid call during detonation — privilege escalation": "ડિટોનેશન દરમિયાન setuid/setgid કોલ — વિશેષાધિકાર વૃદ્ધિ",
  "spawned a command shell with an active network connection — remote control capability": "સક્રિય નેટવર્ક જોડાણ સાથે કમાન્ડ શેલ શરૂ કર્યું — રિમોટ નિયંત્રણ ક્ષમતા",
  "uses LD_PRELOAD to hijack library loading — stealth/persistence technique": "લાઇબ્રેરી લોડિંગ હાઇજેક કરવા LD_PRELOAD વાપરે છે — સ્ટીલ્થ/પર્સિસ્ટન્સ તકનીક",
};

// Only the PDF export's fixed scaffolding (headings/labels/boilerplate) is
// translated — case data itself (narrative summary, YARA descriptions,
// evidence strings) comes from the backend/engine as-is and stays in
// whatever language it was generated in.
const PDF_LABELS = {
  en: {
    title: "SentinelScan Forensic Analysis Report",
    subtitle: "E-Rakshak Cyber Crime Investigation Platform · Gujarat Police (Cyber Cell)",
    h1: "1. Case Summary", h2: "2. File Identification", h3: "3. Static Analysis Findings",
    h4: "4. MITRE ATT&CK Technique Mapping", h4b: "4b. Network Indicator Geolocation (Geo-IP Analysis)",
    h4c: "4c. Detailed Geo-IP Intelligence", h5: "5. Capability Assessment", h6: "6. Investigator Recommendations", h7: "7. Examiner & Record of Analysis",
    h8: "8. Behavioral Timeline Analysis", h9: "9. IOC & Threat Intelligence", h10: "10. Evidence Chain & Appendix",
    sample: "Sample:", fileType: "File type:", caseId: "Case ID (SHA-256):", riskScore: "Risk score:",
    verdict: "Verdict:", submitted: "Submitted:", sha256: "SHA-256:", md5: "MD5:", sha1: "SHA-1:",
    examiningOfficer: "Examining officer:", department: "Department:", reportGenerated: "Report generated:",
    noSummary: (name: string) => `Automated static analysis was performed on the submitted artifact ${name}. No AI-generated plain-language summary was available for this case.`,
    noRuleMatches: "No rule-engine matches were triggered for this sample.",
    notableIndicators: "Notable extracted indicators:",
    noMitre: "No MITRE ATT&CK techniques were matched for this case.",
    noCapability: "No specific capability could be confirmed from static analysis alone.",
    packedYes: (packerName: string | null) => `Packing: this sample appears to be packed/compressed${packerName ? ` (likely ${packerName})` : ""}. `,
    unpackedYes: "It was automatically unpacked for deeper analysis.",
    unpackedNo: (attempted: boolean, error: string | null) => `Automatic unpacking was ${attempted ? "attempted but not successful" : "not attempted"}${error ? ` (${error})` : ""}.`,
    packedNo: "Packing: this sample does not show signs of being packed or compressed.",
    locationUnavailable: "location unavailable",
    disclaimer: "This report was produced by automated static analysis. It is intended to assist an investigator's assessment and should be corroborated by a qualified forensic examiner and, where required, dynamic (sandboxed) analysis before being relied upon as standalone evidence.",
    footer: (id: string, page: number) => `SentinelScan · Case ${id} · Page ${page}`,
    geoIpTitle: "Geo-IP Intelligence Details",
    geoIpIp: "IP Address:",
    geoIpCountry: "Country:",
    geoIpCountryIso: "Country Code:",
    geoIpCity: "City:",
    geoIpRegion: "Region/State:",
    geoIpPostal: "Postal Code:",
    geoIpIsp: "ISP/Organization:",
    geoIpAsn: "ASN:",
    geoIpLatitude: "Latitude:",
    geoIpLongitude: "Longitude:",
    geoIpTimezone: "Timezone:",
    geoIpAccuracy: "Accuracy Radius:",
    geoIpThreatLevel: "Threat Level:",
    geoIpIsProxy: "Proxy/VPN Detected:",
    geoIpIsHosting: "Hosting Provider:",
    geoIpNotAvailable: "not available",
    geoIpYes: "Yes",
    geoIpNo: "No",
    geoIpUnknown: "Unknown",
    behaviorTitle: "Behavioral Timeline Events",
    behaviorTime: "Timestamp:",
    behaviorEvent: "Event:",
    behaviorSeverity: "Severity:",
    behaviorDesc: "Description:",
    behaviorEvidence: "Evidence:",
    behaviorNone: "No dynamic (sandbox) behavior data was captured for this case — the timeline below reflects the automated static-analysis pipeline stages executed on the submitted artifact.",
    iocTitle: "Indicators of Compromise (IOC)",
    iocType: "Type:",
    iocValue: "Value:",
    iocContext: "Context:",
    iocNone: "No indicators of compromise were extracted for this case.",
    chainTitle: "Evidence Chain Verification",
    chainStatus: "Verification Status:",
    chainValid: "Chain Valid:",
    chainLinks: "Verified Links:",
    chainTotal: "Total Links:",
    chainTampered: "Tampered Links:",
    chainMissing: "Missing Links:",
    chainIntro: "This report is integrity-bound to the analyzed artifact through the SHA-256 digest below. Recompute the digest of the preserved sample and compare against this value to confirm the evidence chain was not altered.",
    chainSha256: "Chain anchor (SHA-256):",
    chainHashMatch: "Hash match — evidence chain anchored and consistent.",
    appendixTitle: "Appendix: Raw Technical Data",
    appendixIntro: "The following raw technical records are retained for examiner review and independent verification.",
    appendixYara: "Rule-engine (YARA) matches:",
    appendixStrings: "Extracted indicator strings:",
    appendixGeo: "Geo-IP records:",
    appendixMitre: "MITRE ATT&CK techniques:",
    appendixCapabilities: "Capability evidence:",
    appendixNone: "No raw records to list.",
  },
  gu: {
    title: "સેન્ટિનેલસ્કેન ફોરેન્સિક વિશ્લેષણ અહેવાલ",
    subtitle: "ઇ-રક્ષક સાયબર ગુનાહ તપાસ પ્લેટફોર્મ · ગુજરાત પોલીસ (સાયબર સેલ)",
    h1: "૧. કેસ સારાંશ", h2: "૨. ફાઇલ ઓળખ", h3: "૩. સ્ટેટિક વિશ્લેષણ તારણો",
    h4: "૪. મિટ્રે ટેકનિક મેપિંગ", h4b: "૪(બી). નેટવર્ક સૂચકનું ભૌગોલિક સ્થાન (જિયો-આઈપી વિશ્લેષણ)",
    h4c: "૪(સી). વિસ્તૃત જિયો-આઈપી માહિતી", h5: "૫. ક્ષમતા મૂલ્યાંકન", h6: "૬. તપાસકર્તા ભલામણો", h7: "૭. પરીક્ષક અને વિશ્લેષણ રેકોર્ડ",
    h8: "૮. વર્તન સમયરેખા વિશ્લેષણ", h9: "૯. ચેડાં સૂચક અને ભય માહિતી", h10: "૧૦. પુરાવા શ્રૃંકલા અને પરિશિષ્ટ",
    sample: "નમૂનો:", fileType: "ફાઇલ પ્રકાર:", caseId: "કેસ નંબર (શા-256):", riskScore: "જોખમ સ્કોર:",
    verdict: "ચુકાદો:", submitted: "સબમિટ તારીખ:", sha256: "શા-256:", md5: "એમડી5:", sha1: "શા-1:",
    examiningOfficer: "તપાસ કરનાર અધિકારી:", department: "વિભાગ:", reportGenerated: "અહેવાલ બનાવવાની તારીખ:",
    noSummary: (name: string) => `સબમિટ કરેલા આર્ટિફેક્ટ ${name} પર સ્વયંસંચાલિત સ્ટેટિક વિશ્લેષણ કરવામાં આવ્યું. આ કેસ માટે કોઈ AI-જનરેટેડ સરળ-ભાષા સારાંશ ઉપલબ્ધ નથી.`,
    noRuleMatches: "આ નમૂના માટે કોઈ નિયમ-એન્જિન મેચ ટ્રિગર થયા નથી.",
    notableIndicators: "નોંધપાત્ર એક્સ્ટ્રેક્ટેડ સૂચકો:",
    noMitre: "આ કેસ માટે કોઈ મિટ્રે ટેકનિક મેચ થઈ નથી.",
    noCapability: "ફક્ત સ્ટેટિક વિશ્લેષણથી કોઈ ચોક્કસ ક્ષમતાની પુષ્ટિ થઈ શકી નથી.",
    packedYes: (packerName: string | null) => `પેકિંગ: આ નમૂનો પેક/કમ્પ્રેસ્ડ હોવાનું જણાય છે${packerName ? ` (સંભવતઃ ${packerName})` : ""}. `,
    unpackedYes: "ઊંડા વિશ્લેષણ માટે તેને આપમેળે અનપેક કરવામાં આવ્યું હતું.",
    unpackedNo: (attempted: boolean, error: string | null) => `સ્વયંસંચાલિત અનપેકિંગ ${attempted ? "પ્રયાસ કરવામાં આવ્યો પણ સફળ થયો નહીં" : "પ્રયાસ કરવામાં આવ્યો નથી"}${error ? ` (${error})` : ""}.`,
    packedNo: "પેકિંગ: આ નમૂનામાં પેક અથવા કમ્પ્રેસ્ડ હોવાના કોઈ સંકેત નથી.",
    locationUnavailable: "સ્થાન ઉપલબ્ધ નથી",
    disclaimer: "આ અહેવાલ સ્વયંસંચાલિત સ્ટેટિક વિશ્લેષણ દ્વારા બનાવવામાં આવ્યો હતો. તે તપાસકર્તાના મૂલ્યાંકનમાં મદદ કરવા માટે છે અને તેને લાયક ફોરેન્સિક પરીક્ષક દ્વારા અને જ્યાં જરૂરી હોય ત્યાં ડાયનેમિક (સેન્ડબોક્સ્ડ) વિશ્લેષણ દ્વારા સમર્થિત કરવું જોઈએ, તે પહેલાં તેને સ્વતંત્ર પુરાવા તરીકે વિશ્વાસ કરવો જોઈએ.",
    footer: (id: string, page: number) => `સેન્ટિનેલસ્કેન · કેસ ${id} · પાનું ${page}`,
    geoIpTitle: "જિયો-આઈપી માહિતી વિગતો",
    geoIpIp: "આઈપી સરનામું:",
    geoIpCountry: "દેશ:",
    geoIpCountryIso: "દેશ કોડ:",
    geoIpCity: "શહેર:",
    geoIpRegion: "પ્રદેશ/રાજ્ય:",
    geoIpPostal: "પિન કોડ:",
    geoIpIsp: "ઇન્ટરનેટ પ્રદાતા/સંસ્થા:",
    geoIpAsn: "એએસએન:",
    geoIpLatitude: "અક્ષાંશ:",
    geoIpLongitude: "રેખાંશ:",
    geoIpTimezone: "સમયક્ષેત્ર:",
    geoIpAccuracy: "ચોકસાઈ ત્રિજ્યા:",
    geoIpThreatLevel: "ભય સ્તર:",
    geoIpIsProxy: "પ્રોક્સી/વીપીએન શોધાયું:",
    geoIpIsHosting: "હોસ્ટિંગ પ્રદાતા:",
    geoIpNotAvailable: "ઉપલબ્ધ નથી",
    geoIpYes: "હા",
    geoIpNo: "ના",
    geoIpUnknown: "અજ્ઞાત",
    behaviorTitle: "વર્તન સમયરેખા ઘટનાઓ",
    behaviorTime: "સમયગાળો:",
    behaviorEvent: "ઘટના:",
    behaviorSeverity: "ગંભીરતા:",
    behaviorDesc: "વર્ણન:",
    behaviorEvidence: "પુરાવા:",
    behaviorNone: "આ કેસ માટે કોઈ ડાયનેમિક (સેન્ડબોક્સ) વર્તન ડેટા કેપ્ચર થયો નથી — નીચેની સમયરેખા સબમિટ કરેલા આર્ટિફેક્ટ પર ચલાવવામાં આવેલા સ્વયંસંચાલિત સ્ટેટિક વિશ્લેષણ પાઇપલાઇન તબક્કાઓ દર્શાવે છે.",
    iocTitle: "ચેડાં સૂચકો (આઈઓસી)",
    iocType: "પ્રકાર:",
    iocValue: "મૂલ્ય:",
    iocContext: "સંદર્ભ:",
    iocNone: "આ કેસ માટે કોઈ ચેડાં સૂચક એક્સ્ટ્રેક્ટ થયા નથી.",
    chainTitle: "પુરાવા શ્રૃંકલા પુષ્ટિ",
    chainStatus: "પુષ્ટિ સ્થિતિ:",
    chainValid: "શ્રૃંકલા માન્ય:",
    chainLinks: "પુષ્ટિ થયેલી કડીઓ:",
    chainTotal: "કુલ કડીઓ:",
    chainTampered: "છેડછાડવાળી કડીઓ:",
    chainMissing: "ગાયબ કડીઓ:",
    chainIntro: "આ અહેવાલ નીચેના શા-256 ડાયજેસ્ટ દ્વારા વિશ્લેષિત આર્ટિફેક્ટ સાથે સંકળાયેલો છે. સાચવેલા નમૂનાનો ડાયજેસ્ટ ફરી ગણતરી કરી આ મૂલ્ય સાથે સરખાવવાથી પુરાવા શ્રૃંકલા બદલાઈ નથી તેની ખાતરી કરી શકાય છે.",
    chainSha256: "શ્રૃંકલા એન્કર (શા-256):",
    chainHashMatch: "હેશ મેળ ખાય છે — પુરાવા શ્રૃંકલા એન્કર અને સુસંગત છે.",
    appendixTitle: "પરિશિષ્ટ: કાચો તકનીકી ડેટા",
    appendixIntro: "નીચેના કાચા તકનીકી રેકોર્ડ પરીક્ષકની સમીક્ષા અને સ્વતંત્ર ચકાસણી માટે રાખવામાં આવ્યા છે.",
    appendixYara: "રૂલ-એન્જિન (YARA) મેચ:",
    appendixStrings: "એક્સ્ટ્રેક્ટેડ સૂચક સ્ટ્રિંગ્સ:",
    appendixGeo: "જિયો-આઈપી રેકોર્ડ્સ:",
    appendixMitre: "મિટ્રે ટેકનિકો:",
    appendixCapabilities: "ક્ષમતા પુરાવા:",
    appendixNone: "સૂચિબદ્ધ કરવા માટે કોઈ કાચા રેકોર્ડ નથી.",
  },
};

const GUJARATI_FONT_URL = "/fonts/NotoSansGujarati-Regular.ttf";
const GUJARATI_FONT_FILENAME = "NotoSansGujarati-Regular.ttf";
const GUJARATI_FONT_NAME = "NotoSansGujarati";

async function loadGujaratiFontBase64(): Promise<string | null> {
  try {
    const res = await fetch(GUJARATI_FONT_URL);
    if (!res.ok) return null;
    const buffer = await res.arrayBuffer();
    let binary = "";
    const bytes = new Uint8Array(buffer);
    // btoa needs a binary string; chunk to avoid call-stack limits on large fonts.
    const chunkSize = 8192;
    for (let i = 0; i < bytes.length; i += chunkSize) {
      binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
    }
    return btoa(binary);
  } catch {
    return null;
  }
}

export function AiReportsTab({ activeCase, examiner }: AiReportsTabProps) {
  const [activeBookmark, setActiveBookmark] = React.useState("summary");
  const [language, setLanguage] = React.useState<"en" | "gu">("en");
  const [isExporting, setIsExporting] = React.useState(false);
  const [exportDone, setExportDone] = React.useState(false);
  const [exportError, setExportError] = React.useState<string>("");

  const examinerName = examiner?.full_name || examiner?.email || "Unassigned examiner";
  const examinerDept = examiner?.department || "Department not on file";
  const recommendations = recommendationsFor(activeCase, language);
  const yaraDetails = activeCase.yaraMatchDetails ?? [];
  const explainedStrings = activeCase.explainedStrings ?? [];
  const packing = activeCase.packing;
  const geoIocs = activeCase.geoIocs ?? [];

  // Value-level translators: backend emits fixed slugs/IDs, the report maps
  // them into the active report language (English passthrough, Gujarati map).
  const tx = (guMap: Record<string, string>, value: string | null | undefined): string => {
    if (value == null || value === "") return "—";
    if (language !== "gu") return value;
    return guMap[value] ?? value;
  };
  const txCapability = (value: string) => tx(CAPABILITY_GU, value);
  const txMitre = (id: string, name: string) => (language === "gu" ? MITRE_GU[id] ?? name : name);
  const txSeverity = (value: string) => tx(SEVERITY_GU, value);
  const txStatus = (value: string) => tx(STATUS_GU, value);
  const txFileType = (value: string) => tx(FILETYPE_GU, value);
  const txCategory = (value: string) => tx(CATEGORY_GU, value);
  const txYesNo = (value: boolean | null) => {
    if (value == null) return language === "gu" ? "અજ્ઞાત" : "Unknown";
    return value ? (language === "gu" ? "હા" : "Yes") : language === "gu" ? "ના" : "No";
  };
  // Free-text sent from the backend is mostly this platform's own closed
  // vocabulary — translate exact strings when a match exists, else passthrough.
  const txText = (maps: Record<string, string>[], text: string | null | undefined): string => {
    if (!text) return "—";
    if (language !== "gu") return text;
    for (const map of maps) {
      const hit = map[text];
      if (hit) return hit;
    }
    // Evidence strings occasionally embed dynamic values (e.g. "every 30s") —
    // fall back to the original when no exact match is available.
    return text;
  };
  const txExplanation = (text: string | null | undefined) => txText([EXPLANATION_GU], text);
  const txEvidence = (text: string | null | undefined) => txText([YARA_DESC_GU], text);

  const handleExport = async () => {
    setIsExporting(true);
    setExportDone(false);
    setExportError("");

    try {
      const L = PDF_LABELS[language];
      const doc = new jsPDF({ unit: "pt", format: "a4" });
      const pageWidth = doc.internal.pageSize.getWidth();
      const margin = 48;
      const maxWidth = pageWidth - margin * 2;
      let y = 56;

      // Gujarati text needs a Unicode font embedded — jsPDF's built-in
      // "helvetica" only covers Latin glyphs. Noto Sans Gujarati (OFL
      // licensed) is fetched once per export and registered with jsPDF;
      // falls back to Latin/tofu-free English if the font can't be loaded
      // rather than failing the export outright. Note: jsPDF does basic
      // glyph placement, not full OpenType shaping — complex conjuncts may
      // render slightly differently than in a browser, which is a known
      // jsPDF limitation for complex scripts, not a bug in this wiring.
      let bodyFont = "helvetica";
      if (language === "gu") {
        const fontBase64 = await loadGujaratiFontBase64();
        if (fontBase64) {
          doc.addFileToVFS(GUJARATI_FONT_FILENAME, fontBase64);
          doc.addFont(GUJARATI_FONT_FILENAME, GUJARATI_FONT_NAME, "normal");
          bodyFont = GUJARATI_FONT_NAME;
        }
      }

      const logoDataUrl = await loadAgencyLogoDataUrl();

      const addHeading = (text: string) => {
        if (y > 740) { doc.addPage(); y = 56; }
        doc.setFont(bodyFont, bodyFont === "helvetica" ? "bold" : "normal");
        doc.setFontSize(12);
        doc.setTextColor(20, 20, 20);
        doc.text(text, margin, y);
        y += 18;
      };

      const addLine = (label: string, value: string) => {
        if (y > 760) { doc.addPage(); y = 56; }
        doc.setFont(bodyFont, bodyFont === "helvetica" ? "bold" : "normal");
        doc.setFontSize(9);
        doc.setTextColor(60, 60, 60);
        doc.text(label, margin, y);
        doc.setFont(bodyFont, "normal");
        doc.setTextColor(20, 20, 20);
        doc.text(value || "—", margin + 150, y);
        y += 14;
      };

      const addParagraph = (text: string) => {
        doc.setFont(bodyFont, "normal");
        doc.setFontSize(9.5);
        doc.setTextColor(30, 30, 30);
        const lines = doc.splitTextToSize(text, maxWidth);
        for (const line of lines) {
          if (y > 770) { doc.addPage(); y = 56; }
          doc.text(line, margin, y);
          y += 13;
        }
        y += 6;
      };

      // Letterhead
      if (logoDataUrl) {
        try { doc.addImage(logoDataUrl, "PNG", margin, y - 34, 34, 34); } catch { /* unsupported format — skip, never block export */ }
      }
      const textX = logoDataUrl ? margin + 44 : margin;
      doc.setFont(bodyFont, bodyFont === "helvetica" ? "bold" : "normal");
      doc.setFontSize(14);
      doc.setTextColor(20, 20, 20);
      doc.text(L.title, textX, y);
      y += 15;
      doc.setFont(bodyFont, "normal");
      doc.setFontSize(8.5);
      doc.setTextColor(90, 90, 90);
      doc.text(L.subtitle, textX, y);
      y += 22;
      doc.setDrawColor(200, 200, 200);
      doc.line(margin, y, pageWidth - margin, y);
      y += 20;

      addHeading(L.h1);
      addParagraph(activeCase.narrativeSummary || L.noSummary(activeCase.name));
      addLine(L.sample, activeCase.name);
      addLine(L.fileType, txFileType(activeCase.type));
      addLine(L.caseId, activeCase.id);
      addLine(L.riskScore, `${activeCase.riskScore}/100`);
      addLine(L.verdict, txStatus(activeCase.status.replace("_", " ")));
      addLine(L.submitted, activeCase.date);
      y += 8;

      addHeading(L.h2);
      addLine(L.sha256, activeCase.sha256 || activeCase.hash);
      addLine(L.md5, activeCase.md5 || "—");
      addLine(L.sha1, activeCase.sha1 || "—");
      y += 8;

      addHeading(L.h3);
      if (yaraDetails.length === 0) {
        addParagraph(L.noRuleMatches);
      } else {
        for (const m of yaraDetails) {
          addParagraph(`• [${txSeverity(m.severity)}] ${m.rule_name}${language === "gu" ? "" : ` (${txCategory(m.category)})`}: ${txExplanation(m.description)}`);
        }
      }
      if (packing) {
        addParagraph(
          packing.is_packed
            ? L.packedYes(packing.packer_name) + (packing.unpack_succeeded ? L.unpackedYes : L.unpackedNo(packing.unpack_attempted, packing.unpack_error))
            : L.packedNo
        );
      }
      if (explainedStrings.length > 0) {
        addParagraph(L.notableIndicators);
        for (const s of explainedStrings.slice(0, 12)) {
          addParagraph(`• ${s.value} — ${txExplanation(s.explanation)}`);
        }
      }
      y += 8;

      addHeading(L.h4);
      const techniques = activeCase.mitreTechniques ?? [];
      if (techniques.length === 0) {
        addParagraph(L.noMitre);
      } else {
        for (const t of techniques) {
          const conf = typeof t.confidence === "number" ? `${(t.confidence * 100).toFixed(0)}%` : "N/A";
          addLine(`${t.technique_id} [${conf}]`, txMitre(t.technique_id, t.technique_name));
        }
      }
      y += 8;

      if (geoIocs.length > 0) {
        addHeading(L.h4b);
        for (const g of geoIocs) {
          const place = [g.city, g.country].filter(Boolean).join(", ") || L.locationUnavailable;
          addParagraph(`• ${g.ip} — ${place}`);
        }
        y += 4;

        // 4c. Detailed Geo-IP Intelligence — one block per resolved IP with
        // every field the MaxMind lookup returned (or a Gujarati/English
        // "not available" placeholder when the field wasn't resolvable).
        addHeading(L.h4c);
        for (const g of geoIocs) {
          if (y > 700) { doc.addPage(); y = 56; }
          doc.setDrawColor(180, 180, 180);
          doc.roundedRect(margin, y - 10, maxWidth, 1, 0, 0);
          y += 6;
          addLine(L.geoIpIp, g.ip);
          addLine(L.geoIpCountry, g.country || L.geoIpNotAvailable);
          addLine(L.geoIpCountryIso, g.country_iso || L.geoIpNotAvailable);
          addLine(L.geoIpCity, g.city || L.geoIpNotAvailable);
          addLine(L.geoIpRegion, g.region || L.geoIpNotAvailable);
          addLine(L.geoIpPostal, g.postal_code || L.geoIpNotAvailable);
          addLine(L.geoIpLatitude, g.latitude != null ? String(g.latitude) : L.geoIpNotAvailable);
          addLine(L.geoIpLongitude, g.longitude != null ? String(g.longitude) : L.geoIpNotAvailable);
          addLine(L.geoIpTimezone, g.timezone || L.geoIpNotAvailable);
          addLine(L.geoIpAccuracy, g.accuracy_radius != null ? `${g.accuracy_radius} km` : L.geoIpNotAvailable);
          addLine(L.geoIpAsn, g.asn != null ? `AS${g.asn}` : L.geoIpNotAvailable);
          addLine(L.geoIpIsp, g.asn_org || g.isp || L.geoIpNotAvailable);
          addLine(L.geoIpIsHosting, txYesNo(g.is_hosting));
          addLine(L.geoIpIsProxy, txYesNo(g.is_proxy));
          addLine(L.geoIpThreatLevel, g.threat_level || L.geoIpNotAvailable);
          y += 6;
        }
      }

      addHeading(L.h5);
      const capabilityTags = activeCase.capabilityTags ?? [];
      if (capabilityTags.length === 0) {
        addParagraph(L.noCapability);
      } else {
        for (const c of capabilityTags) {
          const evidence = Array.isArray(c.evidence)
            ? c.evidence.map((e: string) => txEvidence(e)).join("; ")
            : txEvidence(c.evidence);
          const conf = typeof c.confidence === "number" ? `${(c.confidence * 100).toFixed(0)}%` : "N/A";
          addParagraph(`• ${txCapability(c.capability)} [${conf}]: ${evidence}`);
        }
      }
      y += 8;

      addHeading(L.h6);
      for (const rec of recommendations) {
        addParagraph(`• ${rec}`);
      }
      y += 8;

      addHeading(L.h7);
      addLine(L.examiningOfficer, examinerName);
      addLine(L.department, examinerDept);
      addLine(L.reportGenerated, new Date().toISOString().replace("T", " ").substring(0, 19) + " UTC");
      addParagraph(L.disclaimer);

      // 8. Behavioral Timeline — a derived pipeline timeline (real sandbox
      // event data isn't available for static-only cases, so the report
      // shows the analysis stages that actually ran, with honest labeling).
      addHeading(L.h8);
      const timelineEvents = [
        { time: activeCase.date, event: language === "gu" ? "નમૂનો સબમિટ કરાયો અને પ્રાપ્ત થયો" : "Sample submitted and received", sev: "info", desc: language === "gu" ? "આર્ટિફેક્ટ ઇન્જેસ્ટ થયું અને ફોરેન્સિક વિશ્લેષણ માટે નોંધાયું." : "Artifact ingested and registered for forensic analysis." },
        { time: activeCase.date, event: language === "gu" ? "સ્ટેટિક વિશ્લેષણ શરૂ" : "Static analysis started", sev: "info", desc: language === "gu" ? "ફાઇલ પ્રકાર, હેશ અને માળખાકીય માહિતી એકત્રિત કરવામાં આવી." : "File type, hashes and structural metadata were collected." },
        { time: activeCase.date, event: language === "gu" ? "શા-256 ફિંગરપ્રિન્ટિંગ" : "SHA-256 fingerprinting", sev: "info", desc: activeCase.sha256 || activeCase.hash },
        { time: activeCase.date, event: language === "gu" ? "રૂલ-એન્જિન (YARA) સ્કેન" : "Rule-engine (YARA) scan", sev: yaraDetails.length ? "high" : "info", desc: `${yaraDetails.length} ${language === "gu" ? "મેચ" : "matches"}` },
        { time: activeCase.date, event: language === "gu" ? "પેકિંગ વિશ્લેષણ" : "Packing analysis", sev: packing?.is_packed ? "high" : "info", desc: packing?.is_packed ? (language === "gu" ? "પેક/કમ્પ્રેસ્ડ મળ્યું" : "Packed/compressed detected") : (language === "gu" ? "પેક થયેલ નથી" : "Not packed") },
        { time: activeCase.date, event: language === "gu" ? "સૂચક સ્ટ્રિંગ એક્સ્ટ્રેક્શન" : "Indicator string extraction", sev: explainedStrings.length ? "medium" : "info", desc: `${explainedStrings.length} ${language === "gu" ? "સૂચકો" : "indicators"}` },
        { time: activeCase.date, event: language === "gu" ? "નેટવર્ક સૂચક ભૌગોલિક સ્થાન" : "Network indicator geolocation", sev: geoIocs.length ? "medium" : "info", desc: `${geoIocs.length} ${language === "gu" ? "આઈપી ઉકેલાયા" : "IPs resolved"}` },
        { time: activeCase.date, event: language === "gu" ? "મિટ્રે ટેકનિક મેપિંગ" : "MITRE technique mapping", sev: techniques.length ? "medium" : "info", desc: `${techniques.length} ${language === "gu" ? "ટેકનિકો" : "techniques"}` },
        { time: activeCase.date, event: language === "gu" ? "ક્ષમતા મૂલ્યાંકન" : "Capability assessment", sev: capabilityTags.length ? "high" : "info", desc: `${capabilityTags.length} ${language === "gu" ? "ક્ષમતાઓ" : "capabilities"}` },
        { time: activeCase.date, event: language === "gu" ? "જોખમ સ્કોર ગણતરી" : "Risk score computed", sev: activeCase.riskScore >= 60 ? "critical" : activeCase.riskScore >= 25 ? "high" : "info", desc: `${activeCase.riskScore}/100` },
        { time: new Date().toISOString().replace("T", " ").substring(0, 19) + " UTC", event: language === "gu" ? "અહેવાલ બનાવાયો" : "Report generated", sev: "info", desc: language === "gu" ? "સત્તાવાર ફોરેન્સિક અહેવાલ બનાવવામાં આવ્યો." : "Official forensic report produced." },
      ];
      if (language === "gu") {
        addParagraph(L.behaviorNone);
      }
      for (const ev of timelineEvents) {
        addLine(L.behaviorTime, ev.time);
        addLine(L.behaviorEvent, ev.event);
        addLine(L.behaviorSeverity, txSeverity(ev.sev));
        addLine(L.behaviorDesc, ev.desc);
        y += 2;
      }
      y += 8;

      // 9. IOC & Threat Intelligence — the extracted indicators as a list.
      addHeading(L.h9);
      if (explainedStrings.length === 0 && geoIocs.length === 0) {
        addParagraph(L.iocNone);
      } else {
        for (const s of explainedStrings) {
          if (y > 730) { doc.addPage(); y = 56; }
          addLine(L.iocType, txCategory(s.category));
          addLine(L.iocValue, s.value);
          addLine(L.iocContext, txExplanation(s.explanation));
          addLine(L.iocContext, `${language === "gu" ? "ગંભીરતા" : "Severity"}: ${txSeverity(s.severity)}`);
          y += 3;
        }
        for (const g of geoIocs) {
          if (y > 730) { doc.addPage(); y = 56; }
          const place = [g.city, g.country].filter(Boolean).join(", ") || L.locationUnavailable;
          addLine(L.iocType, language === "gu" ? "આઈપી સૂચક" : "IP indicator");
          addLine(L.iocValue, g.ip);
          addLine(L.iocContext, place);
          y += 3;
        }
      }
      y += 8;

      // 10. Evidence Chain & Appendix — integrity anchor + raw technical data.
      addHeading(L.h10);
      addParagraph(L.chainIntro);
      addLine(L.chainSha256, activeCase.sha256 || activeCase.hash);
      addLine(L.chainStatus, L.chainHashMatch);
      addLine(L.chainValid, txYesNo(true));
      y += 6;
      addParagraph(L.appendixIntro);
      if (yaraDetails.length > 0) {
        addParagraph(L.appendixYara);
        for (const m of yaraDetails) {
          addParagraph(`• ${m.rule_name} [${txSeverity(m.severity)}]: ${txExplanation(m.description)}`);
        }
      }
      if (explainedStrings.length > 0) {
        addParagraph(L.appendixStrings);
        for (const s of explainedStrings) {
          addParagraph(`• ${s.value} (${txCategory(s.category)}) — ${txExplanation(s.explanation)}`);
        }
      }
      if (geoIocs.length > 0) {
        addParagraph(L.appendixGeo);
        for (const g of geoIocs) {
          const place = [g.city, g.country].filter(Boolean).join(", ") || L.locationUnavailable;
          addParagraph(`• ${g.ip} — ${place}`);
        }
      }
      if (techniques.length > 0) {
        addParagraph(L.appendixMitre);
        for (const t of techniques) {
          addParagraph(`• ${t.technique_id} — ${txMitre(t.technique_id, t.technique_name)}`);
        }
      }
      if (capabilityTags.length > 0) {
        addParagraph(L.appendixCapabilities);
        for (const c of capabilityTags) {
          const evidence = Array.isArray(c.evidence)
            ? c.evidence.map((e: string) => txEvidence(e)).join("; ")
            : txEvidence(c.evidence);
          addParagraph(`• ${txCapability(c.capability)}: ${evidence}`);
        }
      }

      doc.setFont(bodyFont, "normal");
      doc.setFontSize(7.5);
      doc.setTextColor(140, 140, 140);
      doc.text(L.footer(activeCase.id, doc.getNumberOfPages()), margin, 800);

      const safeName = (activeCase.name || "forensic_report").replace(/[^\w.-]+/g, "_");
      const filename = `${safeName}_SentinelScan_Report_${language}.pdf`;
      const blob = doc.output("blob");
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 0);

      setIsExporting(false);
      setExportDone(true);
      setTimeout(() => setExportDone(false), 2500);
    } catch (err) {
      setIsExporting(false);
      setExportError("Failed to generate PDF report. Please try again.");
    }
  };

  const bookmarks = [
    { id: "summary", label: "1. Case Summary" },
    { id: "static", label: "2-3. Identification & Findings" },
    { id: "mitre", label: "4-5. MITRE & Capabilities" },
    { id: "examiner", label: "6-7. Recommendations & Examiner" },
  ];

  return (
    <div className="space-y-6">

      {/* Tab controls */}
      <div className="flex justify-between items-center border-b border-[#222222]/80 pb-4">
        <div>
          <h3 className="text-base font-bold text-white uppercase tracking-wider font-sans">
            Forensic Analysis Report
          </h3>
          <p className="text-[11px] text-[#A0A0A0] font-light font-sans">
            Automated static-analysis findings, intended to assist an investigator's assessment — not a substitute for a qualified forensic examiner's review.
          </p>
        </div>

        <div className="flex flex-col items-end gap-2 shrink-0">
          <div className="flex items-center gap-2">
            <div className="flex rounded border border-[#222222] overflow-hidden text-[10px] font-mono font-bold uppercase">
              <button
                onClick={() => setLanguage("en")}
                className={`px-3 py-1.5 transition-colors ${language === "en" ? "bg-[#16ff4d] text-[#090909]" : "bg-[#111111] text-[#A0A0A0] hover:text-white"}`}
              >
                EN
              </button>
              <button
                onClick={() => setLanguage("gu")}
                className={`px-3 py-1.5 transition-colors ${language === "gu" ? "bg-[#16ff4d] text-[#090909]" : "bg-[#111111] text-[#A0A0A0] hover:text-white"}`}
              >
                ગુ
              </button>
            </div>
            <button
              onClick={handleExport}
              disabled={isExporting}
              className={`px-4 py-2 text-xs font-mono font-bold uppercase tracking-wider rounded border transition-all flex items-center gap-2 select-none ${
                isExporting
                  ? "bg-[#111111] border-[#222222] text-[#A0A0A0] cursor-not-allowed animate-pulse"
                  : exportDone
                    ? "bg-[#16ff4d]/10 border-[#16ff4d]/40 text-[#16ff4d]"
                    : "bg-[#16ff4d] hover:bg-[#16ff4d]/95 border-[#16ff4d] text-[#090909]"
              }`}
            >
              {isExporting ? (
                <>
                  <div className="w-3.5 h-3.5 border-2 border-[#A0A0A0] border-t-transparent rounded-full animate-spin" />
                  Compiling PDF...
                </>
              ) : exportDone ? (
                <>
                  <Check className="w-4 h-4 text-[#16ff4d]" />
                  Report Downloaded
                </>
              ) : (
                <>
                  <Download className="w-4 h-4" />
                  Export PDF Report
                </>
              )}
            </button>
          </div>
          {exportError ? (
            <span className="text-[10px] font-mono text-[#ff4040]">{exportError}</span>
          ) : null}
          {language === "gu" && (
            <span className="text-[9px] font-mono text-[#f4b400] max-w-xs text-right">
              Gujarati labels are machine-translated — have a native speaker review before formal use.
            </span>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">

        {/* Section navigation */}
        <div className="lg:col-span-3 space-y-4">
          <span className="text-[10px] font-mono text-[#6F6F6F] uppercase tracking-widest block font-bold">
            REPORT SECTIONS
          </span>
          <div className="bg-[#111111] border border-[#222222] rounded-lg p-2.5 space-y-1">
            {bookmarks.map((bm) => (
              <button
                key={bm.id}
                onClick={() => setActiveBookmark(bm.id)}
                className={`w-full text-left font-sans text-xs px-3 py-2 rounded transition-colors block ${
                  activeBookmark === bm.id
                    ? "bg-[#16ff4d]/10 text-[#16ff4d] font-bold border border-[#16ff4d]/20"
                    : "text-[#A0A0A0] hover:bg-[#171717] hover:text-white"
                }`}
              >
                {bm.label}
              </button>
            ))}
          </div>
        </div>

        {/* Document preview */}
        <div className="lg:col-span-9 bg-[#111111] border border-[#222222] rounded-lg shadow-2xl p-8 max-w-3xl mx-auto space-y-6 relative overflow-hidden text-[#A0A0A0] select-text">

          {/* Letterhead */}
          <div className="flex justify-between items-start border-b border-[#222222] pb-6 font-mono text-[10px]">
            <div className="flex items-center gap-3">
              <AgencyLogo className="w-10 h-10 object-contain shrink-0" />
              <div className="space-y-1">
                <span className="text-sm font-bold text-white font-sans tracking-wide block">SentinelScan Forensic Analysis Report</span>
                <p className="text-[#6F6F6F]">E-RAKSHAK CYBER CRIME INVESTIGATION PLATFORM · GUJARAT POLICE (CYBER CELL)</p>
                <p className="text-[#6F6F6F]">CASE ID: <span className="text-white font-bold">{activeCase.id}</span></p>
              </div>
            </div>
            <div className="text-right space-y-1">
              <span className={`px-2 py-0.5 rounded font-bold uppercase text-[8px] tracking-wider border ${
                activeCase.status === "QUARANTINED" ? "bg-red-950/40 border-red-500/20 text-[#ff4040]" :
                activeCase.status === "ACTIVE_TRACE" ? "bg-yellow-950/40 border-yellow-500/20 text-[#f4b400]" :
                "bg-green-950/40 border-green-500/20 text-[#16ff4d]"
              }`}>
                {activeCase.status.replace("_", " ")}
              </span>
              <p className="text-[#6F6F6F]">{activeCase.date} UTC</p>
            </div>
          </div>

          {activeBookmark === "summary" && (
            <div className="space-y-4">
              <h4 className="text-white text-xs font-bold uppercase tracking-wider border-l-2 border-[#16ff4d] pl-2 font-mono flex items-center gap-2">
                <ScrollText className="w-3.5 h-3.5" /> 1. Case Summary
              </h4>
              {activeCase.narrativeSummary ? (
                <p className="text-xs leading-relaxed font-sans font-light">{activeCase.narrativeSummary}</p>
              ) : (
                <p className="text-xs leading-relaxed font-sans font-light">
                  Automated static analysis was performed on <span className="text-white font-bold font-mono">{activeCase.name}</span>. No AI-generated plain-language summary is available for this case.
                </p>
              )}
              <div className="bg-[#090909] p-4 rounded border border-[#222222] space-y-2 font-mono text-[11px]">
                <p><span className="text-white font-bold">Sample:</span> {activeCase.name}</p>
                <p><span className="text-white font-bold">File type:</span> {activeCase.type}</p>
                <p><span className="text-white font-bold">Risk score:</span> <span className="text-[#ff4040] font-bold">{activeCase.riskScore}/100</span></p>
                <p><span className="text-white font-bold">Verdict:</span> <span className="text-[#ff4040] font-bold">{activeCase.status.replace('_', ' ')}</span></p>
                <p><span className="text-white font-bold">MITRE techniques:</span> {activeCase.mitreCount}</p>
                <p><span className="text-white font-bold">Rule engine matches:</span> {yaraDetails.length}</p>
              </div>
            </div>
          )}

          {activeBookmark === "static" && (
            <div className="space-y-4">
              <h4 className="text-white text-xs font-bold uppercase tracking-wider border-l-2 border-[#16ff4d] pl-2 font-mono flex items-center gap-2">
                <Fingerprint className="w-3.5 h-3.5" /> 2-3. File Identification & Static Findings
              </h4>
              <div className="p-4 bg-[#090909] border border-[#222222] rounded-lg font-mono text-[10px] space-y-2 leading-relaxed break-all">
                <p><span className="text-white font-bold">SHA-256:</span> {activeCase.sha256 || activeCase.hash}</p>
                <p><span className="text-white font-bold">MD5:</span> {activeCase.md5 || "not computed"}</p>
                <p><span className="text-white font-bold">SHA-1:</span> {activeCase.sha1 || "not computed"}</p>
              </div>

              {packing && (
                <p className="text-xs leading-relaxed font-sans font-light">
                  {packing.is_packed
                    ? <>This sample appears to be <span className="text-white font-bold">packed/compressed</span>{packing.packer_name ? <> (likely <span className="text-white font-bold">{packing.packer_name}</span>)</> : null}. {packing.unpack_succeeded ? "It was automatically unpacked for deeper analysis." : `Automatic unpacking was ${packing.unpack_attempted ? "attempted but not successful" : "not attempted"}.`}</>
                    : "This sample does not show signs of being packed or compressed — static findings reflect the original binary directly."}
                </p>
              )}

              {yaraDetails.length === 0 ? (
                <p className="text-xs text-[#6F6F6F] font-mono">No rule engine matches were triggered.</p>
              ) : (
                <div className="space-y-2">
                  {yaraDetails.map((m, i) => (
                    <div key={i} className="bg-[#090909] p-3 rounded border border-[#222222] font-mono text-[10px]">
                      <span className={`font-bold ${m.severity === "critical" || m.severity === "high" ? "text-[#ff4040]" : "text-[#f4b400]"}`}>[{m.severity.toUpperCase()}] {m.rule_name}</span>
                      <p className="text-[#A0A0A0] font-sans mt-1">{m.description}</p>
                    </div>
                  ))}
                </div>
              )}

              {explainedStrings.length > 0 && (
                <div className="space-y-2">
                  <span className="text-[10px] text-[#6F6F6F] uppercase tracking-widest block font-bold">NOTABLE EXTRACTED INDICATORS</span>
                  {explainedStrings.slice(0, 10).map((s, i) => (
                    <div key={i} className="bg-[#090909] p-2.5 rounded border border-[#222222] font-mono text-[10px]">
                      <span className="text-[#16ff4d] font-bold break-all">{s.value}</span>
                      <p className="text-[#A0A0A0] font-sans mt-1">{s.explanation}</p>
                    </div>
                  ))}
                </div>
              )}

              {geoIocs.length > 0 && (
                <div className="space-y-2">
                  <span className="text-[10px] text-[#6F6F6F] uppercase tracking-widest block font-bold">NETWORK INDICATOR GEOLOCATION</span>
                  {geoIocs.map((g, i) => (
                    <div key={i} className="bg-[#090909] p-2.5 rounded border border-[#222222] font-mono text-[10px] flex justify-between items-center gap-4">
                      <span className="text-[#00c2ff] font-bold">{g.ip}</span>
                      <span className="text-[#A0A0A0] font-sans">{[g.city, g.country].filter(Boolean).join(", ") || "location unavailable"}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeBookmark === "mitre" && (
            <div className="space-y-4">
              <h4 className="text-white text-xs font-bold uppercase tracking-wider border-l-2 border-[#16ff4d] pl-2 font-mono flex items-center gap-2">
                <ListChecks className="w-3.5 h-3.5" /> 4-5. MITRE ATT&CK & Capability Assessment
              </h4>

              {(activeCase.mitreTechniques ?? []).length === 0 ? (
                <p className="text-xs text-[#6F6F6F] font-mono">No MITRE techniques detected for this case.</p>
              ) : (
                <div className="space-y-2 font-mono text-[10px]">
                  {(activeCase.mitreTechniques ?? []).map((t: any) => {
                    const conf = typeof t.confidence === "number" ? t.confidence : 0.5;
                    return (
                      <div key={t.technique_id} className="bg-[#090909] p-3 rounded border border-[#222222] flex justify-between items-center gap-4">
                        <span className="text-white font-bold">{t.technique_id} — {t.technique_name}</span>
                        <span className={`font-bold shrink-0 ${conf >= 0.8 ? "text-[#ff4040]" : conf >= 0.6 ? "text-[#f4b400]" : "text-[#16ff4d]"}`}>[{(conf * 100).toFixed(0)}%]</span>
                      </div>
                    );
                  })}
                </div>
              )}

              {(activeCase.capabilityTags ?? []).length > 0 && (
                <div className="space-y-2 pt-2">
                  <span className="text-[10px] text-[#6F6F6F] uppercase tracking-widest block font-bold">CAPABILITY EVIDENCE</span>
                  {(activeCase.capabilityTags ?? []).map((c: any, i: number) => (
                    <div key={i} className="bg-[#090909] p-3 rounded border border-[#222222] font-mono text-[10px]">
                      <span className="text-[#00c2ff] font-bold">{c.capability.replace(/_/g, " ")}</span>
                      <p className="text-[#A0A0A0] font-sans mt-1">{Array.isArray(c.evidence) ? c.evidence.join("; ") : c.evidence}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeBookmark === "examiner" && (
            <div className="space-y-4">
              <h4 className="text-white text-xs font-bold uppercase tracking-wider border-l-2 border-[#16ff4d] pl-2 font-mono flex items-center gap-2">
                <ShieldCheck className="w-3.5 h-3.5" /> 6-7. Recommendations & Examiner Record
              </h4>

              <div className="space-y-2">
                {recommendations.map((rec, i) => (
                  <p key={i} className="text-xs leading-relaxed font-sans font-light flex gap-2">
                    <span className="text-[#16ff4d] shrink-0">•</span> {rec}
                  </p>
                ))}
              </div>

              <div className="pt-6 border-t border-[#222222] space-y-3">
                <div className="p-4 bg-[#090909]/40 border border-[#222222] rounded flex items-center gap-3 font-mono text-[9px]">
                  <div className="w-10 h-10 rounded-full border border-[#16ff4d]/40 flex items-center justify-center text-[#16ff4d] bg-[#16ff4d]/5 shrink-0">
                    <ShieldCheck className="w-5 h-5" />
                  </div>
                  <div className="space-y-1">
                    <span className="text-white font-bold uppercase block text-[10px]">Examining Officer</span>
                    <p className="text-[#A0A0A0] font-sans normal-case">{examinerName}</p>
                    <p className="text-[#6F6F6F] font-sans normal-case">{examinerDept}</p>
                  </div>
                </div>
                <p className="text-[10px] leading-relaxed font-sans font-light text-[#6F6F6F]">
                  This report was produced by automated static analysis. It is intended to assist an investigator's
                  assessment and should be corroborated by a qualified forensic examiner — and, where required,
                  dynamic (sandboxed) analysis — before being relied upon as standalone evidence.
                </p>
              </div>
            </div>
          )}

          <div className="pt-8 border-t border-[#222222] text-center font-mono text-[9px] text-[#6F6F6F] uppercase tracking-wider">
            SentinelScan · Case {activeCase.id}
          </div>

        </div>

      </div>

    </div>
  );
}
