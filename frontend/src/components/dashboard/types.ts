import { YaraMatchDetail, PackingInfo, ExplainedStringDetail, GeoIocDetail } from "../../lib/api";

export interface ThreatCase {
  id: string;
  name: string;
  type: "APK" | "PE" | "SYS" | "ELF" | "MACH_O";
  size: string;
  hash: string;
  riskScore: number;
  status: "ACTIVE_TRACE" | "QUARANTINED" | "CLEARED" | "ANALYZING";
  date: string;
  agency: string;
  mitreCount: number;
  yaraMatches: string[];
  narrativeSummary?: string;
  mitreTechniques?: any[];
  capabilityTags?: any[];
  sandboxResult?: any;
  sha256?: string | null;
  md5?: string | null;
  sha1?: string | null;
  yaraMatchDetails?: YaraMatchDetail[];
  packing?: PackingInfo | null;
  explainedStrings?: ExplainedStringDetail[];
  geoIocs?: GeoIocDetail[];
}
