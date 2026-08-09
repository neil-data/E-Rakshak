"""
risk_scoring.py — Weighted risk score calculation, extracted into its
own module so it's unit-testable in isolation from the graph.

Weighting is intentionally simple and documented here — tune weights
in ONE place if scores don't feel right during demo prep.

PHASE 3 ENHANCEMENTS:
- Added Windows-specific behavior chain scoring
- Added critical severity detection bonuses
- Added advanced persistence and privilege escalation detection
- Added defense evasion activity penalties
"""

from __future__ import annotations
from typing import Optional, Dict, Any

from agents.orchestrator.schema import (
    StaticAnalysisOutput,
    DynamicAnalysisOutput,
    MitreTechnique,
    CapabilityTag,
)

# Weight constants — documented and centralized so they're easy to tune
YARA_MATCH_WEIGHT = 15
MITRE_TECHNIQUE_WEIGHT = 8
CAPABILITY_CONFIDENCE_MULTIPLIER = 15
ML_LIKELY_MALICIOUS_BONUS = 20
DYNAMIC_C2_CONFIRMED_BONUS = 20
DYNAMIC_DEVICE_ADMIN_BONUS = 10

# Windows behavior chain weights (Phase 3)
BEHAVIOR_CHAIN_CRITICAL_WEIGHT = 30
BEHAVIOR_CHAIN_HIGH_WEIGHT = 20
BEHAVIOR_CHAIN_MEDIUM_WEIGHT = 10
BEHAVIOR_CHAIN_LOW_WEIGHT = 5

# Special detection bonuses (Phase 3)
PROCESS_INJECTION_BONUS = 25
PRIVILEGE_ESCALATION_BONUS = 25
KERNEL_DRIVER_BONUS = 30
DEFENSE_EVASION_BONUS = 20
PERSISTENCE_BONUS = 15

# Android-specific bonuses (Phase 4)
ANDROID_SMS_INTERCEPTION_BONUS = 30
ANDROID_LOCATION_TRACKING_BONUS = 25
ANDROID_CLIPBOARD_ATTACK_BONUS = 25
ANDROID_SURVEILLANCE_BONUS = 35
ANDROID_PERMISSION_ESCALATION_BONUS = 30
ANDROID_ACCESSIBILITY_ABUSE_BONUS = 35
ANDROID_OVERLAY_ATTACK_BONUS = 30

# Severity thresholds
CRITICAL_CHAIN_THRESHOLD = 3
HIGH_CHAIN_THRESHOLD = 5

MAX_SCORE = 100
MIN_SCORE = 0


def compute_risk_score(
    static: StaticAnalysisOutput,
    dynamic: Optional[DynamicAnalysisOutput],
    mitre: list[MitreTechnique],
    capabilities: list[CapabilityTag],
) -> int:
    score = 0

    score += len(static.yara_matches) * YARA_MATCH_WEIGHT
    score += len(mitre) * MITRE_TECHNIQUE_WEIGHT
    score += sum(int(c.confidence * CAPABILITY_CONFIDENCE_MULTIPLIER) for c in capabilities)

    if static.ml_classifier and static.ml_classifier.classification == "likely_malicious":
        score += ML_LIKELY_MALICIOUS_BONUS

    if dynamic:
        if any(conn.get("flagged_c2") for conn in dynamic.network_connections):
            score += DYNAMIC_C2_CONFIRMED_BONUS
        if any("DevicePolicyManager" in c for c in dynamic.api_calls):
            score += DYNAMIC_DEVICE_ADMIN_BONUS
        
        # Phase 3: Windows behavior chain scoring
        score += _compute_behavior_chain_score(dynamic)
        
        # Phase 3: Special detection bonuses
        score += _compute_special_detection_bonuses(dynamic)

    return max(MIN_SCORE, min(score, MAX_SCORE))


def _compute_behavior_chain_score(dynamic: DynamicAnalysisOutput) -> int:
    """
    Compute risk score from Windows behavior chains.
    
    Behavior chains are sequences of API calls that together constitute
    malicious behavior. Each chain has an associated risk_point value
    and severity level.
    """
    score = 0
    behavior_chains = dynamic.behavior_chains if hasattr(dynamic, 'behavior_chains') else []
    
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    
    for chain in behavior_chains:
        severity = chain.get('severity', 'low').lower()
        risk_points = chain.get('risk_points', 0)
        
        if severity == 'critical':
            critical_count += 1
            score += risk_points
        elif severity == 'high':
            high_count += 1
            score += risk_points
        elif severity == 'medium':
            medium_count += 1
            score += risk_points
        elif severity == 'low':
            low_count += 1
            score += risk_points
    
    # Bonus for multiple critical chains
    if critical_count >= CRITICAL_CHAIN_THRESHOLD:
        score += CRITICAL_CHAIN_THRESHOLD * BEHAVIOR_CHAIN_CRITICAL_WEIGHT
    
    # Bonus for multiple high chains
    if high_count >= HIGH_CHAIN_THRESHOLD:
        score += HIGH_CHAIN_THRESHOLD * BEHAVIOR_CHAIN_HIGH_WEIGHT
    
    return score


def _compute_special_detection_bonuses(dynamic: DynamicAnalysisOutput) -> int:
    """
    Compute bonus scores for special high-value detections.
    
    These are specific behaviors that are particularly concerning
    and warrant additional risk scoring.
    """
    bonus = 0
    behavior_chains = dynamic.behavior_chains if hasattr(dynamic, 'behavior_chains') else []
    
    # Check for process injection
    injection_chains = [
        'classic_injection', 'injection_no_alloc', 'process_hollowing'
    ]
    if any(chain.get('rule_id') in injection_chains for chain in behavior_chains):
        bonus += PROCESS_INJECTION_BONUS
    
    # Check for privilege escalation
    privilege_chains = [
        'token_impersonation_full', 'token_impersonation_basic',
        'privilege_enable_debug', 'escalate_and_exec'
    ]
    if any(chain.get('rule_id') in privilege_chains for chain in behavior_chains):
        bonus += PRIVILEGE_ESCALATION_BONUS
    
    # Check for kernel driver loading
    driver_chains = [
        'driver_load_from_nonstandard_path', 'drop_and_load_driver', 'byovd_attack'
    ]
    if any(chain.get('rule_id') in driver_chains for chain in behavior_chains):
        bonus += KERNEL_DRIVER_BONUS
    
    # Check for defense evasion
    evasion_chains = [
        'security_process_termination', 'security_service_disabled',
        'security_service_deleted', 'registry_security_disabled'
    ]
    if any(chain.get('rule_id') in evasion_chains for chain in behavior_chains):
        bonus += DEFENSE_EVASION_BONUS
    
    # Check for advanced persistence
    persistence_chains = [
        'service_persistence_install', 'service_hijack', 'drop_and_install_service',
        'file_based_persistence', 'file_moved_to_system_location'
    ]
    if any(chain.get('rule_id') in persistence_chains for chain in behavior_chains):
        bonus += PERSISTENCE_BONUS
    
    # Phase 4: Android-specific bonuses
    # Check for SMS interception
    sms_chains = [
        'android_sms_interception', 'android_sms_exfiltration', 'android_sms_evidence_destruction'
    ]
    if any(chain.get('rule_id') in sms_chains for chain in behavior_chains):
        bonus += ANDROID_SMS_INTERCEPTION_BONUS
    
    # Check for location tracking
    location_chains = [
        'android_location_exfiltration', 'android_cached_location_exfiltration',
        'android_geofencing_surveillance', 'android_high_accuracy_tracking'
    ]
    if any(chain.get('rule_id') in location_chains for chain in behavior_chains):
        bonus += ANDROID_LOCATION_TRACKING_BONUS
    
    # Check for clipboard attacks
    clipboard_chains = [
        'android_crypto_clipper', 'android_clipboard_hijack', 'android_clipboard_exfiltration'
    ]
    if any(chain.get('rule_id') in clipboard_chains for chain in behavior_chains):
        bonus += ANDROID_CLIPBOARD_ATTACK_BONUS
    
    # Check for surveillance (camera/microphone)
    surveillance_chains = [
        'android_audio_surveillance', 'android_covert_audio_recording',
        'android_camera_surveillance', 'android_covert_photo_capture'
    ]
    if any(chain.get('rule_id') in surveillance_chains for chain in behavior_chains):
        bonus += ANDROID_SURVEILLANCE_BONUS
    
    # Check for permission escalation
    permission_chains = [
        'android_permission_escalation', 'android_permission_state_manipulation',
        'android_overlay_permission_request'
    ]
    if any(chain.get('rule_id') in permission_chains for chain in behavior_chains):
        bonus += ANDROID_PERMISSION_ESCALATION_BONUS
    
    # Check for accessibility abuse
    accessibility_chains = [
        'android_accessibility_automation', 'android_accessibility_credential_automation',
        'android_accessibility_navigate_and_act'
    ]
    if any(chain.get('rule_id') in accessibility_chains for chain in behavior_chains):
        bonus += ANDROID_ACCESSIBILITY_ABUSE_BONUS
    
    # Check for overlay attacks
    overlay_chains = [
        'android_overlay_without_permission', 'android_overlay_with_permission_escalation',
        'android_automated_overlay_attack'
    ]
    if any(chain.get('rule_id') in overlay_chains for chain in behavior_chains):
        bonus += ANDROID_OVERLAY_ATTACK_BONUS
    
    return bonus


def compute_windows_risk_profile(
    dynamic: DynamicAnalysisOutput
) -> Dict[str, Any]:
    """
    Generate a detailed Windows risk profile from behavior chains.
    
    This provides detailed breakdown of risk factors for the dashboard
    and reporting, beyond the single numerical score.
    """
    behavior_chains = dynamic.behavior_chains if hasattr(dynamic, 'behavior_chains') else []
    
    profile = {
        'total_chains': len(behavior_chains),
        'critical_chains': [],
        'high_chains': [],
        'medium_chains': [],
        'low_chains': [],
        'risk_categories': {
            'process_injection': False,
            'privilege_escalation': False,
            'kernel_driver': False,
            'defense_evasion': False,
            'persistence': False,
            'ransomware': False,
            'data_exfiltration': False,
            'credential_theft': False,
        },
        'mitre_coverage': set(),
        'total_risk_points': 0,
    }
    
    for chain in behavior_chains:
        severity = chain.get('severity', 'low').lower()
        rule_id = chain.get('rule_id', '')
        risk_points = chain.get('risk_points', 0)
        mitre = chain.get('mitre', [])
        
        profile['total_risk_points'] += risk_points
        profile['mitre_coverage'].update(mitre)
        
        chain_summary = {
            'rule_id': rule_id,
            'name': chain.get('name', ''),
            'risk_points': risk_points,
            'mitre': mitre,
        }
        
        if severity == 'critical':
            profile['critical_chains'].append(chain_summary)
        elif severity == 'high':
            profile['high_chains'].append(chain_summary)
        elif severity == 'medium':
            profile['medium_chains'].append(chain_summary)
        else:
            profile['low_chains'].append(chain_summary)
        
        # Categorize by risk type
        if 'injection' in rule_id or 'hollowing' in rule_id:
            profile['risk_categories']['process_injection'] = True
        if 'token' in rule_id or 'privilege' in rule_id or 'escalate' in rule_id:
            profile['risk_categories']['privilege_escalation'] = True
        if 'driver' in rule_id:
            profile['risk_categories']['kernel_driver'] = True
        if 'security' in rule_id or 'evasion' in rule_id or 'termination' in rule_id:
            profile['risk_categories']['defense_evasion'] = True
        if 'persist' in rule_id or 'service' in rule_id or 'run_key' in rule_id:
            profile['risk_categories']['persistence'] = True
        if 'ransomware' in rule_id or 'encrypt' in rule_id:
            profile['risk_categories']['ransomware'] = True
        if 'exfiltrate' in rule_id or 'collect_and' in rule_id:
            profile['risk_categories']['data_exfiltration'] = True
        if 'credential' in rule_id or 'lsass' in rule_id or 'debug' in rule_id:
            profile['risk_categories']['credential_theft'] = True
    
    profile['mitre_coverage'] = list(profile['mitre_coverage'])
    
    return profile


def compute_android_risk_profile(
    dynamic: DynamicAnalysisOutput
) -> Dict[str, Any]:
    """
    Generate a detailed Android risk profile from behavior chains.
    
    This provides detailed breakdown of Android-specific risk factors
    for the dashboard and reporting.
    """
    behavior_chains = dynamic.behavior_chains if hasattr(dynamic, 'behavior_chains') else []
    
    profile = {
        'total_chains': len(behavior_chains),
        'critical_chains': [],
        'high_chains': [],
        'medium_chains': [],
        'low_chains': [],
        'android_risk_categories': {
            'sms_interception': False,
            'sms_exfiltration': False,
            'contact_abuse': False,
            'location_tracking': False,
            'geofencing': False,
            'clipboard_attack': False,
            'camera_surveillance': False,
            'audio_surveillance': False,
            'accessibility_abuse': False,
            'overlay_attack': False,
            'permission_escalation': False,
            'contact_manipulation': False,
        },
        'mitre_coverage': set(),
        'total_risk_points': 0,
    }
    
    for chain in behavior_chains:
        severity = chain.get('severity', 'low').lower()
        rule_id = chain.get('rule_id', '')
        risk_points = chain.get('risk_points', 0)
        mitre = chain.get('mitre', [])
        
        # Only consider Android-specific chains
        if not rule_id.startswith('android_'):
            continue
            
        profile['total_risk_points'] += risk_points
        profile['mitre_coverage'].update(mitre)
        
        chain_summary = {
            'rule_id': rule_id,
            'name': chain.get('name', ''),
            'risk_points': risk_points,
            'mitre': mitre,
        }
        
        if severity == 'critical':
            profile['critical_chains'].append(chain_summary)
        elif severity == 'high':
            profile['high_chains'].append(chain_summary)
        elif severity == 'medium':
            profile['medium_chains'].append(chain_summary)
        else:
            profile['low_chains'].append(chain_summary)
        
        # Categorize by Android risk type
        if 'sms' in rule_id:
            if 'interception' in rule_id or 'exfiltration' in rule_id:
                profile['android_risk_categories']['sms_interception'] = True
                profile['android_risk_categories']['sms_exfiltration'] = True
        if 'contact' in rule_id:
            if 'smishing' in rule_id or 'exfiltration' in rule_id:
                profile['android_risk_categories']['contact_abuse'] = True
            if 'manipulation' in rule_id or 'replacement' in rule_id:
                profile['android_risk_categories']['contact_manipulation'] = True
        if 'location' in rule_id:
            profile['android_risk_categories']['location_tracking'] = True
        if 'geofencing' in rule_id:
            profile['android_risk_categories']['geofencing'] = True
        if 'clipboard' in rule_id:
            profile['android_risk_categories']['clipboard_attack'] = True
        if 'camera' in rule_id:
            profile['android_risk_categories']['camera_surveillance'] = True
        if 'audio' in rule_id or 'recording' in rule_id:
            profile['android_risk_categories']['audio_surveillance'] = True
        if 'accessibility' in rule_id:
            profile['android_risk_categories']['accessibility_abuse'] = True
        if 'overlay' in rule_id:
            profile['android_risk_categories']['overlay_attack'] = True
        if 'permission' in rule_id:
            profile['android_risk_categories']['permission_escalation'] = True
    
    profile['mitre_coverage'] = list(profile['mitre_coverage'])
    
    return profile