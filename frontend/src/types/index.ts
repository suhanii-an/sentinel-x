/** API types, mirroring the FastAPI schemas in backend/app/schemas. */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type AlertStatus = 'new' | 'investigating' | 'escalated' | 'resolved' | 'false_positive'
export type IncidentStatus =
  | 'open'
  | 'investigating'
  | 'contained'
  | 'resolved'
  | 'false_positive'
export type Role = 'viewer' | 'analyst' | 'admin'

export interface ApiErrorBody {
  error: { code: string; message: string; details?: unknown }
}

export interface Page<T> {
  items: T[]
  total: number
  limit: number
  offset: number
}

export interface CurrentUser {
  username: string
  email: string | null
  full_name: string | null
  role: Role
  is_active: boolean
  last_login_at: string | null
}

export interface LoginResponse {
  access_token: string
  token_type: string
  expires_at: string
  user: CurrentUser
}

export interface SecurityEvent {
  event_id: string
  timestamp: string
  event_type: string
  source: string
  host_ref: string | null
  user_ref: string | null
  source_ip: string | null
  destination_ip: string | null
  action: string | null
  status: string
  process_name: string | null
  is_demo: boolean
}

export interface SecurityEventDetail extends SecurityEvent {
  ingested_at: string
  destination_port: number | null
  protocol: string | null
  bytes_out: number | null
  process_id: number | null
  parent_process: string | null
  command_line: string | null
  file_path: string | null
  file_hash: string | null
  cloud_provider: string | null
  cloud_account: string | null
  cloud_service: string | null
  cloud_resource: string | null
  cloud_region: string | null
  message: string | null
  metadata: Record<string, unknown>
  raw_event: Record<string, unknown>
  label: string | null
  label_scenario: string | null
}

export interface Alert {
  alert_id: string
  detected_at: string
  created_at: string
  rule_id: string
  rule_name: string
  rule_type: string
  title: string
  severity: Severity
  confidence: number
  risk_score: number
  status: AlertStatus
  host_ref: string | null
  user_ref: string | null
  source_ip: string | null
  technique_ids: string[]
  tactics: string[]
  detection_latency_ms: number
  is_demo: boolean
  incident_id: string | null
}

export interface RiskComponent {
  factor: string
  weight: number
  value: number
  contribution: number
  explanation: string
}

export interface AlertDetail extends Alert {
  description: string
  explanation: string[]
  risk_breakdown: RiskComponent[]
  entity_keys: string[]
  first_event_at: string
  last_event_at: string
  processing_latency_ms: number
  triaged_by: string | null
  triaged_at: string | null
  false_positive_reason: string | null
  evidence: SecurityEvent[]
}

export interface Incident {
  incident_id: string
  title: string
  severity: Severity
  status: IncidentStatus
  confidence: number
  risk_score: number
  first_seen: string
  last_seen: string
  alert_count: number
  event_count: number
  affected_hosts: string[]
  affected_users: string[]
  technique_ids: string[]
  assigned_to: string | null
  is_demo: boolean
}

export interface AttackChainStage {
  tactic_id: string
  tactic: string
  order: number
  techniques: { technique_id: string; name: string; confidence: number }[]
  first_seen: string
  last_seen: string
  detected_at: string
  confidence: number
  evidence_event_ids: string[]
}

export interface TechniqueMapping {
  technique_id: string
  name: string
  tactic_id: string | null
  tactic_name: string | null
  confidence: number
  first_observed: string
  last_observed: string
  detected_at: string
  evidence_event_ids: string[]
  source_rule_ids: string[]
  url: string | null
}

export interface CorrelationReason {
  method: string
  window_seconds: number
  alert_count: number
  event_count: number
  events_by_type: Record<string, number>
  linking_entities: { entity: string; alert_count: number }[]
  contributing_rules: string[]
  confidence: number
  duration_seconds: number
  merged_from?: { incident_id: string; alert_count: number; merged_at: string }[]
}

export interface AnalystNote {
  author: string
  body: string
  created_at: string
}

export interface IncidentDetail extends Incident {
  summary: string
  created_at: string
  updated_at: string
  duration_seconds: number
  targeted_users: string[]
  source_ips: string[]
  destination_ips: string[]
  risk_breakdown: RiskComponent[]
  confidence_breakdown: RiskComponent[]
  correlation_reason: CorrelationReason
  attack_chain: AttackChainStage[]
  ioc_matches: {
    ioc_id: string
    indicator: string
    ioc_type: string
    matched_field: string
    confidence: number
  }[]
  mttr_seconds: number | null
  closed_at: string | null
  false_positive_reason: string | null
  alerts: Alert[]
  techniques: TechniqueMapping[]
  notes: AnalystNote[]
}

export interface TimelineEntry {
  event_id: string
  timestamp: string
  event_type: string
  source?: string
  action: string | null
  status: string
  host: string | null
  user: string | null
  source_ip: string | null
  destination_ip?: string | null
  process?: string | null
  command_line?: string | null
  file_path?: string | null
  cloud_account?: string | null
  summary: string
  highlights?: Record<string, unknown>
  severity: Severity
  alerts?: { alert_id: string; rule_id: string; severity: Severity; step: string | null; technique_ids: string[] }[]
  alert_count?: number
  alert_ids?: string[]
  incident_ids?: string[]
  ioc_matches?: { ioc_id: string; indicator: string; field: string }[]
}

export interface GraphNode {
  id: string
  kind: string
  label: string
  severity: Severity
  event_count: number
  attributes: Record<string, unknown>
}

export interface GraphEdge {
  id: string
  source: string
  target: string
  relation: string
  count: number
  event_ids: string[]
}

export interface AttackGraph {
  incident_id: string
  nodes: GraphNode[]
  edges: GraphEdge[]
  truncated: boolean
  total_nodes: number
  total_edges: number
}

export interface Host {
  host_id: string
  hostname: string
  os_family: string
  os_version: string | null
  ip_address: string | null
  environment: string
  criticality: number
  risk_score: number
  is_isolated: boolean
  tags: string[]
  first_seen: string
  last_seen: string
}

export interface HostDetail extends Host {
  notes: string | null
  isolated_at: string | null
  event_count: number
  alert_counts: Record<string, number>
  open_incidents: Incident[]
  recent_alerts: Alert[]
  users: string[]
  top_processes: { process: string; count: number }[]
  network_peers: { destination_ip: string; port: number | null; connections: number }[]
}

export interface IdentityUser {
  user_id: string
  display_name: string | null
  user_type: string
  department: string | null
  is_privileged: boolean
  is_disabled: boolean
  risk_score: number
  tags: string[]
  first_seen: string
  last_seen: string
}

export interface UserDetail extends IdentityUser {
  domain: string | null
  disabled_at: string | null
  event_count: number
  alert_counts: Record<string, number>
  source_ips: { source_ip: string; count: number }[]
  hosts: { host: string; count: number }[]
  authentication_summary: { success: number; failure: number; total: number }
  baseline: Record<string, { value: Record<string, unknown>; observations: number; updated_at: string }>
  open_incidents: Incident[]
  recent_alerts: Alert[]
}

export interface IOC {
  ioc_id: string
  indicator: string
  ioc_type: string
  source: string
  confidence: number
  severity: Severity
  is_active: boolean
  is_blocked: boolean
  match_count: number
  tags: string[]
  first_seen: string
  last_seen: string | null
}

export interface IOCDetail extends IOC {
  description: string | null
  matched_events: SecurityEvent[]
  related_incidents: Incident[]
  affected_hosts: string[]
}

export interface DetectionRule {
  rule_id: string
  name: string
  description: string
  rule_type: string
  severity: Severity
  confidence: number
  enabled: boolean
  category: string
  mitre_techniques: string[]
  tactics: string[]
  trigger_count: number
  last_triggered_at: string | null
  created_at: string
  updated_at: string
  version: string
  author: string
}

export interface DetectionRuleDetail extends DetectionRule {
  definition: Record<string, unknown>
  source_path: string | null
  references: string[]
  false_positives: string[]
  tests: Record<string, unknown>[]
}

export interface RuleTestResult {
  rule_id?: string
  test_name: string
  expected: string
  actual: string
  passed: boolean
  matched_count: number
  detail: string
}

export interface DashboardKpis {
  window_hours: number
  active_incidents: number
  critical_incidents: number
  critical_alerts: number
  open_alerts: number
  hosts_at_risk: number
  hosts_at_risk_list: string[]
  isolated_hosts: number
  disabled_accounts: number
  events_ingested_window: number
  mttd: { seconds: number | null; sample_size: number; definition: string }
  mttr: { seconds: number | null; sample_size: number; definition: string }
  detection_rate: {
    value: number | null
    measured: boolean
    precision?: number
    f1?: number
    eval_id?: string
    measured_at?: string
    dataset_size?: number
    explanation: string
  }
}

export interface Dashboard {
  generated_at: string
  kpis: DashboardKpis
  severity_distribution: { severity: Severity; count: number }[]
  alert_trend: {
    bucket_start: string
    bucket_end: string
    total: number
    critical: number
    high: number
    medium: number
    low: number
  }[]
  technique_distribution: {
    technique_id: string
    name: string
    tactic_id: string | null
    tactic: string | null
    alert_count: number
  }[]
  risk_distribution: { band: string; min: number; max: number; count: number }[]
  top_entities: {
    hosts: { value: string; alert_count: number }[]
    users: { value: string; alert_count: number }[]
    source_ips: { value: string; alert_count: number }[]
  }
  detection_performance: EvaluationSummary | null
}

export interface EvaluationSummary {
  eval_id: string
  measured_at: string
  dataset_name: string
  dataset_seed: number
  dataset_size: number
  precision: number
  recall: number
  f1: number
  true_positives: number
  false_positives: number
  true_negatives: number
  false_negatives: number
  median_latency_ms: number
  p95_latency_ms: number
}

export interface EvaluationRun {
  available?: boolean
  message?: string
  eval_id: string
  status: string
  started_at: string
  finished_at: string | null
  requested_by: string
  dataset: {
    name: string
    seed: number
    size: number
    benign: number
    malicious: number
    ambiguous: number
    composition?: Record<string, unknown>
  }
  metrics: Record<string, number | Record<string, unknown>>
  per_scenario: {
    scenario: string
    label: string
    events: number
    detected_events: number
    event_recall: number
    alert_count: number
    rules_fired: string[]
    detected: boolean
    expected_rules?: string[]
    expected_rules_fired?: string[]
    expected_rules_missed?: string[]
    detection_latency_ms?: number | null
  }[]
  per_rule: {
    rule_id: string
    alerts: number
    true_positive_events: number
    false_positive_events: number
    ambiguous_events: number
    event_precision: number
  }[]
  silent_rules: string[]
  totals: Record<string, number>
  methodology?: Record<string, string>
  error: string | null
}

export interface ScenarioSpec {
  key: string
  name: string
  description: string
  expected_telemetry: string[]
  expected_detections: string[]
  techniques: string[]
  tactics: string[]
  default_parameters: Record<string, unknown>
  safety_notice: string
}

export interface SimulationRun {
  run_id: string
  scenario: string
  scenario_name: string
  status: string
  started_at: string
  finished_at: string | null
  duration_ms: number
  seed: number
  parameters: Record<string, unknown>
  event_count: number
  alert_count: number
  alert_ids: string[]
  incident_ids: string[]
  stage_log: {
    stage: string
    record_count: number
    sources: string[]
    first_seen: string | null
    last_seen: string | null
    offset_seconds: number
  }[]
  coverage: {
    expected_techniques: string[]
    detected_techniques: string[]
    covered: string[]
    missed: string[]
    additional: string[]
    coverage_ratio: number
  }
  error: string | null
  requested_by: string
}

export interface HuntFilter {
  field: string
  operator: string
  value: unknown
}

export interface HuntQuery {
  dataset: 'events' | 'alerts' | 'incidents'
  filters: HuntFilter[]
  logic: 'and' | 'or'
  time_range?: { start?: string; end?: string; last_minutes?: number } | null
  sequence?: {
    steps: { name: string; filters: HuntFilter[]; min_count: number }[]
    within_seconds: number
    correlate_on: string[]
  } | null
  order_by?: string | null
  order: 'asc' | 'desc'
  limit: number
  offset: number
  description?: string
}

export interface HuntResult {
  interpretation: string
  query: HuntQuery
  compiled_sql: string
  total: number
  returned: number
  duration_ms: number
  truncated: boolean
  rows: Record<string, unknown>[]
  matches: {
    correlation: Record<string, string>
    first_seen: string
    last_seen: string
    span_seconds: number
    steps: { name: string; count: number; event_ids: string[]; first_seen: string }[]
    event_ids: string[]
  }[]
}

export interface SavedHunt {
  id: number
  name: string
  description: string
  query: HuntQuery
  created_by: string
  created_at: string
  last_run_at: string | null
  run_count: number
  is_builtin: boolean
}

export interface AiStatus {
  available: boolean
  provider: string
  model: string | null
  suggested_questions: string[]
  message: string
  grounding_policy: Record<string, string>
}

export interface AiAnswer {
  summary: string
  reasoning: string
  evidence_ids: string[]
  mitre_techniques: string[]
  recommended_actions: string[]
  confidence: number
  confidence_rationale: string
  limitations: string[]
}

export interface AiResult {
  incident_id?: string
  investigation_id?: number
  evidence_events_supplied?: number
  task: string
  accepted: boolean
  validation_status: string
  validation_errors: string[]
  answer: AiAnswer | null
  provider: string
  model: string
  latency_ms: number
  grounding: {
    evidence_offered: number
    evidence_cited: string[]
    citations_removed: string[]
    techniques_removed: string[]
  }
  prompt_injection: {
    flagged: boolean
    signals: { signal: string; location: string; excerpt: string }[]
  }
}

export interface ResponseActionSpec {
  action_type: string
  name: string
  description: string
  target_type: string
  destructive: boolean
  reverses: string | null
  production_behaviour: string
  requires_role: string
  simulated: boolean
}

export interface ResponseActionRecord {
  action_id: string
  action_type: string
  target_type: string
  target: string
  status: string
  is_simulated: boolean
  parameters: Record<string, unknown>
  result: Record<string, unknown>
  justification: string | null
  playbook_id: string | null
  playbook_step: number | null
  requested_by: string
  created_at: string
}

export interface PlaybookStep {
  order: number
  title: string
  detail: string
  phase: string
  suggested_action: string | null
  reference: string | null
}

export interface Playbook {
  playbook_id: string
  name: string
  description: string
  trigger_rule_ids: string[]
  trigger_techniques: string[]
  steps: PlaybookStep[]
}

export interface RecommendedAction {
  action_type: string
  target: string
  target_type: string
  priority: 'high' | 'medium' | 'low'
  rationale: string
  playbook_id: string | null
}

export interface IncidentResponseState {
  incident_id: string
  simulation_notice: string
  recommended_actions: RecommendedAction[]
  playbooks: Playbook[]
  actions_taken: ResponseActionRecord[]
  mttr_seconds: number | null
  containment_state: { isolated_hosts: string[]; disabled_accounts: string[] }
}

export interface MitreCoverage {
  catalogue: { technique_count: number; tactic_count: number; note: string }
  covered_techniques: number
  coverage_ratio: number
  uncovered_techniques: string[]
  by_tactic: {
    tactic_id: string
    tactic: string
    order: number
    covered_count: number
    total_count: number
    techniques: {
      technique_id: string
      name: string
      is_subtechnique: boolean
      covered: boolean
      detection_rules: string[]
      observed_in_incidents: number
      url: string | null
    }[]
  }[]
}

export interface CloudOverview {
  notice: string
  window_hours: number
  account_count: number
  identity_count: number
  event_count: number
  privilege_operations: number
  defense_evasion_operations: number
  accounts: {
    cloud_account: string
    provider: string
    regions: string[]
    identities: string[]
    identity_count: number
    services: string[]
    event_count: number
    failed_count: number
    privilege_operations: number
    defense_evasion_operations: number
    first_seen: string
    last_seen: string
  }[]
  risky_identities: CloudIdentity[]
  recent_iam_changes: CloudIamChange[]
}

export interface CloudIdentity {
  identity: string
  cloud_account: string
  identity_type: string | null
  api_calls: number
  distinct_apis: number
  privilege_operations: number
  defense_evasion_operations: number
  denied_attempts: number
  no_mfa_calls: number
  source_ips: string[]
  external_source_ips: string[]
  high_risk_policies: string[]
  services: string[]
  first_seen: string
  last_seen: string
  alert_counts: Record<string, number>
  risk_score: number
  risk_band: Severity
  factors: RiskComponent[]
}

export interface CloudIamChange {
  event_id: string
  timestamp: string
  identity: string | null
  cloud_account: string
  api_call: string | null
  service: string | null
  region: string | null
  resource: string | null
  category: string | null
  risk: string | null
  policy: string | null
  high_risk_policy: boolean
  target_principal: string | null
  source_ip: string | null
  mfa_authenticated: boolean | null
  status: string
  error_code: string | null
}

export interface SearchResult {
  query: string
  kind: string
  total: number
  results: Record<string, SearchHit[]>
  message: string | null
}

export interface SearchHit {
  type: string
  id: string
  href: string
  [key: string]: unknown
}

export interface SystemInfo {
  name: string
  version: string
  environment: string
  database_backend: string
  demo_mode: boolean
  ai: { configured: boolean; provider: string | null; note: string }
  detection: { rules_loaded: number; load_errors: string[] }
  data: {
    events: number
    alerts: number
    incidents: number
    simulated_events: number
    simulated_share: number
  }
  boundaries: Record<string, string>
}

export interface AuditEntry {
  id: number
  created_at: string
  actor: string
  actor_role: string | null
  action: string
  target_type: string | null
  target_id: string | null
  result: string
  ip_address: string | null
  details: Record<string, unknown>
}

export interface ReportSummary {
  report_id: string
  incident_id: string | null
  title: string
  created_at: string
  generated_by: string
  sections: string[]
  ai_assisted: boolean
  length_chars?: number
}

export interface ReportDetail extends ReportSummary {
  content: string
  note?: string | null
}
