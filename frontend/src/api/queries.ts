/**
 * TanStack Query hooks.
 *
 * Query keys are arrays built from the same shape as the request, so
 * invalidating a prefix (`['incidents']`) invalidates every variant of it. Keeps
 * cache invalidation after a mutation to one line instead of a list of keys
 * someone has to remember to extend.
 */
import {
  useMutation,
  useQuery,
  useQueryClient,
  type UseQueryOptions,
} from '@tanstack/react-query'

import { api } from '@/api/client'
import type {
  AiResult,
  AiStatus,
  Alert,
  AlertDetail,
  AttackGraph,
  AuditEntry,
  CloudIdentity,
  CloudOverview,
  Dashboard,
  DashboardKpis,
  DetectionRule,
  DetectionRuleDetail,
  EvaluationRun,
  Host,
  HostDetail,
  HuntQuery,
  HuntResult,
  IOC,
  IOCDetail,
  IdentityUser,
  Incident,
  IncidentDetail,
  IncidentResponseState,
  MitreCoverage,
  Page,
  Playbook,
  ReportDetail,
  ReportSummary,
  ResponseActionSpec,
  RuleTestResult,
  SavedHunt,
  ScenarioSpec,
  SearchResult,
  SecurityEventDetail,
  SimulationRun,
  SystemInfo,
  TimelineEntry,
  UserDetail,
} from '@/types'

type Params = Record<string, string | number | boolean | undefined | null | string[]>
type Options<T> = Omit<UseQueryOptions<T, Error, T, readonly unknown[]>, 'queryKey' | 'queryFn'>

// ------------------------------------------------------------------ dashboard
export const useDashboard = (windowHours = 24) =>
  useQuery({
    queryKey: ['dashboard', windowHours],
    queryFn: () => api.get<Dashboard>('/stats/dashboard', { window_hours: windowHours }),
    refetchInterval: 30_000,
  })

export const useKpis = (windowHours = 24) =>
  useQuery({
    queryKey: ['kpis', windowHours],
    queryFn: () => api.get<DashboardKpis>('/stats/kpis', { window_hours: windowHours }),
    refetchInterval: 20_000,
  })

export const useLiveTimeline = (params: Params = {}) =>
  useQuery({
    queryKey: ['timeline', 'live', params],
    queryFn: () => api.get<TimelineEntry[]>('/events/timeline', params),
    refetchInterval: 15_000,
  })

// --------------------------------------------------------------------- alerts
export const useAlerts = (params: Params = {}) =>
  useQuery({
    queryKey: ['alerts', params],
    queryFn: () => api.get<Page<Alert>>('/alerts', params),
  })

export const useAlert = (alertId: string | undefined) =>
  useQuery({
    queryKey: ['alerts', 'detail', alertId],
    queryFn: () => api.get<AlertDetail>(`/alerts/${alertId}`),
    enabled: Boolean(alertId),
  })

export const useAlertStats = () =>
  useQuery({
    queryKey: ['alerts', 'stats'],
    queryFn: () =>
      api.get<{ by_severity: Record<string, number>; by_status: Record<string, number>; by_rule: { rule_id: string; count: number }[]; total: number }>(
        '/alerts/stats',
      ),
  })

export const useUpdateAlertStatus = () => {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (input: { alertId: string; status: string; reason?: string }) =>
      api.patch<AlertDetail>(`/alerts/${input.alertId}/status`, {
        status: input.status,
        reason: input.reason,
      }),
    onSuccess: () => {
      client.invalidateQueries({ queryKey: ['alerts'] })
      client.invalidateQueries({ queryKey: ['incidents'] })
      client.invalidateQueries({ queryKey: ['kpis'] })
      client.invalidateQueries({ queryKey: ['dashboard'] })
    },
  })
}

// ------------------------------------------------------------------ incidents
export const useIncidents = (params: Params = {}) =>
  useQuery({
    queryKey: ['incidents', params],
    queryFn: () => api.get<Page<Incident>>('/incidents', params),
  })

export const useIncident = (incidentId: string | undefined, options?: Options<IncidentDetail>) =>
  useQuery({
    queryKey: ['incidents', 'detail', incidentId],
    queryFn: () => api.get<IncidentDetail>(`/incidents/${incidentId}`),
    enabled: Boolean(incidentId),
    ...options,
  })

export const useIncidentTimeline = (incidentId: string | undefined) =>
  useQuery({
    queryKey: ['incidents', 'timeline', incidentId],
    queryFn: () =>
      api.get<{ incident_id: string; attack_chain: IncidentDetail['attack_chain']; events: TimelineEntry[]; note: string }>(
        `/incidents/${incidentId}/timeline`,
      ),
    enabled: Boolean(incidentId),
  })

export const useIncidentGraph = (incidentId: string | undefined) =>
  useQuery({
    queryKey: ['incidents', 'graph', incidentId],
    queryFn: () => api.get<AttackGraph>(`/incidents/${incidentId}/graph`),
    enabled: Boolean(incidentId),
  })

export const useIncidentEvidence = (incidentId: string | undefined, params: Params = {}) =>
  useQuery({
    queryKey: ['incidents', 'evidence', incidentId, params],
    queryFn: () =>
      api.get<{ incident_id: string; total: number; events: SecurityEventDetail[] }>(
        `/incidents/${incidentId}/evidence`,
        params,
      ),
    enabled: Boolean(incidentId),
  })

export const useSimilarIncidents = (incidentId: string | undefined) =>
  useQuery({
    queryKey: ['incidents', 'similar', incidentId],
    queryFn: () =>
      api.get<{
        incident_id: string
        method: string
        weights: Record<string, number>
        candidates_considered: number
        similar: {
          incident_id: string
          title: string
          severity: string
          status: string
          risk_score: number
          last_seen: string
          similarity: number
          matched_on: Record<string, { score: number; shared?: string[]; value?: string }>
        }[]
      }>(`/incidents/${incidentId}/similar`),
    enabled: Boolean(incidentId),
  })

export const useUpdateIncidentStatus = () => {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (input: {
      incidentId: string
      status: string
      reason?: string
      assigned_to?: string
    }) =>
      api.patch<IncidentDetail>(`/incidents/${input.incidentId}/status`, {
        status: input.status,
        reason: input.reason,
        assigned_to: input.assigned_to,
      }),
    onSuccess: () => {
      client.invalidateQueries({ queryKey: ['incidents'] })
      client.invalidateQueries({ queryKey: ['kpis'] })
      client.invalidateQueries({ queryKey: ['dashboard'] })
    },
  })
}

export const useAddIncidentNote = () => {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (input: { incidentId: string; body: string }) =>
      api.post<IncidentDetail>(`/incidents/${input.incidentId}/notes`, { body: input.body }),
    onSuccess: () => client.invalidateQueries({ queryKey: ['incidents'] }),
  })
}

// ------------------------------------------------------------------- entities
export const useHosts = (params: Params = {}) =>
  useQuery({ queryKey: ['hosts', params], queryFn: () => api.get<Page<Host>>('/hosts', params) })

export const useHost = (hostId: string | undefined) =>
  useQuery({
    queryKey: ['hosts', 'detail', hostId],
    queryFn: () => api.get<HostDetail>(`/hosts/${hostId}`),
    enabled: Boolean(hostId),
  })

export const useHostTimeline = (hostId: string | undefined) =>
  useQuery({
    queryKey: ['hosts', 'timeline', hostId],
    queryFn: () => api.get<TimelineEntry[]>(`/hosts/${hostId}/timeline`),
    enabled: Boolean(hostId),
  })

export const useUsers = (params: Params = {}) =>
  useQuery({
    queryKey: ['users', params],
    queryFn: () => api.get<Page<IdentityUser>>('/users', params),
  })

export const useUser = (userId: string | undefined) =>
  useQuery({
    queryKey: ['users', 'detail', userId],
    queryFn: () => api.get<UserDetail>(`/users/${userId}`),
    enabled: Boolean(userId),
  })

export const useUserTimeline = (userId: string | undefined) =>
  useQuery({
    queryKey: ['users', 'timeline', userId],
    queryFn: () => api.get<TimelineEntry[]>(`/users/${userId}/timeline`),
    enabled: Boolean(userId),
  })

// ----------------------------------------------------------------------- iocs
export const useIocs = (params: Params = {}) =>
  useQuery({ queryKey: ['iocs', params], queryFn: () => api.get<Page<IOC>>('/iocs', params) })

export const useIoc = (iocId: string | undefined) =>
  useQuery({
    queryKey: ['iocs', 'detail', iocId],
    queryFn: () => api.get<IOCDetail>(`/iocs/${iocId}`),
    enabled: Boolean(iocId),
  })

export const useIocProvenance = () =>
  useQuery({
    queryKey: ['iocs', 'provenance'],
    queryFn: () =>
      api.get<{
        dataset: string
        version: string
        provenance: string
        notice: string
        indicator_count: number
        external_feeds_configured: string[]
        external_feed_support: string
      }>('/iocs/provenance'),
  })

// ----------------------------------------------------------------- detections
export const useDetectionRules = (params: Params = {}) =>
  useQuery({
    queryKey: ['detections', params],
    queryFn: () => api.get<Page<DetectionRule>>('/detections', params),
  })

export const useDetectionRule = (ruleId: string | undefined) =>
  useQuery({
    queryKey: ['detections', 'detail', ruleId],
    queryFn: () => api.get<DetectionRuleDetail>(`/detections/${ruleId}`),
    enabled: Boolean(ruleId),
  })

export const useDetectionStatus = () =>
  useQuery({
    queryKey: ['detections', 'status'],
    queryFn: () =>
      api.get<{
        rules_on_disk: number
        rules_registered: number
        rules_enabled: number
        by_type: Record<string, number>
        load_errors: string[]
        healthy: boolean
      }>('/detections/status'),
  })

export const useRuleTests = () =>
  useQuery({
    queryKey: ['detections', 'tests'],
    queryFn: () =>
      api.get<{
        total: number
        passed: number
        failed: number
        ok: boolean
        rules_without_tests: string[]
        rules_without_negative_tests: string[]
        results: RuleTestResult[]
      }>('/detections/tests'),
  })

export const useToggleRule = () => {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (input: { ruleId: string; enabled: boolean; reason?: string }) =>
      api.patch<DetectionRuleDetail>(`/detections/${input.ruleId}`, {
        enabled: input.enabled,
        reason: input.reason,
      }),
    onSuccess: () => client.invalidateQueries({ queryKey: ['detections'] }),
  })
}

export const useTestRule = () =>
  useMutation({
    mutationFn: (ruleId: string) =>
      api.post<{ rule_id: string; total: number; passed: number; failed: number; results: RuleTestResult[] }>(
        `/detections/${ruleId}/test`,
      ),
  })

// ---------------------------------------------------------------------- mitre
export const useMitreCoverage = () =>
  useQuery({ queryKey: ['mitre', 'coverage'], queryFn: () => api.get<MitreCoverage>('/mitre/coverage') })

export const useMitreTechnique = (techniqueId: string | undefined) =>
  useQuery({
    queryKey: ['mitre', 'technique', techniqueId],
    queryFn: () => api.get<Record<string, unknown>>(`/mitre/techniques/${techniqueId}`),
    enabled: Boolean(techniqueId),
  })

// -------------------------------------------------------------------- hunting
export const useHuntSchema = () =>
  useQuery({
    queryKey: ['hunt', 'schema'],
    queryFn: () =>
      api.get<{
        datasets: Record<string, string[]>
        operators: string[]
        metadata_fields: { note: string; common_keys: string[] }
        sequence: { note: string; correlatable_fields: string[]; max_steps: number }
        safety: string
      }>('/hunt/schema'),
    staleTime: Infinity,
  })

export const useSavedHunts = () =>
  useQuery({ queryKey: ['hunt', 'saved'], queryFn: () => api.get<SavedHunt[]>('/hunt/saved') })

export const useRunHunt = () =>
  useMutation({ mutationFn: (query: HuntQuery) => api.post<HuntResult>('/hunt/run', query) })

export const useTranslateHunt = () =>
  useMutation({
    mutationFn: (input: { question: string; execute: boolean }) =>
      api.post<{
        question: string
        ai: AiResult
        query: HuntQuery | null
        interpretation: string | null
        executed: boolean
        results: HuntResult | null
      }>('/hunt/translate', input),
  })

export const useSaveHunt = () => {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (input: { name: string; description: string; query: HuntQuery }) =>
      api.post<{ id: number; name: string }>('/hunt/saved', input),
    onSuccess: () => client.invalidateQueries({ queryKey: ['hunt', 'saved'] }),
  })
}

// ---------------------------------------------------------------- simulations
export const useScenarios = () =>
  useQuery({
    queryKey: ['simulations', 'scenarios'],
    queryFn: () =>
      api.get<{ safety_notice: string; scenarios: ScenarioSpec[] }>('/simulations/scenarios'),
    staleTime: Infinity,
  })

export const useSimulationRuns = (params: Params = {}) =>
  useQuery({
    queryKey: ['simulations', 'runs', params],
    queryFn: () => api.get<{ total: number; items: SimulationRun[] }>('/simulations/runs', params),
  })

export const useRunSimulation = () => {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (input: { scenario: string; seed?: number; parameters?: Record<string, unknown> }) =>
      api.post<{
        run: SimulationRun
        pipeline: Record<string, number>
        incidents: string[]
        expected_detections: string[]
        actual_detections: string[]
        detections_missing: string[]
        safety_notice: string
      }>('/simulations/run', input),
    onSuccess: () => {
      // A simulation changes essentially everything, so the whole cache is stale.
      client.invalidateQueries()
    },
  })
}

// --------------------------------------------------------------------- response
export const useResponseActions = () =>
  useQuery({
    queryKey: ['response', 'actions'],
    queryFn: () =>
      api.get<{ simulation_notice: string; actions: ResponseActionSpec[] }>('/response/actions'),
    staleTime: Infinity,
  })

export const usePlaybooks = () =>
  useQuery({ queryKey: ['response', 'playbooks'], queryFn: () => api.get<Playbook[]>('/response/playbooks') })

export const useIncidentResponse = (incidentId: string | undefined) =>
  useQuery({
    queryKey: ['response', 'incident', incidentId],
    queryFn: () => api.get<IncidentResponseState>(`/response/incidents/${incidentId}`),
    enabled: Boolean(incidentId),
  })

export const useExecuteAction = () => {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (input: {
      action_type: string
      target: string
      incident_id?: string
      justification?: string
      playbook_id?: string
      playbook_step?: number
    }) => api.post<{ action: Record<string, unknown>; simulation_notice: string }>('/response/execute', input),
    onSuccess: () => {
      client.invalidateQueries({ queryKey: ['response'] })
      client.invalidateQueries({ queryKey: ['incidents'] })
      client.invalidateQueries({ queryKey: ['hosts'] })
      client.invalidateQueries({ queryKey: ['users'] })
      client.invalidateQueries({ queryKey: ['kpis'] })
    },
  })
}

// ------------------------------------------------------------------------- ai
export const useAiStatus = () =>
  useQuery({ queryKey: ['ai', 'status'], queryFn: () => api.get<AiStatus>('/ai/status') })

export const useAiHistory = (incidentId: string | undefined) =>
  useQuery({
    queryKey: ['ai', 'history', incidentId],
    queryFn: () =>
      api.get<{ incident_id: string; total: number; accepted: number; rejected: number; items: Record<string, unknown>[] }>(
        `/ai/incidents/${incidentId}/history`,
      ),
    enabled: Boolean(incidentId),
  })

export const useAskAi = () => {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (input: { incidentId: string; task: string; question?: string; strict?: boolean }) =>
      api.post<AiResult>(`/ai/incidents/${input.incidentId}/investigate`, {
        task: input.task,
        question: input.question,
        strict: input.strict ?? false,
      }),
    onSuccess: (_data, variables) =>
      client.invalidateQueries({ queryKey: ['ai', 'history', variables.incidentId] }),
  })
}

// ------------------------------------------------------------------- reporting
export const useReports = (params: Params = {}) =>
  useQuery({
    queryKey: ['reports', params],
    queryFn: () => api.get<{ total: number; items: ReportSummary[] }>('/reports', params),
  })

export const useReport = (reportId: string | undefined) =>
  useQuery({
    queryKey: ['reports', 'detail', reportId],
    queryFn: () => api.get<ReportDetail>(`/reports/${reportId}`),
    enabled: Boolean(reportId),
  })

export const useGenerateReport = () => {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (input: { incident_id: string; use_ai_summary: boolean }) =>
      api.post<ReportDetail>('/reports', input),
    onSuccess: () => client.invalidateQueries({ queryKey: ['reports'] }),
  })
}

// ------------------------------------------------------------------ evaluation
export const useLatestEvaluation = () =>
  useQuery({ queryKey: ['evaluation', 'latest'], queryFn: () => api.get<EvaluationRun>('/evaluation/latest') })

export const useEvaluationRuns = () =>
  useQuery({
    queryKey: ['evaluation', 'runs'],
    queryFn: () => api.get<{ total: number; items: EvaluationRun[] }>('/evaluation/runs'),
  })

export const useRunEvaluation = () => {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (input: { seed: number; benign_days: number; include_ambiguous: boolean }) =>
      api.post<EvaluationRun>('/evaluation/run', input),
    onSuccess: () => {
      client.invalidateQueries({ queryKey: ['evaluation'] })
      client.invalidateQueries({ queryKey: ['kpis'] })
      client.invalidateQueries({ queryKey: ['dashboard'] })
    },
  })
}

// ---------------------------------------------------------------------- cloud
export const useCloudOverview = (windowHours = 168) =>
  useQuery({
    queryKey: ['cloud', 'overview', windowHours],
    queryFn: () => api.get<CloudOverview>('/cloud/overview', { window_hours: windowHours }),
  })

export const useCloudIdentityGraph = (identity: string | undefined) =>
  useQuery({
    queryKey: ['cloud', 'identity-graph', identity],
    queryFn: () =>
      api.get<{
        identity: string
        window_hours: number
        event_count: number
        nodes: { id: string; kind: string; label: string; count: number; attributes: Record<string, unknown> }[]
        edges: { id: string; source: string; target: string; relation: string; count: number; event_ids: string[] }[]
      }>(`/cloud/identities/${identity}/graph`),
    enabled: Boolean(identity),
  })

export const useCloudIdentities = (windowHours = 168) =>
  useQuery({
    queryKey: ['cloud', 'identities', windowHours],
    queryFn: () =>
      api.get<{ notice: string; risk_model: string; identities: CloudIdentity[] }>('/cloud/identities', {
        window_hours: windowHours,
      }),
  })

// --------------------------------------------------------------------- system
export const useSearch = (term: string) =>
  useQuery({
    queryKey: ['search', term],
    queryFn: () => api.get<SearchResult>('/search', { q: term }),
    enabled: term.trim().length >= 2,
    staleTime: 10_000,
  })

export const useSystemInfo = () =>
  useQuery({ queryKey: ['system', 'info'], queryFn: () => api.get<SystemInfo>('/system/info') })

export const useAuditLog = (params: Params = {}) =>
  useQuery({
    queryKey: ['audit', params],
    queryFn: () => api.get<{ total: number; items: AuditEntry[] }>('/audit', params),
  })

export const useEvent = (eventId: string | undefined) =>
  useQuery({
    queryKey: ['events', 'detail', eventId],
    queryFn: () => api.get<SecurityEventDetail>(`/events/${eventId}`),
    enabled: Boolean(eventId),
  })

export const useRoles = () =>
  useQuery({
    queryKey: ['auth', 'roles'],
    queryFn: () =>
      api.get<{ roles: { role: string; level: number; description: string; can: string[]; cannot: string[] }[] }>(
        '/auth/roles',
      ),
    staleTime: Infinity,
  })
