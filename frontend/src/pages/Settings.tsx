/**
 * Platform posture.
 *
 * This page exists to answer "what is this system actually doing, and what is
 * it explicitly not doing" without the reader having to take anything on
 * trust. Every value here is read from the running backend — the rule count,
 * the AI provider, the share of events that are simulated, the boundaries the
 * platform refuses to cross. Nothing on this page is written into the source
 * as a claim about the deployment.
 */
import clsx from 'clsx'
import { AlertOctagon, Bot, Database, ShieldCheck, Workflow } from 'lucide-react'
import { useState } from 'react'

import {
  useAiStatus,
  useDetectionStatus,
  usePlaybooks,
  useResponseActions,
  useRoles,
  useSystemInfo,
} from '@/api/queries'
import {
  Badge,
  Callout,
  Code,
  EmptyState,
  KeyValue,
  Loading,
  Panel,
  QueryBoundary,
  Tabs,
  TabPanel,
} from '@/components/ui'
import { useAuth } from '@/hooks/useAuth'
import { PageBody, PageHeader } from '@/layouts/AppLayout'
import { absoluteTime, compactNumber, percent, titleCase } from '@/utils/format'

const TABS = [
  { id: 'platform', label: 'Platform' },
  { id: 'ai', label: 'AI assistance' },
  { id: 'response', label: 'Response actions' },
  { id: 'access', label: 'Access control' },
  { id: 'account', label: 'Your account' },
]

export function SettingsPage() {
  const [tab, setTab] = useState('platform')

  return (
    <>
      <PageHeader
        title="Settings & Posture"
        description="What this deployment is configured to do, and what it is built never to do. Every value is read from the running backend."
      />

      <PageBody>
        <Tabs tabs={TABS} active={tab} onChange={setTab} className="space-y-5">
          <TabPanel id="platform">
            <PlatformTab />
          </TabPanel>
          <TabPanel id="ai">
            <AiTab />
          </TabPanel>
          <TabPanel id="response">
            <ResponseTab />
          </TabPanel>
          <TabPanel id="access">
            <AccessTab />
          </TabPanel>
          <TabPanel id="account">
            <AccountTab />
          </TabPanel>
        </Tabs>
      </PageBody>
    </>
  )
}

function PlatformTab() {
  const info = useSystemInfo()
  const detection = useDetectionStatus()

  return (
    <QueryBoundary query={info} context="Could not load platform information">
      {(data) => (
        <div className="space-y-5">
          <Panel title={`${data.name} ${data.version}`} subtitle="Deployment configuration">
            <KeyValue
              columns={3}
              items={[
                { label: 'Environment', value: titleCase(data.environment) },
                { label: 'Database backend', value: data.database_backend },
                {
                  label: 'Demo mode',
                  value: data.demo_mode ? (
                    <span className="text-medium">on — seeded data present</span>
                  ) : (
                    <span className="text-healthy">off</span>
                  ),
                },
                { label: 'Detection rules loaded', value: data.detection.rules_loaded },
                {
                  label: 'Rule load errors',
                  value:
                    data.detection.load_errors.length === 0 ? (
                      <span className="text-healthy">none</span>
                    ) : (
                      <span className="text-critical">{data.detection.load_errors.length}</span>
                    ),
                },
                {
                  label: 'AI provider',
                  value: data.ai.configured ? (
                    data.ai.provider
                  ) : (
                    <span className="text-ink-faint">not configured</span>
                  ),
                },
              ]}
            />

            {data.detection.load_errors.length > 0 && (
              <Callout tone="critical" title="Rules that failed to load">
                <ul className="space-y-1 mt-1">
                  {data.detection.load_errors.map((error) => (
                    <li key={error} className="mono text-2xs">
                      {error}
                    </li>
                  ))}
                </ul>
                <p className="mt-2">
                  A rule that fails validation is never loaded in a degraded form — it is refused
                  and reported, because a partially-parsed detection rule is worse than no rule.
                </p>
              </Callout>
            )}
          </Panel>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            <Panel title="Data in this deployment" subtitle="Counts read live from the database">
              <div className="grid grid-cols-3 gap-3">
                <Stat icon={<Database className="h-4 w-4" />} label="Events" value={compactNumber(data.data.events)} />
                <Stat label="Alerts" value={compactNumber(data.data.alerts)} />
                <Stat label="Incidents" value={compactNumber(data.data.incidents)} />
              </div>
              <div className="mt-4">
                <div className="flex items-baseline justify-between mb-1">
                  <span className="text-xs text-ink-muted">Events generated by the simulator</span>
                  <span className="text-sm font-semibold text-ink tabular-nums">
                    {compactNumber(data.data.simulated_events)} ({percent(data.data.simulated_share, 1)})
                  </span>
                </div>
                <div className="h-1.5 w-full bg-raised rounded-full overflow-hidden">
                  <div
                    className="h-full bg-medium rounded-full"
                    style={{ width: `${Math.min(100, data.data.simulated_share * 100)}%` }}
                  />
                </div>
                <p className="text-2xs text-ink-faint mt-2 leading-relaxed">
                  Simulated telemetry is flagged in the database, surfaced in the interface and
                  counted here, so no figure anywhere in this console can quietly pass seeded data
                  off as production activity.
                </p>
              </div>
            </Panel>

            <Panel title="Detection engine health">
              {detection.isLoading && <Loading rows={3} />}
              {detection.data && (
                <>
                  <div className="grid grid-cols-3 gap-3">
                    <Stat label="On disk" value={detection.data.rules_on_disk} />
                    <Stat label="Registered" value={detection.data.rules_registered} />
                    <Stat label="Enabled" value={detection.data.rules_enabled} />
                  </div>
                  <div className="mt-4">
                    <p className="label mb-2">Rules by detector type</p>
                    <div className="flex flex-wrap gap-1.5">
                      {Object.entries(detection.data.by_type).map(([type, count]) => (
                        <Badge key={type} className="border-accent/30 text-accent">
                          {type} · {count}
                        </Badge>
                      ))}
                    </div>
                  </div>
                  <div className="mt-4 flex items-center gap-2">
                    <ShieldCheck
                      className={clsx(
                        'h-4 w-4',
                        detection.data.healthy ? 'text-healthy' : 'text-critical',
                      )}
                      aria-hidden="true"
                    />
                    <span className="text-xs text-ink">
                      {detection.data.healthy
                        ? 'Every rule on disk is registered and parses cleanly.'
                        : 'Some rules did not load — see the errors above.'}
                    </span>
                  </div>
                </>
              )}
            </Panel>
          </div>

          <Panel
            title="Boundaries"
            subtitle="Things this platform is built never to do, stated by the backend rather than asserted by the interface"
          >
            <ul className="space-y-2.5">
              {Object.entries(data.boundaries).map(([key, value]) => (
                <li key={key} className="flex gap-2.5">
                  <AlertOctagon className="h-4 w-4 text-medium shrink-0 mt-0.5" aria-hidden="true" />
                  <div className="min-w-0">
                    <p className="text-sm text-ink">{titleCase(key)}</p>
                    <p className="text-xs text-ink-muted leading-relaxed">{value}</p>
                  </div>
                </li>
              ))}
            </ul>
          </Panel>
        </div>
      )}
    </QueryBoundary>
  )
}

function AiTab() {
  const status = useAiStatus()

  return (
    <QueryBoundary query={status} context="Could not load AI status">
      {(data) => (
        <div className="space-y-5">
          <Panel title="Provider">
            <div className="flex flex-wrap items-center gap-2 mb-3">
              <Bot className="h-4 w-4 text-accent" aria-hidden="true" />
              {data.available ? (
                <Badge className="border-healthy/40 text-healthy">available</Badge>
              ) : (
                <Badge className="border-line text-ink-faint">not configured</Badge>
              )}
              <Code>{data.provider}</Code>
              {data.model && <Code>{data.model}</Code>}
            </div>
            <p className="text-sm text-ink-muted leading-relaxed">{data.message}</p>
            <Callout tone="info" title="The AI is not the detection engine">
              <p>
                Detection, correlation, scoring, MITRE mapping and reporting all run without an AI
                provider. Turning the assistant off removes explanation and summarisation; it does
                not reduce what this platform detects. That is deliberate — a detection pipeline
                whose verdicts depend on a language model has no reproducible behaviour to test.
              </p>
            </Callout>
          </Panel>

          <Panel
            title="Grounding policy"
            subtitle="The rules every AI response is validated against before an analyst sees it"
          >
            <ul className="space-y-2.5">
              {Object.entries(data.grounding_policy).map(([key, value]) => (
                <li key={key}>
                  <p className="text-sm text-ink">{titleCase(key)}</p>
                  <p className="text-xs text-ink-muted leading-relaxed">{value}</p>
                </li>
              ))}
            </ul>
          </Panel>

          {data.suggested_questions.length > 0 && (
            <Panel title="Suggested questions" subtitle="Available on any incident's AI tab">
              <ul className="space-y-1.5">
                {data.suggested_questions.map((question) => (
                  <li key={question} className="text-xs text-ink-muted flex gap-2">
                    <span className="text-ink-faint shrink-0" aria-hidden="true">
                      ·
                    </span>
                    {question}
                  </li>
                ))}
              </ul>
            </Panel>
          )}
        </div>
      )}
    </QueryBoundary>
  )
}

function ResponseTab() {
  const actions = useResponseActions()
  const playbooks = usePlaybooks()

  return (
    <div className="space-y-5">
      <QueryBoundary query={actions} context="Could not load the response catalogue">
        {(data) => (
          <Panel title="Response action catalogue" dense>
            <div className="px-4 pt-4">
              <Callout tone="warning" title="Every action is simulated">
                <p>{data.simulation_notice}</p>
              </Callout>
            </div>
            <div className="table-wrap mt-3">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Action</th>
                    <th>Target</th>
                    <th>Destructive</th>
                    <th>Reversed by</th>
                    <th>Minimum role</th>
                    <th>What it would do in production</th>
                  </tr>
                </thead>
                <tbody>
                  {data.actions.map((action) => (
                    <tr key={action.action_type}>
                      <td>
                        <span className="text-ink">{action.name}</span>
                        <Code className="ml-2">{action.action_type}</Code>
                      </td>
                      <td className="text-ink-muted">{action.target_type}</td>
                      <td>
                        {action.destructive ? (
                          <Badge className="border-high/40 text-high">destructive</Badge>
                        ) : (
                          <span className="text-2xs text-ink-faint">no</span>
                        )}
                      </td>
                      <td className="mono text-ink-muted">{action.reverses ?? '—'}</td>
                      <td>
                        <Badge className="border-line text-ink-faint">{action.requires_role}</Badge>
                      </td>
                      <td className="text-xs text-ink-muted max-w-sm">
                        {action.production_behaviour}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
        )}
      </QueryBoundary>

      <Panel
        title="Playbooks"
        subtitle="Suggested response sequences, matched to incidents by rule and technique"
        dense
      >
        {playbooks.isLoading && <Loading rows={3} />}
        {playbooks.data && playbooks.data.length === 0 && (
          <EmptyState title="No playbooks are defined" />
        )}
        {playbooks.data && playbooks.data.length > 0 && (
          <div className="divide-y divide-line">
            {playbooks.data.map((playbook) => (
              <details key={playbook.playbook_id} className="px-4 py-3">
                <summary className="cursor-pointer flex flex-wrap items-center gap-2">
                  <Workflow className="h-3.5 w-3.5 text-accent shrink-0" aria-hidden="true" />
                  <span className="text-sm text-ink">{playbook.name}</span>
                  <Badge className="border-line text-ink-faint">
                    {playbook.steps.length} steps
                  </Badge>
                </summary>
                <p className="text-xs text-ink-muted mt-2 leading-relaxed">{playbook.description}</p>

                <div className="flex flex-wrap gap-1 mt-2">
                  {playbook.trigger_techniques.map((technique) => (
                    <Badge key={technique} className="border-accent/25 text-accent/90">
                      {technique}
                    </Badge>
                  ))}
                  {playbook.trigger_rule_ids.map((rule) => (
                    <Code key={rule}>{rule}</Code>
                  ))}
                </div>

                <ol className="mt-3 space-y-2">
                  {playbook.steps.map((step) => (
                    <li key={step.order} className="flex gap-2.5">
                      <span className="mono text-2xs text-ink-faint tabular-nums w-4 shrink-0 mt-0.5">
                        {step.order}
                      </span>
                      <div className="min-w-0">
                        <p className="text-xs text-ink">
                          {step.title}
                          <Badge className="ml-2 border-line text-ink-faint">{step.phase}</Badge>
                        </p>
                        <p className="text-2xs text-ink-muted leading-relaxed mt-0.5">
                          {step.detail}
                        </p>
                        {step.suggested_action && (
                          <p className="text-2xs text-ink-faint mt-0.5">
                            Suggested action: <Code>{step.suggested_action}</Code>
                          </p>
                        )}
                      </div>
                    </li>
                  ))}
                </ol>
              </details>
            ))}
          </div>
        )}
      </Panel>
    </div>
  )
}

function AccessTab() {
  const roles = useRoles()

  return (
    <QueryBoundary query={roles} context="Could not load role definitions">
      {(data) => (
        <div className="space-y-5">
          <Callout tone="info" title="Enforced on the server">
            <p>
              The interface hides controls a role cannot use, but that is a courtesy, not the
              control. Every privileged endpoint re-checks the caller's role from the token, so a
              request crafted outside this console is refused the same way.
            </p>
          </Callout>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {data.roles.map((role) => (
              <Panel key={role.role} title={titleCase(role.role)} subtitle={`level ${role.level}`}>
                <p className="text-xs text-ink-muted leading-relaxed">{role.description}</p>

                <div className="mt-3">
                  <p className="label mb-1.5 text-healthy">Can</p>
                  <ul className="space-y-1">
                    {role.can.map((item) => (
                      <li key={item} className="text-2xs text-ink-muted flex gap-1.5">
                        <span className="text-healthy shrink-0" aria-hidden="true">
                          +
                        </span>
                        {item}
                      </li>
                    ))}
                  </ul>
                </div>

                {role.cannot.length > 0 && (
                  <div className="mt-3">
                    <p className="label mb-1.5 text-high">Cannot</p>
                    <ul className="space-y-1">
                      {role.cannot.map((item) => (
                        <li key={item} className="text-2xs text-ink-muted flex gap-1.5">
                          <span className="text-high shrink-0" aria-hidden="true">
                            −
                          </span>
                          {item}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </Panel>
            ))}
          </div>
        </div>
      )}
    </QueryBoundary>
  )
}

function AccountTab() {
  const { user, logout } = useAuth()

  if (!user) return <EmptyState title="Not signed in" />

  return (
    <div className="space-y-5 max-w-2xl">
      <Panel title="Signed in as">
        <KeyValue
          columns={2}
          items={[
            { label: 'Username', value: <span className="mono">{user.username}</span> },
            { label: 'Role', value: titleCase(user.role) },
            { label: 'Full name', value: user.full_name ?? '—' },
            { label: 'Email', value: user.email ?? '—' },
            {
              label: 'Account state',
              value: user.is_active ? (
                <span className="text-healthy">active</span>
              ) : (
                <span className="text-critical">disabled</span>
              ),
            },
            {
              label: 'Last sign-in',
              value: user.last_login_at ? absoluteTime(user.last_login_at) : 'this session',
            },
          ]}
        />
        <button type="button" className="btn-secondary mt-4" onClick={logout}>
          Sign out
        </button>
      </Panel>

      <Panel title="Session handling">
        <ul className="space-y-2 text-xs text-ink-muted leading-relaxed">
          <li>
            The access token lives in <Code>sessionStorage</Code>, so it is discarded when this tab
            closes — the right default for a console used on shared analyst workstations.
          </li>
          <li>
            Tokens are valid for eight hours and are not refreshed silently. An expired token
            returns you to the sign-in screen rather than failing requests one at a time in the
            background.
          </li>
          <li>
            Signing out clears this browser's copy of the token and records the sign-out, but it
            does not invalidate the token server-side — there is no deny list. Disabling an
            account <em>does</em> take effect immediately, because identity is re-read from the
            database on every request.
          </li>
          <li>
            Passwords are stored as bcrypt hashes. The API has no endpoint that returns a password
            hash, and the request logger redacts bearer tokens and credential-shaped strings before
            anything reaches a log file.
          </li>
          <li>
            Signing in and out are both written to the audit trail, along with the source address.
          </li>
        </ul>
      </Panel>
    </div>
  )
}

function Stat({
  label,
  value,
  icon,
}: {
  label: string
  value: number | string
  icon?: React.ReactNode
}) {
  return (
    <div className="bg-base border border-line rounded-md p-2.5">
      <div className="flex items-center gap-1.5 text-ink-faint">
        {icon}
        <p className="label">{label}</p>
      </div>
      <p className="text-lg font-bold text-ink tabular-nums mt-0.5">{value}</p>
    </div>
  )
}
