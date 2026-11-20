# Nexio customization

Based on the official OpenRMM v0.11.4 release. Source branch:
https://github.com/Kevin-Nexio/openrmm/tree/nexio/alert-email-templates

Alert and recovery email subjects prefer the device description, then hostname,
then agent ID. Whitespace is normalized and the body retains the technical
hostname. Recipient selection and alert-transition deduplication are unchanged.
If a device moved to another monitoring scope after an incident began, its
current description is not copied into that incident's emails; the original
hostname remains the fallback. No database migration is introduced.

This applies to check failures/recoveries and agent offline/recovery alerts.
Account emails, test emails, job-failure notifications and AI release notices
retain their existing subjects.

Build the customized backend (signed agents remain official):

```sh
docker build --platform linux/amd64 -f deploy/Dockerfile.nexio \
  --build-arg REVISION="$(git rev-parse HEAD)" \
  -t nexio/openrmm-server:0.11.4-nexio.3 .
```

Set `OPENRMM_SERVER_IMAGE` in the deployment environment to the built image,
then recreate only the server service with Docker Compose. Retain the original
image and environment for rollback. Back up the installation before deploying.

Validation: `go test ./internal/notify ./internal/scheduler`. Set
`RMM_TEST_DATABASE_URL` to an isolated PostgreSQL instance to also exercise the
outbox lifecycle and duplicate prevention after a description edit.

For an upstream upgrade, rebase the customization onto the new official tag,
update both pinned images in the Nexio Dockerfile, rerun tests and build a new
version. This fork does not automatically carry the change into upstream images.

## Configurable alert email templates

Version 0.11.4-nexio.2 adds an editor under Users & Settings > Alert email.
Global administrators can choose description, hostname or both for `{{device}}`,
and edit separate subject/plain-text body templates for alerts and recoveries.
The preview uses the same server renderer as live mail without saving or sending.
The example button uses saved templates, prefixes the subject with `[TEST]`, and
sends to the signed-in user's email using the existing SMTP security rules.
Restoring defaults edits the draft; Save applies them to future notifications.
Queued messages retain their original contents.

Supported variables: `{{device}}`, `{{description}}`, `{{hostname}}`, `{{event}}`,
`{{details}}`, `{{time}}` (UTC), `{{console_url}}`, `{{agent_id}}`, `{{alert_id}}`.
Variables are literal substitutions, not expressions or HTML. Unknown variables,
empty templates, oversized templates and multiline subject templates are rejected.
Agent-provided values cannot inject headers or recursively expand variables.
The existing scope-history protection for descriptions remains in place.

Configuration is stored as one JSON setting, `notify.alert_templates`, independent
of SMTP credentials and account email. No migration or restart is needed when
editing templates. Writes are audited without recording the message text.

Build the console and frontend image, then deploy it together with the backend:

```sh
(cd openrmm && npm ci && npm test && npm run build)
docker build --platform linux/amd64 -f deploy/Dockerfile.nexio-frontend \
  --build-arg REVISION="$(git rev-parse HEAD)" \
  -t nexio/openrmm-frontend:0.11.4-nexio.2 .
```

Set `OPENRMM_FRONTEND_IMAGE` alongside `OPENRMM_SERVER_IMAGE`. Keep the previous
images for both services to roll back; the earlier backend ignores the new setting.
API integration tests are in `internal/api/api_mail_templates_test.go` and use the
same isolated `RMM_TEST_DATABASE_URL` as the notification tests.

Backend 0.11.4-nexio.3 adds `RMM_CONSOLE_PUBLIC_URL` for links in previews,
examples and queued notifications. Set it to the browser console origin when
agents and the console use separate hostnames. If unset, the previous
`RMM_PUBLIC_URL` fallback remains. The frontend stays at 0.11.4-nexio.2.
