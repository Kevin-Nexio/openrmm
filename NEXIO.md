# Nexio customization

Based on the official OpenRMM v0.11.4 release. Source branch:
https://github.com/Kevin-Nexio/openrmm/tree/nexio/alert-description

Alert and recovery email subjects prefer the device description, then hostname,
then agent ID. Whitespace is normalized and the body retains the technical
hostname. Recipient selection and alert-transition deduplication are unchanged.
If a device moved to another monitoring scope after an incident began, its
current description is not copied into that incident's emails; the original
hostname remains the fallback. No database migration is introduced.

This applies to check failures/recoveries and agent offline/recovery alerts.
Account emails, test emails, job-failure notifications and AI release notices
retain their existing subjects.

Build only the customized backend (frontend and signed agents remain official):

```sh
docker build --platform linux/amd64 -f deploy/Dockerfile.nexio \
  --build-arg REVISION="$(git rev-parse HEAD)" \
  -t nexio/openrmm-server:0.11.4-nexio.1 .
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
