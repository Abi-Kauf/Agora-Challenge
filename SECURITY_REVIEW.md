# Atlas - Production Security Review

**Reviewer:** Abigail Kauf  
**Scope:** Supplied architecture and configuration  

## Priority and approach

I would address the following three issues first:

1. Untrusted pull-request code can run in the image-publishing workflow.
2. The worker can read Kubernetes Secrets across the entire cluster.
3. The API's cloud permissions span every tenant document in the bucket.

I prioritized a path for introducing attacker-controlled code ahead of permissions that amplify a workload compromise. The business priority is preventing unauthorized access to or modification of another customer's documents.

This is a configuration review, not a runtime assessment. I use the README for business context and intended behavior, while grounding findings in the supplied files. Infrastructure definitions are condensed and use illustrative cloud identifiers; I have not verified deployed IAM policies, application authorization, or cluster state. Where a consequence depends on those details, I state that explicitly.

## 1. Untrusted pull-request code runs in the image-publishing workflow

**Affected assets:** CI execution environment, registry publishing identity, production image, and the API and worker that consume that image.

### Evidence

- [`.github/workflows/build.yaml`](.github/workflows/build.yaml) triggers on `pull_request_target` and checks out `github.event.pull_request.head.sha`.
- The job has `id-token: write`, requests the image-publisher role, and then executes `./scripts/build.sh` from the checked-out revision.
- [`scripts/build.sh`](scripts/build.sh) executes dependency installation, tests, and a Docker build. Both the script and Dockerfile can be changed by the PR.
- [`infra/platform.ts`](infra/platform.ts) describes a publisher trust pattern of `repo:atlas-company/platform-*:*` and permissions to upload and publish images.
- Both workload manifests reference the mutable image tag `registry.example/atlas-api:production`.

### Plausible attack path

An external contributor submits a PR that changes the build script. If the workflow is allowed to run and the cloud trust policy accepts its identity, that script executes after cloud credentials have been obtained. It can use the publishing identity to replace the production image with attacker-controlled content.

The broad trust pattern and mutable production tag are parts of this same exposure: the former expands which job identities may publish, and the latter lets a registry write change what a production reference resolves to.

The README describes rollout of a replaced production tag within five minutes. That timing is an intended behavior, not something demonstrated by the manifests: replacing a tag alone does not prove that existing pods will restart. Even without that rollout assumption, a subsequent pull of the changed tag can consume the malicious image.

### Likely impact

If the malicious image is deployed, attacker-controlled code runs under the API or worker identity. This can expose or modify customer documents and compromise processing results. It can also exploit the excessive permissions described in the next two findings. Review requirements on source changes do not protect this path when unapproved PR code can publish an image independently.

### Next action

First, remove cloud identity and registry publishing access from jobs that execute PR-controlled code. Run PR validation in an unprivileged workflow; publish only from approved code on the protected production branch.

Then restrict the publisher trust to the exact repository and approved deployment context, and promote images by immutable digest through a reviewed deployment change. Validate that a fork PR cannot obtain the publishing identity or change the production artifact.

## 2. The worker can read Secrets across the cluster

**Affected assets:** Kubernetes Secrets in all namespaces, including database and integration credentials stored there.

### Evidence

[`kubernetes/worker.yaml`](kubernetes/worker.yaml) defines:

- A ClusterRole allowing `get` and `list` on `secrets`.
- A ClusterRoleBinding granting that role to `atlas-worker` in `atlas-production`.
- No restriction to specific secret names or namespaces.

Putting the subject ServiceAccount in one namespace does not limit the scope of a ClusterRoleBinding.

### Plausible attack path

If an attacker gains code execution in the worker—for example through the image-publishing path above—they can use its Kubernetes identity to list and retrieve Secrets throughout the cluster, provided API connectivity and usable service-account credentials are available. The manifests do not disable service-account token automounting; its effective setting should be checked.

Running as non-root and using a read-only filesystem do not restrict the ServiceAccount's authorization.

### Likely impact

The attacker can steal credentials belonging to other workloads and use them to expand access. The actual downstream impact depends on which Secrets exist and the privileges of those credentials; it may include database access, integration compromise, and access beyond the document-processing service.

### Next action

Replace the cluster-wide binding with a namespace-scoped Role and RoleBinding granting only the required access. Prefer `get` on an explicit set of secret names and remove `list` unless there is a justified requirement.

For credentials that can be mounted, consider removing the need to read them through the Kubernetes API. Verify that the worker can retrieve required integration credentials but cannot list Secrets or read an unrelated namespace's Secrets.

## 3. The API identity has bucket-wide access to tenant documents

**Affected assets:** Confidential customer documents in the shared object-storage bucket.

### Evidence

[`infra/platform.ts`](infra/platform.ts) defines API permissions for:

- `object-storage:ListBucket`
- `object-storage:GetObject`
- `object-storage:PutObject`

The resources include the bucket and `${tenantDocuments.arn}/*`, with no tenant-specific conditions shown.

### Plausible attack path

An attacker who compromises the API process or obtains its usable cloud credentials can use the API's identity to enumerate, read, and write documents across the bucket. They would not need to go through the application's normal customer routes.

This is a blast-radius finding, not evidence of an existing cross-tenant application authorization bug. The API may legitimately serve every tenant; the design question is whether compromising one shared identity should expose all customer documents.

### Likely impact

The compromise can affect confidentiality and integrity across tenants, which is the highest-impact business event in the brief. Public-access blocking and encryption at rest do not stop reads or writes authorized under the compromised role. Versioning can support recovery from some modifications but cannot undo disclosure.

### Next action

Confirm the operations and tenant scope the API actually needs, and remove unnecessary capabilities immediately—for example, bucket listing if the application does not require it.

Then define a tenant isolation approach that creates an enforceable boundary for document access. Options include separate workload identities or a trusted component issuing narrowly scoped, short-lived access. Merely organizing documents into prefixes does not contain a compromise if the API can still authorize access to every prefix.

Validate the boundary using a tenant-scoped identity: legitimate access should succeed, while reads and writes for another tenant should be denied by the storage authorization layer.

## Questions to resolve before implementation

- What exact deployed OIDC claims can assume the publisher role, and can fork PR jobs obtain that role?
- What mechanism rolls out changes to the production image tag?
- Which Secrets does the worker need, and does it need to discover them dynamically?
- Which document operations require a shared API identity, and what tenant isolation is feasible?

These questions refine remediation, they do not remove the configuration exposures identified above.
