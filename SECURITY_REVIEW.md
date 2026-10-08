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

## Extra Information

### Additional risk matrix

This matrix covers findings outside the three priorities above. Broad publisher trust and the mutable production tag are already included in finding 1 and are not counted again.

Scores are qualitative planning estimates for the supplied design approaching production, not measured incident probabilities or CVSS scores. Likelihood: **1 = Low** (requires an uncommon prerequisite), **2 = Medium** (credible under realistic conditions), **3 = High** (expected when the stated trigger occurs). Impact: **1 = Low** (limited disruption), **2 = Medium** (material but recoverable service or investigation impact), **3 = High** (potential confidential-data exposure, unauthorized modification, or broad compromise). **Total = likelihood × impact:** 1–2 Low, 3–4 Medium, 6 High, 9 Critical. Conditional scores apply only if the stated prerequisites hold; they do not establish a confirmed exploit.

| ID | Additional finding / evidence | Affected asset | Likelihood | Impact | Total risk | Evidence limits and rationale |
|---|---|---|---|---|---|---|
| A1 | Public origin and exposed operations route: `infra/platform.ts` accepts HTTPS from `0.0.0.0/0`; `kubernetes/api.yaml` routes `/ops/reprocess`. | Operations endpoint and document-processing jobs | Medium (2), conditional | High (3), conditional | **High (6), conditional** | Public routing is shown. Header-only authentication is described in the README but no application implementation verifies it. If that behavior is accurate and no origin restriction exists, direct requests could bypass employee authentication. Exact operation capabilities and cross-tenant impact remain unverified. |
| A2 | Object access logging and data-event auditing are disabled in `infra/platform.ts`. | Document-access audit trail and incident investigation | Medium (2) | Medium (2) | **Medium (4)** | The gap matters when unauthorized access occurs: management logs alone do not establish which documents were read or changed. This does not independently grant data access. |
| A3 | Actions use `@v4`; the Dockerfile uses `node:24-alpine`, without immutable references. | CI dependencies, build integrity, container image | Low (1) | High (3) | **Medium (3)** | Compromise or unexpected changes to an upstream reference could affect execution. No compromised dependency is demonstrated. Impact is high if malicious content runs in the privileged publishing job. |
| A4 | Worker containers have no resource requests or limits in `kubernetes/worker.yaml`. | Worker capacity, cluster nodes, colocated workloads | Medium (2) | Medium (2) | **Medium (4)** | Heavy document-processing jobs or a runaway process could cause resource contention. Effective namespace defaults, workload behavior, and node capacity are not supplied. |
| A5 | API and worker Deployments have no readiness, liveness, or startup probes. | API availability and processing continuity | Medium (2) | Medium (2) | **Medium (4)** | A process can be running while unready or stuck; without appropriate probes, traffic routing or recovery may be delayed. Application failure behavior is not supplied. |
| A6 | Container security contexts do not explicitly drop capabilities or set `seccompProfile`. | Container processes and host isolation | Low (1) | High (3), conditional | **Medium (3), conditional** | A compromised process may face fewer restrictions than intended. Effective runtime or admission defaults are unknown; missing settings do not prove a container escape. |
| A7 | No NetworkPolicy resources appear in the supplied files. | Internal service boundaries and reachable workloads | Medium (2), conditional | High (3), conditional | **High (6), conditional** | If the deployed cluster has no equivalent segmentation, a compromised workload can attempt lateral connections. Absence from this repository does not prove absence in the cluster or successful access to authenticated services. |
| A8 | Configured audit retention is 30 days in `infra/platform.ts`. | Historical evidence for incident investigation | Low (1), conditional | Medium (2) | **Low (2), conditional** | Investigations starting after retention expires may lose evidence. Adequacy depends on detection times and any external log archive; 30 days is not inherently a vulnerability. |

### Deployment and build readiness gaps

The following are observed configuration defects or incomplete assessment material. They should be checked before production, but are not presented as additional exploitable vulnerabilities. Scores assume the supplied files are used as-is, without omitted prerequisites.

| ID | Gap / evidence | Affected asset | Likelihood | Impact | Total risk | Evidence limits and rationale |
|---|---|---|---|---|---|---|
| R1 | Both `apps/v1` Deployments lack the required `spec.selector`. | Deployment pipeline and release availability | High (3) | Medium (2) | **High (6)** | Applying these exact manifests should fail validation. This can block releases; it does not establish an outage of an existing deployment. |
| R2 | The operations Service selects `app: atlas-api`, but the API pod template provides no matching labels; the referenced `atlas-api` Service is also absent. | API and operations routing | High (3) | Medium (2) | **High (6)** | The supplied resources do not establish working endpoints. Existing Services or external manifest generation could change the runtime outcome. |
| R3 | The supplied repository lacks application source, `package.json`, and a lockfile; the Dockerfile does not show provisioning of pnpm or build dependencies. | Build reproducibility and release pipeline | High (3) | Medium (2) | **High (6)** | The supplied package is insufficient to demonstrate a successful build. This may be intentional for a configuration-only exercise; it is not evidence of an application vulnerability. |

High availability scores in the readiness table do not override the business-driven top-three priorities: those findings address paths to compromise confidential customer documents or credentials. The matrix is a triage aid, and related rows should not be added together as independent risk totals.
