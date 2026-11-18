# Finding affected JDKs — inventory guidance

JDKs hide in more places than a package inventory shows. CISA's alert makes this point explicitly:
runtimes may not appear as separate entries when bundled into third-party applications, containers or
appliances.

## Places to look

- OS package manager: `dpkg -l | grep -Ei 'openjdk|temurin|zulu|corretto|liberica|sapmachine'`,
  `rpm -qa | grep -Ei 'java|jdk|jre'`.
- Alternatives system: `update-alternatives --list java`, `ls -l /etc/alternatives/java`.
- Application bundles: Atlassian (Jira/Confluence ship a JRE), Jenkins, JFrog, Ping, Elasticsearch,
  Solr, Kafka, Gerrit, Spinnaker, Keycloak, and every Java build tool.
- Container images: `docker images` / registry scan; look for `eclipse-temurin`, `amazoncorretto`,
  `openjdk`, `zulu`, `microsoft-openjdk` base images and rebuilt application images.
- Appliances and network devices that embed a JVM: check vendor advisories rather than probing.
- CI runners and developer machines: less targeted, but a compromised build agent is high impact.

## Check both gates

Run `02-detections/common/check-java4shell-exposure.sh --json` per host and collect the JSON. It
reports the Java paths/versions it can see and whether the CPU exposes AVX-512 VBMI
(`avx512f`, `avx512bw`, `avx512vbmi`, `bmi2`).

A host is **exposed** only when an affected JDK is present, the CPU gate is true, and a process
Base64-decodes attacker-influenced data. Use free-text notes for the last condition; it is a
configuration judgement, not a version check.

## Priority order for remediation

1. Identity providers and SSO endpoints (Keycloak, PingFederate).
2. Internet-facing collaboration, CI and artefact services (Jira, Confluence, Jenkins, Artifactory).
3. Internal services with authenticated users (Kafka, Solr, Elasticsearch, Gerrit, Spinnaker).
4. Everything else with an embedded JVM, and the build/deploy chain that pushes JVMs to production.

## Record keeping

Keep a table per host: JDK product, version, fixed-line comparison, CPU gate, exposed service,
patch action, date. The version line to compare against is in `PATCH-AVAILABILITY.md`. Do not infer
patched status from the OS package version alone when the application bundles its own JRE.
