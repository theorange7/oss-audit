# ── oss-audit Dockerfile ──────────────────────────────────────────────────────
# Multi-stage build: tool installer → final image
# Bundles: syft, grype, gitleaks, semgrep, osv-scanner, trivy, licensee
# Python runtime for the orchestration CLI
# ──────────────────────────────────────────────────────────────────────────────

# ── Stage 1: download & install Go-based tools ────────────────────────────────
FROM ubuntu:24.04 AS tool-installer

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates tar gzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tools

# syft (SBOM generator)
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
    | sh -s -- -b /usr/local/bin

# grype (vulnerability scanner)
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
    | sh -s -- -b /usr/local/bin

# gitleaks (secret scanner)
RUN GITLEAKS_VERSION=$(curl -sSf https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
    | grep '"tag_name"' | cut -d'"' -f4 | tr -d 'v') \
    && curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks

# trivy (all-in-one scanner, complement to grype)
RUN curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin

# osv-scanner
RUN OSV_VERSION=$(curl -sSf https://api.github.com/repos/google/osv-scanner/releases/latest \
    | grep '"tag_name"' | cut -d'"' -f4 | tr -d 'v') \
    && curl -sSfL "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_amd64" \
    -o /usr/local/bin/osv-scanner \
    && chmod +x /usr/local/bin/osv-scanner


# ── Stage 2: final runtime image ──────────────────────────────────────────────
FROM python:3.12-slim

LABEL org.opencontainers.image.title="oss-audit"
LABEL org.opencontainers.image.description="OSS security, privacy, and license audit tool"

# System packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    ruby ruby-dev build-essential \
    && gem install licensee --no-document \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install semgrep via pip
RUN pip install --no-cache-dir semgrep

# Copy tools from installer stage
COPY --from=tool-installer /usr/local/bin/syft        /usr/local/bin/syft
COPY --from=tool-installer /usr/local/bin/grype       /usr/local/bin/grype
COPY --from=tool-installer /usr/local/bin/gitleaks    /usr/local/bin/gitleaks
COPY --from=tool-installer /usr/local/bin/trivy       /usr/local/bin/trivy
COPY --from=tool-installer /usr/local/bin/osv-scanner /usr/local/bin/osv-scanner

# Install oss-audit CLI
WORKDIR /app
COPY pyproject.toml ./
COPY oss_audit/ ./oss_audit/
# Regular install (not editable) — source is baked into the image
RUN pip install --no-cache-dir .

# Output directory (mount here to retrieve reports)
RUN mkdir /reports

ENTRYPOINT ["oss-audit"]
CMD ["--help"]

# ── Usage ────────────────────────────────────────────────────────────────────
# Build:
#   docker build -t oss-audit .
#
# Run (note the `scan` subcommand):
#   docker run --rm -v $(pwd)/reports:/reports \
#     oss-audit scan https://github.com/org/repo \
#     --output /reports/myrepo \
#     --profile privacy