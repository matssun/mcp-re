"""Who is asking for admission, derived from the runner hook environment."""

from __future__ import annotations

import os
from dataclasses import dataclass

# The workflow IDENTITY, not a human-readable job title.
#
# `GITHUB_WORKFLOW_REF` is "owner/repo/.github/workflows/slo.yml@refs/heads/main". The path
# segment survives a rename of the job's `name:` and cannot be spoofed by an unrelated
# workflow choosing a similar title, which a title match would admit. Measured present in
# the real hook environment on dev1 before being relied on -- see `runner-arbiter dump-env`.
SLO_WORKFLOW_PATH = os.environ.get("MCP_RE_ARBITER_SLO_WORKFLOW", ".github/workflows/slo.yml")
SLO_REPOSITORY = os.environ.get("MCP_RE_ARBITER_SLO_REPOSITORY", "matssun/mcp-re")


@dataclass(frozen=True)
class JobIdentity:
    """One job's identity as the pre-job hook sees it."""

    runner: str
    repository: str
    workflow_ref: str
    workflow_path: str
    run_id: str
    run_attempt: str
    job: str

    @property
    def key(self) -> str:
        """A filesystem-safe identifier unique to this job attempt on this runner."""
        raw = f"{self.runner}-{self.run_id}-{self.run_attempt}-{self.job}"
        return "".join(c if c.isalnum() or c in "-_." else "_" for c in raw)

    @property
    def is_slo(self) -> bool:
        """True only on an exact workflow-path AND repository match.

        A job that cannot be identified as the SLO workflow is ORDINARY, and that default
        is the safe one in both directions. An unidentified job wrongly treated as the SLO
        lane would take the exclusive reservation and lock every runner on the host out of
        admission; an SLO job wrongly treated as ordinary merely fails to reserve, and the
        `assert-slo-exclusive` clause then refuses the measurement rather than publishing
        one taken without exclusivity.
        """
        return self.workflow_path == SLO_WORKFLOW_PATH and self.repository == SLO_REPOSITORY

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "JobIdentity":
        e = dict(os.environ if env is None else env)
        ref = e.get("GITHUB_WORKFLOW_REF", "")
        repo = e.get("GITHUB_REPOSITORY", "")
        path = ""
        if ref:
            before_git_ref = ref.split("@", 1)[0]
            if repo and before_git_ref.startswith(repo + "/"):
                path = before_git_ref[len(repo) + 1 :]
        return cls(
            runner=e.get("RUNNER_NAME", "unknown-runner"),
            repository=repo,
            workflow_ref=ref,
            workflow_path=path,
            run_id=e.get("GITHUB_RUN_ID", "0"),
            run_attempt=e.get("GITHUB_RUN_ATTEMPT", "0"),
            job=e.get("GITHUB_JOB", "job"),
        )
