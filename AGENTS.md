# Repository Guidelines

## Project Structure & Module Organization
- `src/`: Terraform component (`main.tf`, `variables.tf`, `outputs.tf`, `providers.tf`, `versions.tf`, `context.tf`). This is the source of truth.
- `test/`: Go Terratest suite using Atmos fixtures (`component_test.go`, `fixtures/`, `test_suite.yaml`). Tests deploy/destroy real AWS resources.
- `README.yaml`: Source for the generated `README.md` (via atmos + terraform-docs).
- `.github/`: CI/CD, Renovate/Dependabot, labels, and automerge settings.
- `docs/`: Project docs (if any). Keep lightweight and current.

## Build, Test, and Development Commands
- To install atmos read this docs https://github.com/cloudposse/atmos
- `atmos docs generate readme`: Regenerate `README.md` from `README.yaml` and terraform source.
- `atmos docs generate readme-simple`: Regenerate `src/README.md` from `README.yaml` and terraform source.
- `atmos test run`: Run Terratest suite in `test/` (uses Atmos fixtures; creates and destroys AWS resources).
- Pre-commit locally: `pre-commit install && pre-commit run -a` (runs `terraform_fmt`, `terraform_docs`, `tflint`).
- TFLint plugin setup: `tflint --init` (uses `.tflint.hcl`).

## Coding Style & Naming Conventions
- Indentation: Terraform 2 spaces; YAML/Markdown 2 spaces.
- Terraform: prefer lower_snake_case for variables/locals; keep resources/data sources descriptive and aligned with Cloud Posse null-label patterns.
- Lint/format: `terraform fmt -recursive`, TFLint rules per `.tflint.hcl`. Do not commit formatting or lint violations.

## Testing Guidelines
- Framework: Go Terratest with `github.com/cloudposse/test-helpers` and `atmos` fixtures.
- Location/naming: put tests in `test/` and name files `*_test.go`. Add scenarios under `test/fixtures/stacks/catalog/usecase/`.
- Run: `atmos test run`. Ensure AWS credentials are configured; tests may incur AWS costs and will clean up after themselves.

## Commit & Pull Request Guidelines
- Commits: follow Conventional Commits (e.g., `feat:`, `fix:`, `chore(deps):`, `docs:`). Keep messages concise and scoped.
- PRs: include a clear description, linked issues, and any behavioral changes. Update `README.yaml` when inputs/outputs change and run `atmos docs generate readme`.
- CI: ensure pre-commit, TFLint, and tests pass. Avoid unrelated changes in the same PR.

## Security & Configuration Tips
- Never commit secrets. Configure AWS credentials/role assumption externally; the provider setup in `src/providers.tf` supports role assumption via the `iam_roles` module.
- Global quotas must be applied in `us-east-1`; place in the `gbl` stack and set `region: us-east-1` in `vars`.
