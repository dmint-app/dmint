# Code Coverage Table (Branch Coverage)

## 1. Security-Critical Modules Under 90% Combined Coverage

| Module | Statements | Missed Stmts | Branches | Missed Branches | Line % | Combined % | Sample Uncovered Lines |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `src/dmint/mcp/__init__.py` | 19 | 8 | 0 | 0 | 57.89% | **57.89%** | 22, 23, 24, 25, 26, 27 ... (+2 more) |
| `src/dmint/mcp/__main__.py` | 65 | 26 | 10 | 5 | 60.0% | **58.67%** | 84, 85, 86, 87, 92, 93 ... (+20 more) |
| `src/dmint/core/storage/sql.py` | 513 | 175 | 186 | 91 | 65.89% | **61.95%** | 86, 192, 194, 207, 211, 212 ... (+169 more) |
| `src/dmint/core/storage/base.py` | 58 | 16 | 0 | 0 | 72.41% | **72.41%** | 27, 32, 37, 42, 47, 52 ... (+10 more) |
| `src/dmint/core/keys.py` | 169 | 39 | 62 | 23 | 76.92% | **73.16%** | 81, 82, 112, 113, 117, 118 ... (+33 more) |
| `src/dmint/mcp/gateway.py` | 331 | 75 | 134 | 44 | 77.34% | **74.41%** | 73, 74, 76, 80, 82, 120 ... (+69 more) |
| `src/dmint/mcp/config_loader.py` | 287 | 60 | 170 | 53 | 79.09% | **75.27%** | 88, 123, 127, 136, 137, 140 ... (+54 more) |
| `src/dmint/mcp/client.py` | 191 | 39 | 60 | 20 | 79.58% | **76.49%** | 24, 43, 69, 76, 81, 109 ... (+33 more) |
| `src/dmint/mcp/ssrf.py` | 111 | 21 | 60 | 16 | 81.08% | **78.36%** | 53, 88, 94, 96, 98, 99 ... (+15 more) |
| `src/dmint/core/policy.py` | 289 | 51 | 160 | 46 | 82.35% | **78.4%** | 50, 53, 55, 63, 67, 68 ... (+45 more) |
| `src/dmint/core/constraints.py` | 450 | 86 | 338 | 80 | 80.89% | **78.93%** | 67, 68, 84, 91, 144, 157 ... (+80 more) |
| `src/dmint/core/resources.py` | 428 | 87 | 236 | 49 | 79.67% | **79.52%** | 89, 118, 138, 146, 150, 170 ... (+81 more) |
| `src/dmint/core/__init__.py` | 26 | 4 | 4 | 2 | 84.62% | **80.0%** | 243, 245, 247, 253 |
| `src/dmint/core/request_binding.py` | 38 | 7 | 12 | 3 | 81.58% | **80.0%** | 20, 23, 37, 45, 46, 80 ... (+1 more) |
| `src/dmint/core/enforcement.py` | 315 | 44 | 114 | 40 | 86.03% | **80.42%** | 52, 70, 86, 114, 139, 151 ... (+38 more) |
| `src/dmint/dashboard/app.py` | 129 | 19 | 56 | 17 | 85.27% | **80.54%** | 42, 57, 61, 107, 108, 109 ... (+13 more) |
| `src/dmint/mcp/proxy.py` | 325 | 46 | 120 | 39 | 85.85% | **80.9%** | 86, 88, 94, 95, 96, 97 ... (+40 more) |
| `src/dmint/core/storage/sqlite.py` | 568 | 86 | 200 | 44 | 84.86% | **83.07%** | 158, 164, 170, 171, 177, 178 ... (+80 more) |
| `src/dmint/dashboard/routes.py` | 246 | 33 | 46 | 12 | 86.59% | **84.59%** | 81, 82, 130, 195, 254, 255 ... (+27 more) |
| `src/dmint/core/verification.py` | 328 | 35 | 88 | 26 | 89.33% | **85.34%** | 88, 95, 102, 108, 116, 117 ... (+29 more) |
| `src/dmint/core/redaction.py` | 74 | 9 | 32 | 6 | 87.84% | **85.85%** | 39, 40, 41, 42, 43, 44 ... (+3 more) |
| `src/dmint/core/authority.py` | 77 | 7 | 22 | 6 | 90.91% | **86.87%** | 86, 109, 122, 123, 124, 159 ... (+1 more) |
| `src/dmint/mcp/config.py` | 245 | 23 | 104 | 22 | 90.61% | **87.11%** | 81, 156, 170, 171, 174, 176 ... (+17 more) |
| `src/dmint/dashboard/__main__.py` | 66 | 6 | 12 | 3 | 90.91% | **88.46%** | 94, 98, 99, 125, 126, 195 |
| `src/dmint/dashboard/auth.py` | 36 | 2 | 8 | 3 | 94.44% | **88.64%** | 24, 39 |
| `src/dmint/core/approvals.py` | 279 | 17 | 56 | 17 | 93.91% | **89.85%** | 71, 80, 92, 98, 238, 355 ... (+11 more) |
| `src/dmint/mcp/auth.py` | 126 | 9 | 52 | 9 | 92.86% | **89.89%** | 42, 52, 55, 135, 142, 146 ... (+3 more) |

Total security-critical modules under 90%: 27

## 2. All Modules

| Module | Statements | Missed Stmts | Branches | Missed Branches | Line % | Combined % |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `src/dmint/__init__.py` | 17 | 5 | 4 | 2 | 70.59% | 66.67% |
| `src/dmint/approvals.py` | 4 | 0 | 0 | 0 | 100.0% | 100.0% |
| `src/dmint/authority.py` | 4 | 0 | 0 | 0 | 100.0% | 100.0% |
| `src/dmint/canonicalize.py` | 10 | 10 | 0 | 0 | 0.0% | 0.0% |
| `src/dmint/cli/__init__.py` | 23 | 7 | 0 | 0 | 69.57% | 69.57% |
| `src/dmint/cli/__main__.py` | 108 | 20 | 48 | 7 | 81.48% | 82.69% |
| `src/dmint/cli/api.py` | 185 | 32 | 68 | 22 | 82.7% | 78.66% |
| `src/dmint/cli/approvals.py` | 236 | 62 | 62 | 21 | 73.73% | 72.15% |
| `src/dmint/cli/compile_policy.py` | 38 | 14 | 2 | 1 | 63.16% | 62.5% |
| `src/dmint/cli/create_mcp_policy.py` | 479 | 110 | 212 | 58 | 77.04% | 75.69% |
| `src/dmint/cli/create_policy.py` | 284 | 61 | 112 | 38 | 78.52% | 75.0% |
| `src/dmint/cli/dashboard.py` | 16 | 4 | 0 | 0 | 75.0% | 75.0% |
| `src/dmint/cli/errors.py` | 24 | 0 | 0 | 0 | 100.0% | 100.0% |
| `src/dmint/cli/install_skill.py` | 146 | 41 | 48 | 21 | 71.92% | 68.04% |
| `src/dmint/cli/io_utils.py` | 49 | 10 | 6 | 2 | 79.59% | 78.18% |
| `src/dmint/cli/keys.py` | 67 | 4 | 6 | 1 | 94.03% | 93.15% |
| `src/dmint/cli/limits.py` | 21 | 0 | 0 | 0 | 100.0% | 100.0% |
| `src/dmint/cli/mcp_auth.py` | 315 | 52 | 120 | 24 | 83.49% | 82.53% |
| `src/dmint/cli/mcp_connections.py` | 322 | 32 | 134 | 19 | 90.06% | 88.82% |
| `src/dmint/cli/mcp_credentials.py` | 356 | 57 | 134 | 49 | 83.99% | 78.37% |
| `src/dmint/cli/mcp_oauth.py` | 364 | 79 | 90 | 26 | 78.3% | 76.87% |
| `src/dmint/cli/prompts/__init__.py` | 0 | 0 | 0 | 0 | 100.0% | 100.0% |
| `src/dmint/cli/verify_policy.py` | 62 | 9 | 12 | 2 | 85.48% | 85.14% |
| `src/dmint/cli/version.py` | 3 | 0 | 0 | 0 | 100.0% | 100.0% |
| `src/dmint/core/__init__.py` | 26 | 4 | 4 | 2 | 84.62% | 80.0% |
| `src/dmint/core/approvals.py` | 279 | 17 | 56 | 17 | 93.91% | 89.85% |
| `src/dmint/core/authority.py` | 77 | 7 | 22 | 6 | 90.91% | 86.87% |
| `src/dmint/core/canonicalize.py` | 166 | 9 | 78 | 9 | 94.58% | 92.62% |
| `src/dmint/core/constraints.py` | 450 | 86 | 338 | 80 | 80.89% | 78.93% |
| `src/dmint/core/enforcement.py` | 315 | 44 | 114 | 40 | 86.03% | 80.42% |
| `src/dmint/core/errors.py` | 83 | 0 | 0 | 0 | 100.0% | 100.0% |
| `src/dmint/core/hashing.py` | 5 | 0 | 0 | 0 | 100.0% | 100.0% |
| `src/dmint/core/keys.py` | 169 | 39 | 62 | 23 | 76.92% | 73.16% |
| `src/dmint/core/models.py` | 65 | 3 | 14 | 3 | 95.38% | 92.41% |
| `src/dmint/core/policy.py` | 289 | 51 | 160 | 46 | 82.35% | 78.4% |
| `src/dmint/core/redaction.py` | 74 | 9 | 32 | 6 | 87.84% | 85.85% |
| `src/dmint/core/request_binding.py` | 38 | 7 | 12 | 3 | 81.58% | 80.0% |
| `src/dmint/core/resources.py` | 428 | 87 | 236 | 49 | 79.67% | 79.52% |
| `src/dmint/core/storage/__init__.py` | 6 | 0 | 0 | 0 | 100.0% | 100.0% |
| `src/dmint/core/storage/base.py` | 58 | 16 | 0 | 0 | 72.41% | 72.41% |
| `src/dmint/core/storage/factory.py` | 30 | 3 | 8 | 0 | 90.0% | 92.11% |
| `src/dmint/core/storage/sql.py` | 513 | 175 | 186 | 91 | 65.89% | 61.95% |
| `src/dmint/core/storage/sqlite.py` | 568 | 86 | 200 | 44 | 84.86% | 83.07% |
| `src/dmint/core/storage/thread_safe.py` | 93 | 8 | 16 | 1 | 91.4% | 91.74% |
| `src/dmint/core/verification.py` | 328 | 35 | 88 | 26 | 89.33% | 85.34% |
| `src/dmint/core/versions.py` | 6 | 0 | 0 | 0 | 100.0% | 100.0% |
| `src/dmint/core/webhooks.py` | 122 | 2 | 26 | 4 | 98.36% | 95.95% |
| `src/dmint/dashboard/__init__.py` | 6 | 0 | 0 | 0 | 100.0% | 100.0% |
| `src/dmint/dashboard/__main__.py` | 66 | 6 | 12 | 3 | 90.91% | 88.46% |
| `src/dmint/dashboard/app.py` | 129 | 19 | 56 | 17 | 85.27% | 80.54% |
| `src/dmint/dashboard/auth.py` | 36 | 2 | 8 | 3 | 94.44% | 88.64% |
| `src/dmint/dashboard/core_client.py` | 52 | 0 | 10 | 0 | 100.0% | 100.0% |
| `src/dmint/dashboard/routes.py` | 246 | 33 | 46 | 12 | 86.59% | 84.59% |
| `src/dmint/enforcement.py` | 4 | 4 | 0 | 0 | 0.0% | 0.0% |
| `src/dmint/errors.py` | 4 | 0 | 0 | 0 | 100.0% | 100.0% |
| `src/dmint/hashing.py` | 4 | 4 | 0 | 0 | 0.0% | 0.0% |
| `src/dmint/mcp/__init__.py` | 19 | 8 | 0 | 0 | 57.89% | 57.89% |
| `src/dmint/mcp/__main__.py` | 65 | 26 | 10 | 5 | 60.0% | 58.67% |
| `src/dmint/mcp/auth.py` | 126 | 9 | 52 | 9 | 92.86% | 89.89% |
| `src/dmint/mcp/client.py` | 191 | 39 | 60 | 20 | 79.58% | 76.49% |
| `src/dmint/mcp/config.py` | 245 | 23 | 104 | 22 | 90.61% | 87.11% |
| `src/dmint/mcp/config_loader.py` | 287 | 60 | 170 | 53 | 79.09% | 75.27% |
| `src/dmint/mcp/errors.py` | 13 | 0 | 0 | 0 | 100.0% | 100.0% |
| `src/dmint/mcp/gateway.py` | 331 | 75 | 134 | 44 | 77.34% | 74.41% |
| `src/dmint/mcp/mapper.py` | 77 | 5 | 22 | 1 | 93.51% | 93.94% |
| `src/dmint/mcp/proxy.py` | 325 | 46 | 120 | 39 | 85.85% | 80.9% |
| `src/dmint/mcp/ssrf.py` | 111 | 21 | 60 | 16 | 81.08% | 78.36% |
| `src/dmint/models.py` | 4 | 0 | 0 | 0 | 100.0% | 100.0% |
| `src/dmint/policy.py` | 4 | 0 | 0 | 0 | 100.0% | 100.0% |
| `src/dmint/request_binding.py` | 4 | 0 | 0 | 0 | 100.0% | 100.0% |
| `src/dmint/skills/__init__.py` | 4 | 0 | 0 | 0 | 100.0% | 100.0% |
| `src/dmint/skills/manager.py` | 30 | 14 | 8 | 5 | 53.33% | 50.0% |
| `src/dmint/skills/skill.py` | 2 | 0 | 0 | 0 | 100.0% | 100.0% |
| `src/dmint/skills/version.py` | 3 | 0 | 0 | 0 | 100.0% | 100.0% |
| `src/dmint/storage/__init__.py` | 4 | 1 | 0 | 0 | 75.0% | 75.0% |
| `src/dmint/storage/sqlite.py` | 4 | 0 | 0 | 0 | 100.0% | 100.0% |
| `src/dmint/version.py` | 13 | 0 | 2 | 0 | 100.0% | 100.0% |
| `src/dmint/versions.py` | 4 | 0 | 0 | 0 | 100.0% | 100.0% |
