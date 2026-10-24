# REA Research MCP for AgentOS (v0.1)

**Status: experimental, STDIO-only, tested locally on KVM. NOT connected to ChatGPT yet.**

This is a **small, closed-set REA Evidence MCP** for analyzing two copied Linux ELF binaries. It is not a network proxy for REA's 139 built-in tools. The unrestricted REA MCP must not be connected directly to GPT on the shared VPS.

## Four read-only tools

- `rea_lab_inventory` — curated target aliases and capabilities.
- `rea_elf_layout` — static REA/pwntools ELF layout for `systemctl` or `systemd-pid1`.
- `rea_ghidra_overview` — cached REA/Ghidra procedure/string overview for `systemctl`.
- `rea_compare_elf` — two-target static layout comparison.

No tool accepts arbitrary paths, process IDs, shell commands, network URLs, systemd unit names, or dynamic tool names. All tool results are bounded projections of locally curated, separately captured REA Evidence JSON. No tool runs a new binary, Ghidra analysis, shell, or OS manager command. The MCP listener is stdio only. It does **not** provide current OS observations or an AgentOS Admin plane.

**Important trust limit:** read-only tool code alone does not constitute a security sandbox. Do not run this server as root through a remote tunnel. Use a dedicated unprivileged account, a fixed read-only Evidence mount and restrictive filesystem permissions. Verify that the runtime has no capabilities to reach production secrets, Docker socket or mutable OS paths.

## KVM lab verification (2026-10-24)

REA checkout `dscuongk581-lang/rea` v6.3.0. The source repo MCP doctor: 139/139 tool registration, 6/6 prompts, production-stdio adapter PASS.

The curated adapter test executed real MCP SDK client/server requests with `@modelcontextprotocol/server@2.3.1` and returned **PASS** for: exactly 4 tool definitions; read-only annotations; inventory; 32-section `systemctl` ELF; 1,276 recognized `systemctl` procedures; 31-section `systemd` ELF; malformed path rejected. No local TCP listener.

Command (only in an authorized isolated test environment):

```sh
cd /opt/agentos-rea-research/rea
REA_LAB_EVIDENCE_DIR=/opt/agentos-rea-research/linux-native-v10/evidence \
  node research/agentos-gpt-mcp/test.mjs
```

Each curated Evidence file is produced by REA during an **offline scan of an explicitly chosen copy** of the OS binary. The repo does not distribute those original binaries or Evidence dumps. The host being Debian 13 is still outside REA's officially supported distro set. The results are x86-64 evidence and do not establish ARM64 Pi support.

## To connect from ChatGPT privately

1. Arrange an isolated, unprivileged deployment of this server **before** external access. Restrict the Evidence directory to selected JSON files, no writable production mounts, no Docker socket, no root, and use OS cgroups/limits.
2. Prefer OpenAI **Secure MCP Tunnel** rather than opening an inbound port. It can launch a locally reachable **stdio** MCP command. Follow the official tunnel-client documentation, using a trusted tunnel provisioned in the correct OpenAI Platform organization/workspace.
3. The owner must create/select a `tunnel_id` in Platform tunnel settings and configure its runtime API key **via protected secret input**, never in ChatGPT messages, git, logs or command arguments. These credentials are not in this repo.
4. Configure tunnel-client to launch the unprivileged REA MCP command with its `REA_LAB_EVIDENCE_DIR` value. Validate `tunnel-client doctor --profile <profile> --explain`, run it and verify ready/polling.
5. From ChatGPT **web** Plugins (when the user/workspace is eligible), select **Add custom MCP server → Tunnel**, select the matching tunnel, review tools, and connect. Mobile setup and account permissions may differ.
6. A connection is only accepted when the four tools are discovered and an actual `rea_elf_layout(target=systemctl)` call from ChatGPT returns a supported Evidence hash. Until this end-to-end test, mark `CHATGPT_NOT_CONNECTED`.

Official docs:
- https://developers.openai.com/api/docs/guides/secure-mcp-tunnels
- https://help.openai.com/en/articles/12584461-connecting-custom-mcp-servers-in-chatgpt

## Phase 2, not part of this PR

Introduce an isolated REA analysis worker that can copy a **pre-authorized, digest-pinned** binary into a staging directory and analyze it under a separate short-lived process with CPU, memory and time limits. Add independently approved access to fresh binaries, a producer-consumer Evidence queue, audit provenance and observability. Keep AgentOS OS Graph/Event/Reconciler and admin executor in **Agentz**, not REA. No arbitrary read paths, shell or write tools in a future GPT connector.
