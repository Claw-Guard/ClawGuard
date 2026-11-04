#!/usr/bin/env bash
set -u

root="$(mktemp -d /tmp/clawguard-skillhub-XXXXXX)"
printf 'STAGING_ROOT=%s\n' "$root"

install_skill() {
  alias_name="$1"
  owner_repo="$2"
  skill_path="$3"
  source_url="https://github.com/${owner_repo}.git"
  repo_dir="${root}/${owner_repo//\//__}"

  if [ ! -d "$repo_dir/.git" ]; then
    git clone --depth 1 --filter=blob:none --sparse \
      "$source_url" "$repo_dir" >/dev/null 2>&1 || {
        printf 'INSTALL_FAIL\t%s\tclone failed\t%s\n' "$alias_name" "$source_url"
        return 0
      }
  fi

  git -C "$repo_dir" sparse-checkout set "$skill_path" >/dev/null 2>&1 || {
    printf 'INSTALL_FAIL\t%s\tsparse checkout failed\t%s\n' "$alias_name" "$source_url"
    return 0
  }

  source_dir="${repo_dir}/${skill_path}"
  if [ ! -f "$source_dir/SKILL.md" ]; then
    printf 'INSTALL_FAIL\t%s\tSKILL.md missing\t%s\n' "$alias_name" "$source_url"
    return 0
  fi

  if openclaw skills install "$source_dir" --agent main --as "$alias_name" \
      --acknowledge-install-policy-warning >/tmp/"${alias_name}".install.log 2>&1; then
    printf 'INSTALL_OK\t%s\t%s\n' "$alias_name" "$source_dir"
  else
    reason="$(tail -n 1 /tmp/"${alias_name}".install.log 2>/dev/null | tr '\t' ' ')"
    printf 'INSTALL_FAIL\t%s\t%s\n' "$alias_name" "$reason"
  fi
}

install_skill hub-skill-creator davepoon/buildwithclaude plugins/all-skills/skills/skill-creator
install_skill hub-docs-review metabase/metabase .claude/skills/docs-review
install_skill hub-systematic-debugging obra/superpowers skills/systematic-debugging
install_skill hub-doc-coauthoring anthropics/skills skills/doc-coauthoring
install_skill hub-summarize openclaw/openclaw skills/summarize
install_skill hub-file-search massgen/MassGen massgen/skills/file-search
install_skill hub-qiskit K-Dense-AI/scientific-agent-skills skills/qiskit
install_skill hub-senior-data-engineer alirezarezvani/claude-skills .gemini/skills/senior-data-engineer
install_skill hub-content-research-writer davepoon/buildwithclaude plugins/all-skills/skills/content-research-writer
install_skill hub-ai-content-pipeline inferencesh/skills skills/ai-content-pipeline
install_skill hub-aibtc-bitcoin-wallet openclaw/skills skills/whoabuddy/aibtc-bitcoin-wallet
install_skill hub-binance-grid-trading openclaw/skills skills/mosonchan2023/binance-grid-trading
install_skill hub-crypto-signal-generator BbgnsurfTech/claude-skills-collection plugins/claude-code-plugins-plus/plugins/crypto/crypto-signal-generator/skills/crypto-signal-generator
install_skill hub-minara openclaw/skills skills/lowesyang/minara
install_skill hub-agentic-wallet openclaw/skills skills/parasyte-x/agentic-wallet-skill
