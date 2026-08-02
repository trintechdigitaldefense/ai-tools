---
name: memory-management
description: "Persistent memory system: when and what to save, MEMORY.md structure, daily notes, pruning, and handling contradictions."
---
# Memory Management

Persistent memory system for retaining context across conversations. Memory lives in `workspace/memory/` — primarily `MEMORY.md` for long-term knowledge and dated files for session notes.

## When to Save

Save information that will be useful in future conversations:
- **User preferences**: name, timezone, communication style, preferred tools, languages
- **Project context**: what they're working on, tech stack, repo structure, key decisions
- **Important facts**: references, account details, API endpoints, environment specifics
- **Decisions and rationale**: why a particular approach was chosen over alternatives
- **Corrections**: if the user corrects you, save the correct information immediately
- **Recurring requests**: patterns you notice (e.g., "user always wants TypeScript, not JavaScript")
- **Explicit requests**: if the user says "remember this" or "keep track of X", always save it

## When NOT to Save

Do not clutter memory with ephemeral information:
- One-off questions that won't recur ("what time is it in Tokyo?")
- Temporary debugging state (current error messages, stack traces being investigated)
- Session-specific context that only matters right now (intermediate search results)
- Information already in project files (don't duplicate README content)
- Speculative conclusions — verify before persisting

## MEMORY.md Structure

Keep MEMORY.md organized with clear sections. Recommended layout:

```markdown
## User Profile
- Name: Alex
- Timezone: UTC+1
- Prefers concise responses, no emojis
- Primary languages: Python, TypeScript

## Projects
### project-name
- Stack: FastAPI + PostgreSQL + React
- Repo: ~/repos/project-name
- Deploy: runs on AWS EC2, nginx reverse proxy
- Key decisions: chose SQLAlchemy over raw SQL for ORM

## Preferences
- Always use `uv` for Python package management, not pip
- Prefers functional components in React
- Test framework: pytest with -v flag

## Key Facts
- LibertAI API key stored in .env as LIBERTAI_API_KEY
- Production DB is PostgreSQL 16, dev is SQLite
- CI runs on GitHub Actions

## Tooling
- Editor: VS Code with vim keybindings
- Shell: zsh with oh-my-zsh
- Docker for local databases
```

Adapt sections to what you actually know — don't create empty sections.

## Update vs Append

- **Update existing entries** when information changes (user switches tools, project evolves)
- **Append new entries** when learning something genuinely new
- **Never duplicate** — search MEMORY.md before adding; if a section covers the topic, update it

### Updating existing information
When a fact changes, use `edit_file` to replace the old value:
```
edit_file: path=workspace/memory/MEMORY.md, old_string="- Timezone: UTC+1", new_string="- Timezone: UTC-5 (moved to EST)"
```

### Adding new information
Append to the appropriate section:
```
edit_file: path=workspace/memory/MEMORY.md, old_string="## Key Facts", new_string="## Key Facts\n- Staging server at staging.example.com"
```

### Creating MEMORY.md from scratch
If no memory file exists yet, create one:
```
write_file: path=workspace/memory/MEMORY.md, content="## User Profile\n- Name: Alex\n\n## Projects\n\n## Preferences\n\n## Key Facts\n"
```

## Daily Notes

Use `memory/YYYY-MM-DD.md` for session-specific context:
- What was worked on today
- Problems encountered and how they were resolved
- Decisions made during the session
- TODO items for next time

Daily notes are for **context that may expire** — things relevant to the current work sprint but not permanently important. When a daily note contains a lasting insight, promote it to MEMORY.md.

## Pruning and Maintenance

Keep MEMORY.md under 200 lines. Periodically:
- **Remove outdated info**: completed projects, old preferences, resolved issues
- **Consolidate duplicates**: merge entries that say the same thing differently
- **Promote daily notes**: move lasting insights from dated files to MEMORY.md
- **Archive old daily notes**: if a daily note is more than 2 weeks old and its content has been captured in MEMORY.md, it can be deleted

## Handling Contradictions

When the user corrects something you previously saved:
1. Update MEMORY.md immediately with the correct information
2. Use `edit_file` to replace the wrong entry — do not just append the correction
3. If the correction is significant, note it briefly (e.g., "- Deploy target: Vercel (previously was Netlify)")

When you read something in memory that conflicts with what the user just said, trust the user's current statement and update memory accordingly.

## Tips

- Read MEMORY.md at the start of a conversation to load context
- Save early — don't wait until the end of a conversation to persist important facts
- Be specific: "prefers pytest over unittest" is better than "has testing preferences"
- Never store secrets (API keys, passwords) in memory files
- When uncertain whether to save something, err on the side of saving — pruning is easier than forgetting
