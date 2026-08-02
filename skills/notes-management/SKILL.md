---
name: notes-management
description: "Create, search, organize, and manage personal notes in the workspace file system."
---
# Notes Management

Create, search, organize, and manage personal notes using the workspace file system. Notes are stored as markdown files in `workspace/notes/`.

## Directory Structure

```
workspace/notes/
├── inbox.md              — quick capture, unsorted thoughts
├── personal/             — personal notes, contacts, ideas
├── work/                 — work-related notes, meeting notes
├── projects/             — project-specific notes
│   ├── project-name.md
│   └── another-project.md
├── reference/            — reference material, how-tos, checklists
└── archive/              — completed/old notes
```

Create directories as needed — don't pre-create empty structures.

## Quick Capture

When the user shares a thought, idea, or piece of information without context, **append** to the inbox:
```
bash: mkdir -p workspace/notes && cat >> workspace/notes/inbox.md << 'EOF'

---
### [2025-03-25] Quick Note Title
Content here...
EOF
```

If `inbox.md` doesn't exist yet, create it with a header first:
```
bash: mkdir -p workspace/notes && cat > workspace/notes/inbox.md << 'EOF'
# Inbox
Quick capture for unsorted notes. Review and sort regularly.

### [2025-03-25] Note Title
Content here...
EOF
```

**Important:** Always use `cat >>` (append) for adding to an existing inbox. Never use `write_file` or `edit_file` for appending — `write_file` overwrites the entire file and `edit_file` requires an exact string match.

## Creating Notes

### Topical note
```
write_file: path=workspace/notes/topic-name.md
---
# Topic Name
Created: 2025-03-25
Tags: tag1, tag2

## Key Points
- Point 1
- Point 2

## Details
Extended content here...

## References
- [Source](url)
---
```

### Meeting notes
```
write_file: path=workspace/notes/work/meeting-2025-03-25.md
---
# Meeting: Title
Date: 2025-03-25
Attendees: Alice, Bob, Charlie

## Agenda
1. Item 1
2. Item 2

## Discussion
- Key point discussed...
- Decision made: ...

## Action Items
- [ ] Alice: do X by Friday
- [ ] Bob: review Y

## Next Meeting
Date: TBD
---
```

### Project note
```
write_file: path=workspace/notes/projects/project-name.md
---
# Project: Name
Status: Active
Started: 2025-03-25

## Overview
What this project is about...

## Goals
- [ ] Goal 1
- [ ] Goal 2

## Log
### 2025-03-25
- Started project, set up initial structure
- Decision: using Python for backend
---
```

## Searching Notes

### Find notes by keyword
```
bash: grep -rli "SEARCH_TERM" workspace/notes/ 2>/dev/null || echo "No matches found"
```

### Search with context (show matching lines)
```
bash: grep -rni "SEARCH_TERM" workspace/notes/ 2>/dev/null || echo "No matches found"
```

### List all notes
```
bash: find workspace/notes/ -name "*.md" -type f | sort
```

### List recent notes (modified in last 7 days)
```
bash: find workspace/notes/ -name "*.md" -type f -mtime -7 | sort
```

### List notes by size (find longest/most detailed)
```
bash: find workspace/notes/ -name "*.md" -type f -exec wc -l {} + | sort -n
```

## Organizing Notes

### Move a note to a category
```
bash: mkdir -p workspace/notes/work && mv workspace/notes/some-note.md workspace/notes/work/
```

### Archive old notes
```
bash: mkdir -p workspace/notes/archive && mv workspace/notes/old-note.md workspace/notes/archive/
```

### Process the inbox
Periodically review `inbox.md`, move items to proper notes, and clear processed entries:
1. `read_file: path=workspace/notes/inbox.md`
2. For each item, either:
   - Create/update a topical note with the content
   - Save to memory if it's a preference or key fact
   - Delete if no longer relevant
3. Clean up processed items from inbox

### Create a table of contents
```
bash: echo "# Notes Index" > workspace/notes/INDEX.md && echo "" >> workspace/notes/INDEX.md && find workspace/notes/ -name "*.md" ! -name "INDEX.md" -type f | sort | while read f; do title=$(head -1 "$f" | sed 's/^#* *//'); echo "- [${title:-$(basename $f)}]($f)" >> workspace/notes/INDEX.md; done && cat workspace/notes/INDEX.md
```

## Linking Notes to Memory

When a note contains lasting information (user preferences, key decisions, important contacts), promote it to `workspace/memory/MEMORY.md`:
```
edit_file: path=workspace/memory/MEMORY.md
old_string: ## Key Facts
new_string: ## Key Facts
- Important fact extracted from notes/project-x.md
```

Notes are for detailed, evolving content. Memory is for distilled, stable facts.

## Tips

- Use the `inbox.md` for quick capture — sort later.
- Prefix filenames with dates for chronological notes: `2025-03-25-meeting.md`.
- Use `grep -rli` for case-insensitive search across all notes.
- Keep notes concise — if a note grows beyond 200 lines, split it.
- Use `list_dir` before creating a note to avoid duplicates.
- Tag notes with `Tags:` in the header for easier discovery.
- Use `spawn` to search notes in the background while answering the user.
