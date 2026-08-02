---
name: software-design
description: "Plan and design software changes before coding: gather requirements, break down components, define interfaces, and write a design doc."
---
# Software Design

Plan and design software changes before coding: gather requirements, break down components, define interfaces, and write a design doc.

## When to Design First

Design before coding when:
- The change touches **3+ files** or introduces a new module
- You're building a **new feature** (not a small fix or tweak)
- Requirements are **vague or ambiguous** -- you need to clarify before writing code
- The change involves **new data structures, APIs, or protocols**
- You're unsure how existing code is organized or what already exists

Skip formal design for: one-line fixes, config changes, renaming, simple bug patches.

## Step 1: Understand the Codebase

Before designing anything, explore what already exists:
```
list_dir: path=src/
read_file: path=src/main.py
bash: grep -r "class.*Manager" src/ --include="*.py" -l
```

Read key files to understand current patterns, conventions, and data flow:
```
read_file: path=src/models.py
read_file: path=src/services/auth.py
```

## Step 2: Gather Requirements

Clarify what the user actually wants before designing:
- **What** does this feature do from the user's perspective?
- **Who** uses it? (API consumer, end user, admin, background task)
- **What inputs/outputs?** What data goes in, what comes out?
- **What constraints?** (performance, compatibility, security, dependencies)
- **What error cases** need handling?

If any of these are unclear, ask the user before proceeding.

## Step 3: Break Down Components

Identify the pieces needed. For each component, define its **responsibility** (one clear job), **location** (file path), and **dependencies** (what it needs):

```
Feature: File upload with virus scanning

Components:
1. UploadRouter (routers/upload.py) -- HTTP endpoint, validates file type/size
2. StorageService (services/storage.py) -- saves files to disk or S3
3. ScanService (services/scanner.py) -- calls antivirus API
4. FileRecord model (models.py) -- DB schema for uploaded files
```

## Step 4: Define Interfaces

Specify function signatures, data structures, and API contracts for each component:

```python
async def save(file: UploadFile, user_id: int) -> str:
    """Save file, return storage path."""

class FileRecord:
    id: int
    user_id: int
    filename: str
    storage_path: str
    status: str  # "pending_scan", "clean", "infected"
```

## Step 5: Map Data Flow

Trace how data moves through the system for the primary use case:

```
1. Client sends POST /upload with multipart file
2. UploadRouter validates file type and size (<10MB)
3. StorageService.save() writes to /uploads/{user_id}/{uuid}.{ext}
4. FileRecord created in DB with status="pending_scan"
5. Background task: ScanService.scan(path) calls antivirus API
6. FileRecord.status updated to "clean" or "infected"
```

## Step 6: Identify Risks

Check for issues before writing code:
- **Build order** -- what must exist before other parts can work?
- **External dependencies** -- new packages, APIs, services needed?
- **Migration needs** -- database schema changes? Data backups?
- **Breaking changes** -- does this change interfaces others depend on?

```
bash: git log --oneline -10 -- src/models.py    # recent model changes
read_file: path=requirements.txt                 # current dependencies
```

## Step 7: Write a Design Doc

Save a brief plan to the workspace before coding:
```
write_file: path=workspace/design/feature-name.md, content="..."
```

A good design doc:
```markdown
# Feature: [Name]

## Goal
One sentence describing what this achieves.

## Components
- [Component] -- [responsibility]

## Key Interfaces
[Function signatures or API contracts]

## Data Flow
[Numbered steps]

## Open Questions
- [Anything still unclear]
```

Keep it short -- half a page to one page. Working reference, not formal documentation.

## Step 8: Implement

With the design in place, code in this order:
1. **Data models first** -- DB tables, Pydantic schemas
2. **Core logic next** -- services and business rules
3. **Integration last** -- routers, CLI commands, UI

Use the relevant domain skill for implementation (`python-dev`, `node-dev`, etc.). Refer back to the design doc as you work:
```
read_file: path=workspace/design/feature-name.md
```

## Tips

- Start simple -- design the minimum that works, then extend
- If the design feels too complex, split the feature into smaller deliverables
- Name things by what they do, not how they do it (`UserNotifier` not `EmailSMTPSender`)
- Check existing code for patterns before inventing new ones -- consistency matters
- When stuck on a design choice, write out both options with trade-offs and ask the user
