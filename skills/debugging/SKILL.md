---
name: debugging
description: "Systematically diagnose and fix bugs: reproduce the issue, read errors carefully, form and test hypotheses, and verify the fix."
---
# Debugging

Systematically diagnose and fix bugs: reproduce the issue, read errors carefully, form and test hypotheses, and verify the fix.

## The Debugging Process

Follow these steps in order. Do not skip ahead to guessing fixes.

## Step 1: Reproduce the Bug

Get the exact failure before doing anything else:
```
bash: python3 script.py                          # run the failing command
bash: pytest tests/test_auth.py::test_login -v   # run the specific failing test
```

If you cannot reproduce it, ask the user for exact command, input data, and full error output.

## Step 2: Read the Error Carefully

Read the **full** error message -- every line matters.

For Python tracebacks, read bottom-up:
1. **Last line** = exception type + message (the "what")
2. **Last frame above it** = file, line number, and code (the "where")
3. **Frames above that** = call chain showing how execution got there (the "how")

```
read_file: path=src/auth.py, offset=40, limit=15   # read around the failing line
```

Do NOT fix anything yet. Just read and understand.

## Step 3: Gather Context

Read the code around the failure point and check recent changes:
```
read_file: path=src/auth.py                         # full file for context
bash: git log --oneline -10 -- src/auth.py          # recent commits to this file
bash: git diff HEAD~3 -- src/auth.py                # recent changes
bash: grep -r "from.*auth import" src/ --include="*.py"  # who uses this module
```

## Step 4: Form a Hypothesis

Based on the error and context, state **one specific guess** about the cause:
- "The `user` variable is None because `get_user()` returns None when the token is expired, but line 45 accesses `user.name` without checking"
- "The file path is wrong because it uses a relative path but the script runs from a different working directory"

Be specific. "Something is wrong with auth" is not a hypothesis.

## Step 5: Test the Hypothesis

Add targeted logging to confirm your guess:
```
edit_file: path=src/auth.py, old_string="user = get_user(token)", new_string="user = get_user(token)\nprint(f'DEBUG: user={user}, token={token[:8]}...')"
bash: python3 script.py
```

If your hypothesis was wrong, remove debug prints, go back to Step 4 with what you learned. If confirmed, proceed to the fix.

## Step 6: Fix the Bug

Make the minimal fix that addresses the root cause, then clean up debug prints:
```
edit_file: path=src/auth.py, old_string="broken code", new_string="fixed code"
```

## Step 7: Verify the Fix

Run the exact same failing command from Step 1:
```
bash: python3 script.py                          # should succeed now
bash: pytest tests/test_auth.py::test_login -v   # should pass now
```

If it still fails, go back to Step 4. Do not stack more guesses on top -- re-examine.

## Step 8: Check for Regressions

Run broader tests to make sure the fix did not break other things:
```
bash: pytest tests/                              # full test suite
bash: pytest tests/test_auth.py -v               # all tests in the affected module
```

If no tests exist, manually test the happy path and error cases.

## Common Bug Patterns

### NameError: name 'x' is not defined
- Typo in variable/function name
- Missing import statement
- Variable used outside the scope where it was defined
```
bash: grep -n "import" src/failing_file.py       # check imports
```

### TypeError (wrong type, missing argument)
- Function returned None unexpectedly (missing return statement)
- Dict lookup returned None (use `.get()` with default)
- Wrong argument types passed to a function
```
read_file: path=src/utils.py, offset=25, limit=10   # check the function's return paths
```

### FileNotFoundError
- Relative path but working directory is different than expected
- File was deleted, moved, or never created
```
bash: ls -la path/to/expected/file
bash: pwd
```

### ConnectionError / TimeoutError
- Service is not running, wrong host/port, firewall issue
```
bash: curl -v http://localhost:8000/health
bash: ss -tlnp | grep 8000
```

### IndexError / KeyError
- Off-by-one, empty collection not checked, missing dict key, case sensitivity
```
edit_file: old_string="items[idx]", new_string="print(f'DEBUG: len={len(items)}, idx={idx}')\nitems[idx]"
```

## Tips

- Fix one bug at a time. If you find multiple issues, fix and verify each separately.
- Resist the urge to guess. Five minutes reading beats thirty minutes of trial and error.
- If stuck after two failed hypotheses, step back and re-read the full traceback and surrounding code.
- Keep debug changes minimal and always clean them up after.
- For complex bugs spanning multiple files, use `spawn` to investigate different parts in parallel.
- After fixing, consider adding a test to prevent the bug from returning.
