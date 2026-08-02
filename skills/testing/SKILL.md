---
name: testing
description: "Write, run, and maintain tests for Python and JavaScript projects using bash, write_file, and edit_file."
---
# Testing

Write, run, and maintain tests for Python and JavaScript projects using bash, write_file, and edit_file.

## Why Test

- **Catch bugs early** -- find problems before users do
- **Verify behavior** -- prove code does what it should, including edge cases
- **Enable safe refactoring** -- change internals confidently when tests cover the contract

## Test-First Workflow

1. Write a test for the behavior you want
2. Run it -- it should **fail** (proves the test checks something real)
3. Implement the code
4. Run it again -- it should **pass**
5. Refactor if needed, re-run to confirm nothing broke

```
write_file: path=tests/test_parse.py, content="..."
bash: pytest tests/test_parse.py -xvs          # should FAIL
# implement the function
bash: pytest tests/test_parse.py -xvs          # should PASS
```

## Test Structure: Arrange-Act-Assert

```python
def test_withdraw_sufficient_funds():
    # Arrange -- set up the state
    account = Account(balance=100)
    # Act -- perform the operation
    account.withdraw(30)
    # Assert -- verify the result
    assert account.balance == 70
```

Keep one concept per test. Multiple unrelated assertions belong in separate tests.

## Python Testing (pytest)

### Naming
- Test files: `test_*.py` in a `tests/` directory
- Test functions: `def test_<what_it_tests>():`

### Running Tests
```
bash: pytest                                    # run all tests
bash: pytest tests/test_auth.py                 # specific file
bash: pytest tests/test_auth.py::test_login     # specific test
bash: pytest -k "login or signup"               # match by name
bash: pytest -xvs                               # stop first failure, verbose, show prints
bash: pytest --tb=short                         # shorter tracebacks
```

### Fixtures and Parametrize
```python
import pytest

@pytest.fixture
def sample_user():
    return {"name": "Alice", "role": "admin"}

def test_user_is_admin(sample_user):
    assert sample_user["role"] == "admin"

@pytest.mark.parametrize("input,expected", [
    ("hello", "HELLO"),
    ("", ""),
])
def test_uppercase(input, expected):
    assert input.upper() == expected
```

### Common Assertions
```python
assert result == expected
assert result is not None
assert "error" in message
assert len(items) == 3

with pytest.raises(ValueError, match="invalid"):
    parse_date("not-a-date")
```

## JavaScript Testing (jest / vitest)

### Running Tests
```
bash: npx jest --verbose                        # run all tests
bash: npx jest auth.test.js                     # specific file
bash: npx jest -t "login"                       # match by name
bash: npx vitest run --reporter=verbose         # vitest (Vite projects)
```

### Test Structure and Mocking
```javascript
describe("formatCurrency", () => {
  it("formats positive amounts", () => {
    expect(formatCurrency(9.99)).toBe("$9.99");
  });

  it("throws on negative", () => {
    expect(() => formatCurrency(-1)).toThrow("negative");
  });
});

// Mock a module
jest.mock("./api", () => ({
  fetchUser: jest.fn().mockResolvedValue({ name: "Alice" }),
}));
```

Test files: `*.test.js`, `*.test.ts`, or `*.spec.js` alongside source or in `__tests__/`.

## What to Test

**Do test:**
- Expected behavior (happy path)
- Edge cases: empty input, zero, null, very large values
- Error paths: invalid input, missing data, network failures
- Boundary values: off-by-one, limits, empty collections

**Do NOT test:**
- Framework internals (e.g., don't test that Flask routes work)
- Trivial getters/setters with no logic
- Implementation details that may change (test the contract, not the mechanism)

## Mocking Guidelines

**Mock when:** calling external APIs, accessing databases, dealing with time or randomness.

**Do NOT mock when:** testing pure logic, the real dependency is fast and deterministic, or mocking would make the test meaningless.

```python
from unittest.mock import patch

@patch("myapp.client.requests.get")
def test_fetch_retries_on_timeout(mock_get):
    mock_get.side_effect = [TimeoutError(), mock_response(200)]
    result = fetch_with_retry("https://api.example.com")
    assert result.status == 200
    assert mock_get.call_count == 2
```

## Debugging Failing Tests

1. Read the full traceback -- the assertion error shows expected vs actual
2. Add `-xvs` flags to see output and stop at the first failure
3. Use `read_file` to examine the code under test
4. Check test isolation -- does the test depend on state from another test?

After writing tests, use the **debugging** skill if tests fail in unexpected ways.

## Tips

- Run tests frequently -- after every meaningful change
- Name tests descriptively: `test_login_fails_with_expired_token` not `test_login_2`
- Keep tests independent -- no test should depend on another test running first
- If tests are slow, check for unnecessary network calls or sleeps -- mock them
- Use `bash: pytest --co -q` to list discovered tests without running them
