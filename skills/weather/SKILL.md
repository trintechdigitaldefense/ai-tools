---
name: weather
description: "Weather forecasts, moon phases, and comparisons using wttr.in (no API key needed)."
---
# Weather

Weather forecasts, moon phases, and comparisons using wttr.in (no API key needed).

## Quick Check
Use the bash tool to fetch weather:
```
bash: curl -s "wttr.in/CityName?format=3"
```

For detailed current conditions:
```
bash: curl -s "wttr.in/CityName"
```

## Multi-Day Forecast
Append `?N` where N is the number of days (0-3):
```
bash: curl -s "wttr.in/Paris?2"       # today + 2 days
bash: curl -s "wttr.in/Paris?0"       # today only (compact)
```

## Location Formats
- **City names**: `wttr.in/Paris`, `wttr.in/New+York`, `wttr.in/São+Paulo`
- **Airport codes**: `wttr.in/JFK`, `wttr.in/CDG`
- **Coordinates**: `wttr.in/48.8566,2.3522`
- **Landmarks**: `wttr.in/~Eiffel+Tower`, `wttr.in/~Statue+of+Liberty`
- **IP-based** (auto-detect): `wttr.in/` (no location)

## Custom Format Strings
Build custom output with `?format=`:
```
bash: curl -s "wttr.in/London?format=%l:+%c+%t+%h+%w"
```

Useful format codes:
| Code | Meaning | Example |
|------|---------|---------|
| `%c` | Weather condition icon | ☀️ |
| `%t` | Temperature | +15°C |
| `%h` | Humidity | 72% |
| `%w` | Wind | →13km/h |
| `%p` | Precipitation (mm) | 0.0mm |
| `%u` | UV index | 4 |
| `%S` | Sunrise | 06:42:00 |
| `%s` | Sunset | 20:15:00 |
| `%m` | Moon phase icon | 🌓 |
| `%M` | Moon day | 7 |

## Moon Phase
```
bash: curl -s "wttr.in/Moon"
```
Shows current moon phase with ASCII art and illumination percentage.

## Comparing Multiple Cities
Fetch several locations in a single command:
```
bash: echo "=== Paris ===" && curl -s "wttr.in/Paris?format=3" && echo "=== London ===" && curl -s "wttr.in/London?format=3" && echo "=== Tokyo ===" && curl -s "wttr.in/Tokyo?format=3"
```

## Options
- `?m` — metric units (default outside US)
- `?u` — US/imperial units
- `?format=j1` — JSON output for programmatic use
- `?lang=fr` — output in other languages (fr, de, es, etc.)
- `?T` — disable terminal color codes (for cleaner text output)

## Error Handling
If wttr.in is down or returns an error:
1. Retry once after a short pause: `bash: sleep 2 && curl -s "wttr.in/Paris?format=3"`
2. If it still fails, try the JSON endpoint: `bash: curl -s "wttr.in/Paris?format=j1"`
3. As a last resort, use web_search to find current weather: `web_search: "current weather in Paris"`
4. Let the user know wttr.in is temporarily unavailable
