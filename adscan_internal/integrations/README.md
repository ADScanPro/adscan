# Internal Integrations

This directory contains vendored/integrated third-party tools that are tightly coupled with ADscan.

## Why Internal Integrations?

Tools in this directory are:
1. **Performance-critical**: Direct Python imports are 7-10x faster than subprocess calls
2. **Tightly coupled**: Require deep integration with ADscan's service layer
3. **Distribution-friendly**: Must be included in PyInstaller/PyArmor builds
4. **Maintained by us**: Either developed in-house or heavily customized

## Current Integrations

### bloodhound-cli

**Location**: `bloodhound_cli/`
**Purpose**: BloodHound data querying and analysis
**Edition**: Both BloodHound CE and Legacy (Neo4j)
**Service**: [BloodHoundService](../services/bloodhound_service.py)

BloodHound integration for Active Directory attack path analysis. Provides:
- User and computer enumeration
- Session detection
- ACL/ACE analysis
- Attack path discovery
- Data upload (CE only)

**Dependencies**:
- neo4j>=5.0.0
- requests>=2.31.0
- rich>=13.7.0
- structlog>=24.1.0
- pydantic-settings>=2.4.0

**Import path**: `from adscan_internal.integrations.bloodhound_cli.core import ...`

## Adding New Integrations

When adding a new tool integration:

1. **Evaluate necessity**: Only integrate if:
   - Tool is performance-critical (subprocess overhead unacceptable)
   - Deep integration needed (not just CLI wrapper)
   - Must be in binary distribution
   - We control/maintain the codebase

2. **Directory structure**:
   ```
   integrations/
   ├── __init__.py
   ├── README.md (this file)
   └── tool_name/
       ├── __init__.py
       └── ...
   ```

3. **Service wrapper**:
   - Create service in `adscan_internal/services/tool_service.py`
   - Inherit from `BaseService`
   - Emit progress events
   - Use `@requires_pro` for PRO features
   - Add comprehensive docstrings

4. **Dependencies**:
   - Add to `requirements.txt` with versions
   - Test with PyInstaller to ensure proper packaging
   - Document in service docstring

5. **Documentation**:
   - Create `docs/tool_service_integration.md`
   - Include usage examples
   - Document migration from subprocess approach
   - Performance comparison

## Not for Integrations

Some tools should **NOT** be integrated here:

- **External CLIs**: Tools we don't control (NetExec, Impacket) - use adapter pattern
- **System tools**: Standard utilities (curl, wget, apt-get)
- **Simple wrappers**: If subprocess works fine and no performance issue
- **Rarely used**: Tools only used in edge cases

For these, use:
- Adapter pattern with clean subprocess interface
- Runtime dependency checks
- Clear error messages if tool missing

## Build Considerations

### PyInstaller

Tools in this directory are automatically detected by PyInstaller's module scanning. No special configuration needed unless:
- Dynamic imports are used
- Non-Python files need inclusion (data, configs)

If needed, add to `adscan.spec`:
```python
datas=[
    ('adscan_internal/integrations/tool_name/data/*', 'adscan_internal/integrations/tool_name/data/'),
]
```

### PyArmor

All Python code in integrations will be obfuscated automatically with the rest of ADscan. Ensure:
- No reflection/eval usage (breaks obfuscation)
- No hardcoded paths to source files
- All imports use relative paths

## Testing

Test integrated tools in both contexts:

1. **Development**: Direct Python execution
2. **Production**: PyInstaller binary

```bash
# Development
python -m adscan_internal.services.tool_service

# After build
./dist/adscan check
```

## License Considerations

Integrated tools must have compatible licenses:
- MIT, Apache 2.0, BSD: ✅ Safe to integrate
- GPL: ⚠️ Requires careful consideration (ADscan is proprietary)
- Proprietary: ✅ If we own it (like bloodhound-cli)

Always verify license compatibility before integration.
