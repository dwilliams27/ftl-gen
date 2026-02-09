# Phase 5: Pipeline Integration

**Goal**: Wire binary patching into the existing mod generation/deployment flow.

## Modified flow

```
1. Slipstream validates .ftl mod         (existing)
2. Slipstream patches ftl.dat            (existing)
3. -> Binary patcher applies augment remap (NEW, opt-in)
4. FTL launches                          (existing)
```

## Changes to existing files

### `cli.py`

Add `--binary-patch` flag to `mod` command (explicit opt-in):

```python
binary_patch: bool = typer.Option(False, "--binary-patch", help="Apply binary patches for augment effects")
```

### `_validate_patch_run()`

After Slipstream patch succeeds, if `binary_patch=True`:
1. Generate patch spec from mod's augments (using `AugmentEffectMapper`)
2. Apply via `BinaryPatcher`
3. On cleanup/error, revert binary

### `core/slipstream.py`

Add `binary_patches` param to `patch_and_launch()` — apply between XML patch and FTL launch.

### `core/launcher.py`

Store reference to patcher; revert binary on `stop()` if patches were applied.

## API endpoints: `src/ftl_gen/api/routes/binary.py`

- `GET /api/v1/binary-info` — binary inspection results
- `GET /api/v1/binary-patch/status` — current patch state
- `POST /api/v1/binary-patch/apply` — apply patches for a mod's augments
- `POST /api/v1/binary-patch/revert` — restore original binary

Register in `api/app.py` router.

## UI (minimal, later phase)

- Binary patch toggle on Generate page
- Patch status indicator in Settings page
