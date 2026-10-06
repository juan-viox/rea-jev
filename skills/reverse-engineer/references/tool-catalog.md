# REA tool catalog (rea-agents 4.0.1)

Generated from rea-agents 4.0.1 (116 tools). Source: `data/rea-tool-catalog.json`. Do not edit by hand; regenerate with `node scripts/validate.mjs --write-catalog` after bumping the pin.

Tool names are bare. In Claude Code they appear as `mcp__rea__<tool>` (REA registered globally by `rea setup`) or `mcp__plugin_rea-jev_rea__<tool>` (REA bundled by this plugin). Required inputs are the schema's `required` list; optional inputs are in the JSON catalog.

**Effect class** is what the rea-jev gate (`scripts/lib/rea.mjs`) uses, derived from the name and the `launchesProcess` effect:

| Class | Rule | Gate behavior |
|---|---|---|
| `runtime` (5) | launches a process and the name starts with `capture_` or `observe_` | local hard rules, then a Jev scope/risk check; may `ask` or `deny` |
| `mutation` (15) | `set_*`, `annotate_*`, `import_*`, `export_*`, `unset_bookmark`, `record_unknown`, `update_unknown`, `extract_artifact`, `open_binary`, `close_binary` | never deduplicated; resets the redundancy window |
| `status` (9) | `binary_session`, `list_unknowns`, `get_navigation_context`, `current_*`, `get_evidence_bundle`, `verify_unknown_resolution`, `list_documents` | never deduplicated, never sent to Jev |
| `inspect` (87) | everything else | an identical repeated call (same tool + same input) is denied until a mutation happens; results are scored by the evidence hook |

Contents: [official-proxy](#official-proxy-39-tools) · [enhanced](#enhanced-14-tools) · [native-provider](#native-provider-7-tools) · [artifact-provider](#artifact-provider-5-tools) · [managed-provider](#managed-provider-3-tools) · [application](#application-11-tools) · [browser-provider](#browser-provider-9-tools) · [electron-provider](#electron-provider-5-tools) · [runtime-provider](#runtime-provider-2-tools) · [session](#session-21-tools)

## official-proxy (39 tools)

Official proxy — Hopper/Ghidra provider primitives.

| Tool | Description | Required inputs | Effect |
|---|---|---|---|
| `inspect_native_data_type` | Inspect one recovered type by exact database category path or defined typed data address. | — | inspect |
| `inspect_native_instruction` | Inspect one exact instruction address: decoded bytes, mnemonic, ordered operand tokens, flow and typed references. | `address` | inspect |
| `resolve_native_call_targets` | Resolve one explicit static call site using typed provider call references. | `address` | inspect |
| `address_name` | Resolve the primary analyzed name at a code or data address. | — | inspect |
| `comment` | Read the regular analysis comment at an address, defaulting to the current cursor. | — | inspect |
| `current_address` | Return Hopper's current cursor address for the selected document. | — | status |
| `current_procedure` | Return the analyzed procedure containing Hopper's current cursor. | — | status |
| `current_document` | Return the document currently selected by REA's Hopper bridge. | — | status |
| `goto_address` | Move Hopper's GUI cursor to a hexadecimal address and return the resolved address. | `address` | inspect |
| `inline_comment` | Read the inline instruction comment at an address, defaulting to the current cursor. | — | inspect |
| `list_bookmarks` | List every bookmark in the selected Hopper document as address and name pairs. | — | inspect |
| `list_documents` | List provider program or document identities. | — | status |
| `list_names` | List every analyzed memory and external symbol as address/value pairs. | — | inspect |
| `list_procedures` | List every analyzed procedure as address/value pairs after provider analysis. | — | inspect |
| `list_segments` | List segments or memory blocks using exclusive end addresses. | — | inspect |
| `list_strings` | List every provider-defined string, or filter to one address, as address/value pairs. | — | inspect |
| `next_address` | Return the next analyzed object address after an explicit address or current cursor. | — | inspect |
| `prev_address` | Return the previous analyzed instruction start before an explicit address or current cursor. | — | inspect |
| `procedure_address` | Resolve an unambiguous procedure symbol name or provider-normalized address to its canonical entry address. | `procedure` | inspect |
| `procedure_assembly` | Return assembly for one analyzed procedure identified by symbol or hexadecimal address. | `procedure` | inspect |
| `procedure_callees` | Return the provider's resolved direct callees for one procedure identified by symbol or address. | `procedure` | inspect |
| `procedure_callers` | Return the provider's resolved direct callers for one procedure identified by symbol or address. | `procedure` | inspect |
| `procedure_info` | Return provider metadata for one procedure identified by symbol or address: entrypoint, signature, locals, size, block count, and complete… | `procedure` | inspect |
| `read_function_instructions` | Return every raw instruction for one analyzed procedure. | `procedure` | inspect |
| `read_bytes` | Read analyzed bytes from one provider-normalized virtual address. | `address` | inspect |
| `address_to_file_offset` | Map one provider-normalized virtual address to its original nonnegative file offset. | `address` | inspect |
| `procedure_references` | Return every raw incoming or outgoing reference edge for one procedure. | `procedure` | inspect |
| `procedure_pseudo_code` | Decompile one analyzed procedure by symbol name or provider-normalized address. | `procedure` | inspect |
| `resolve_containing_procedure` | Resolve an arbitrary address, including an interior instruction or exact external entry, to its provider-analyzed containing procedure. | `address` | inspect |
| `search_procedures` | Search every analyzed procedure name using literal matching by default or regex when requested. | `pattern` | inspect |
| `search_strings` | Search every analyzed string using literal matching by default or regex when requested. | `pattern` | inspect |
| `set_address_name` | Assign an analyst name to one hexadecimal address and report Hopper's boolean result. | `address`, `name` | mutation |
| `set_addresses_names` | Assign analyst names to multiple addresses in one call and return per-address success booleans. | `names` | mutation |
| `set_bookmark` | Create or replace a bookmark at a hexadecimal address and report success. | `address` | mutation |
| `set_comment` | Write a regular analysis comment at a hexadecimal address and return whether readback matched. | `address`, `comment` | mutation |
| `set_current_document` | Select an already-open Hopper document by exact document name. | `document` | mutation |
| `set_inline_comment` | Write an inline instruction comment at a hexadecimal address and return whether readback matched. | `address`, `comment` | mutation |
| `unset_bookmark` | Remove the bookmark at a hexadecimal address and return whether it is absent. | `address` | mutation |
| `xrefs` | Return analyzed references to a code or data address. | — | inspect |

## enhanced (14 tools)

Enhanced — composed native analysis.

| Tool | Description | Required inputs | Effect |
|---|---|---|---|
| `inspect_native_dispatch_metadata` | Inspect the bound provider's name inventory for Objective-C class/method symbols and Swift mangled symbols, returning at most max_records… | — | inspect |
| `get_objc_classes` | Discover and deduplicate Objective-C class labels, optionally filtering by literal substring. | — | inspect |
| `get_objc_protocols` | Discover and deduplicate Objective-C and Swift protocol labels. | — | inspect |
| `batch_decompile` | Decompile each explicit procedure symbol or address concurrently. | — | inspect |
| `get_call_graph` | Traverse the bound provider's caller or callee relationships from one symbol or address until the reachable graph is exhausted. | `address` | inspect |
| `analyze_swift_types` | Categorize analyzed procedure names into Swift classes, structs, enums, protocols, extensions, and other symbols. | — | inspect |
| `find_xrefs_to_name` | Resolve an exact name against the bound provider's name inventory and return a resolved or unresolved result. | `name` | inspect |
| `binary_overview` | Return native-binary metadata, every segment with its length, and exhaustive procedure/string counts. | — | inspect |
| `analyze_function` | Build a dossier for one native function identified by symbol or provider-returned address. | `procedure` | inspect |
| `inspect_native_api` | Analyze a native API boundary in one function identified by symbol or provider-returned address. | `procedure` | inspect |
| `trace_feature` | Trace a literal feature query through every matching string and procedure, their xrefs, and truthful containing-procedure resolution. | `query` | inspect |
| `trace_call_path` | Trace direct callers or callees from one exact procedure address until the graph is exhausted or the optional goal is reached. | `start` | inspect |
| `trace_native_ui_action` | Trace one unique compiled UI action, object ID, native symbol or exact function address through authored connections, encoded… | `action` | inspect |
| `trace_native_values` | Trace a bounded static dependency graph from one explicit native procedure. | `procedure` | inspect |

## native-provider (7 tools)

Native provider — Mach-O metadata and native UI.

| Tool | Description | Required inputs | Effect |
|---|---|---|---|
| `observe_native_ui` | Observe an already-running native app by PID and window ID, bound to the active Mach-O target. | `pid`, `window_id` | runtime |
| `capture_native_ui_scenario` | Run selected-element press, increment/decrement scroll, AXValue text entry and bounded wait steps in one exact native app window. | `pid`, `window_id`, `steps` | runtime |
| `inspect_macho` | Inspect Mach-O slices, load commands, imports, exports, dependencies, build metadata, segments, sections, permissions, and exact command… | — | inspect |
| `inspect_signature` | Inspect the active artifact's code-signing identity, hashes, authorities, requirements, entitlements, hardened-runtime state, and exact… | — | inspect |
| `inspect_plist` | Parse Info.plist from the active artifact by default, or pass any local plist path. | — | inspect |
| `list_architectures` | List thin or universal Mach-O slices with offsets, sizes, alignment, explicit coverage, and native-tool provenance. | — | inspect |
| `demangle_swift` | Demangle an ordered list of Swift symbols without requiring Hopper. | `symbols` | inspect |

## artifact-provider (5 tools)

Artifact provider — packages, archives, bundles.

| Tool | Description | Required inputs | Effect |
|---|---|---|---|
| `inspect_artifact` | Inspect an active archive or application package in one call. | — | inspect |
| `extract_artifact` | Extract all regular files from the active archive or application package into a fresh temporary directory chosen by REA. | — | mutation |
| `decode_interface_builder` | Decode compiled storyboard and nib archives inside the active Apple app bundle, including keyed property lists and NIBArchive object… | — | inspect |
| `inspect_keyed_archive` | Inspect one Foundation NSKeyedArchiver plist in the active app bundle as original object-table nodes, class descriptors, named roots,… | — | inspect |
| `inspect_asset_catalog` | Inspect compiled Assets.car metadata in an active Apple app bundle. | — | inspect |

## managed-provider (3 tools)

Managed provider — .NET PE/CLI.

| Tool | Description | Required inputs | Effect |
|---|---|---|---|
| `inspect_managed_artifact` | Open and classify an explicit managed PE/CLI path, or inspect the active managed target, then inventory exact assembly/module identity… | — | inspect |
| `inspect_managed_members` | Inspect PE/CLI metadata members, signatures, raw CIL hashes, decoded-instruction-tuple hashes, separately reported exception regions, call… | — | inspect |
| `inspect_managed_native_boundaries` | Inspect PE/CLI ModuleRef, ImplMap/PInvoke declarations, CLI native-header indicators, and non-IL method implementation flags… | — | inspect |

## application (11 tools)

Application workflows — managed and JavaScript graphs, reconstruction.

| Tool | Description | Required inputs | Effect |
|---|---|---|---|
| `compare_managed_members` | Compare two authenticated inspect_managed_members Evidence records using unique-only decoded-CIL/signature and structural method-shape… | `left`, `right` | inspect |
| `verify_managed_native_boundaries` | Verify managed P/Invoke/native-boundary declarations against authenticated native export or function Evidence without executing managed… | `managed_boundaries`, `native_observations` | inspect |
| `import_managed_reconstruction` | Import decompiler-produced managed reconstruction against authenticated inspect_managed_members Evidence. | `static_members`, `decompiler`, `methods` | mutation |
| `project_managed_application_graph` | Project authenticated managed artifact, member, and native-boundary Evidence into the provider-neutral application graph without executing… | — | inspect |
| `trace_application_feature` | Trace a typed literal seed through every reachable part of an authenticated JavaScript Application Graph supplied as inline Evidence. | `seed`, `application` | inspect |
| `trace_javascript_semantics` | Trace static JavaScript data-flow, direct call/return, and closure relations from inline application Evidence. | `application`, `query` | inspect |
| `compare_application_versions` | Compare two authenticated JavaScript Application Graph versions supplied as inline Evidence. | `left`, `right` | inspect |
| `compare_source_to_bundle` | Compare a cryptographically committed HistoricalSourceGraph with inline authenticated JavaScript Application Graph Evidence. | `reference`, `application` | inspect |
| `compare_javascript_export_shapes` | Compare static return shapes for one exact module/export selector on each authenticated JavaScript Application Graph supplied as inline… | `left_module_path`, `left_export_name`, `right_module_path`, `right_export_name`, `left`, `right` | inspect |
| `build_reconstruction_obligation_ledger` | Generate the complete deterministic ReconstructionObligationLedger from an authenticated Evidence bundle, reviewed obligations,… | `evidence_bundle`, `reviewed_obligations`, `manifest` | inspect |
| `evaluate_reconstruction_coverage` | Evaluate inline evidence-backed reconstruction coverage against one named boundary. | `coverage`, `boundary_id` | inspect |

## browser-provider (9 tools)

Browser provider — Chrome DevTools Protocol.

| Tool | Description | Required inputs | Effect |
|---|---|---|---|
| `list_browser_targets` | List page targets exposed by the selected loopback Chrome DevTools Protocol endpoint. | `cdp_endpoint` | inspect |
| `inspect_web_page` | Passively inspect one selected page target through CDP without evaluating JavaScript, navigating, clicking, closing, or mutating the page. | — | inspect |
| `analyze_web_bundle` | Capture JavaScript source from one selected CDP page and statically derive a chunk graph, route and endpoint candidates, vendor… | `cdp_endpoint`, `target_id` | inspect |
| `observe_web_session` | Arm a CDP observation window of the requested duration while the user operates the page. | `cdp_endpoint`, `target_id` | inspect |
| `discover_webmcp_tools` | Passively inventory every page-registered WebMCP tool and its complete structural input-schema summary using the experimental CDP WebMCP… | `cdp_endpoint`, `target_id` | inspect |
| `compare_web_captures` | Compare passive web captures by providing before and after, or compare recorded scenarios by providing before_scenario and after_scenario… | — | inspect |
| `capture_web_screenshot` | Capture the current visible viewport of one configured page as an inline, content-addressed PNG artifact. | `cdp_endpoint`, `target_id` | inspect |
| `compare_web_screenshots` | Compare two self-verifying PNG screenshot artifacts with local pixel metrics. | `before`, `after` | inspect |
| `capture_browser_scenario` | Run a controlled browser scenario when passive observation cannot exercise the application. | `browser`, `start_url`, `actions` | runtime |

## electron-provider (5 tools)

Electron provider.

| Tool | Description | Required inputs | Effect |
|---|---|---|---|
| `list_electron_targets` | List every Electron file:// page target from a selected loopback CDP endpoint. | `cdp_endpoint` | inspect |
| `inspect_electron_page` | Passively inspect one Electron file page by supplying its loopback CDP endpoint and target ID. | — | inspect |
| `analyze_javascript_application` | Reconstruct one local ASAR or extracted JavaScript application as an inline application graph without executing it. | `input_path` | inspect |
| `reconcile_javascript_runtime` | Reconcile verified static JavaScript application graphs with existing passive web/Electron CDP, passive V8 Inspector, or provider-owned… | `static_layers`, `runtime_observations` | inspect |
| `capture_electron_scenario` | Use this for a provider-owned Electron run when passive CDP or Inspector observation cannot exercise application behavior. | `executable_path`, `application_path` | runtime |

## runtime-provider (2 tools)

Runtime provider — V8 Inspector.

| Tool | Description | Required inputs | Effect |
|---|---|---|---|
| `list_javascript_runtime_targets` | List every eligible Node/Electron V8 Inspector target from an explicit literal-loopback endpoint. | `inspector_endpoint` | inspect |
| `observe_javascript_runtime` | Attach passively to one Node/Electron V8 Inspector target by supplying its loopback Inspector endpoint and target ID. | `inspector_endpoint`, `target_id` | inspect |

## session (21 tools)

Session — target lifecycle, Evidence, unknowns, comparisons.

| Tool | Description | Required inputs | Effect |
|---|---|---|---|
| `open_binary` | Open a local executable, application bundle, archive, JavaScript, source map, plist, or analysis database after validation. | `path` | mutation |
| `close_binary` | Optionally write a provider-neutral analysis snapshot atomically to the caller-supplied path, then close the active target and every… | — | mutation |
| `binary_session` | Report the complete current target, provider, capability availability, client-feature, analysis, and server-identity status… | — | status |
| `export_evidence_bundle` | Atomically write the session's deterministic Evidence bundle to the requested local path. | `path` | mutation |
| `import_evidence_bundle` | Read the JSON bundle at the supplied local path, validate every Evidence ID and canonical manifest, then atomically merge it. | `path` | mutation |
| `capture_process_scenario` | Run one caller-selected command under a PTY and return process capture Evidence with residual unknowns. | `executable` | runtime |
| `compare_process_captures` | Compare two compatible process capture observations across terminal, interaction, lifecycle, process, filesystem, command-shim, HTTP,… | `left`, `right` | inspect |
| `compare_artifacts` | Compare complete artifact inventories by logical occurrence path, content identity, metadata, and graph relations. | `left`, `right` | inspect |
| `compare_functions` | Compare two explicit sets of analyze_function Evidence across identity, exact provider text, calls, references, strings,… | `left`, `right` | inspect |
| `compare_bundles` | Compare two canonical Evidence bundles by exact record membership, explicit one-to-one observation pairs, and complete residual-unknown… | `left_bundle_path`, `right_bundle_path` | inspect |
| `find_changed_behavior` | Aggregate validated process and artifact comparison Evidence. | — | inspect |
| `build_call_path` | Build every shortest direct-callee path inline from complete analyze_function Evidence records using exact canonical addresses. | `functions`, `start`, `goal` | inspect |
| `correlate_static_and_runtime` | Evaluate every explicit caller-declared hypothesis between exact static comparison findings and runtime comparison dimensions. | `static_comparisons`, `runtime_comparisons`, `mappings` | inspect |
| `verify_reconstruction` | Verify a finite typed behavioral and structural specification against a canonical Evidence bundle. | `specification` | inspect |
| `list_unknowns` | List every current residual-unknown head in deterministic ID order, with optional exact status, severity, and domain filters. | — | status |
| `record_unknown` | Create one deterministic residual unknown and immutable mutation evidence. | `question`, `severity`, `domain`, `required_authority`, `required_confidence`, `required_environment`, `recommended_probes`, `relationships` | mutation |
| `update_unknown` | Append one immutable full-state revision and mutation evidence. | `unknown_id`, `expected_revision`, `status`, `severity`, `supporting_evidence_ids`, `contradicting_evidence_ids`, `required_authority`, `required_confidence`, `required_environment`, `recommended_probes`, `relationships`, `resolution` | mutation |
| `verify_unknown_resolution` | Revalidate the current residual-unknown head against live bundled evidence, exact authority/confidence/environment requirements,… | `unknown_id` | status |
| `get_evidence_bundle` | Return every Evidence record and residual unknown currently retained by this session as one inline bundle for direct inspection… | — | status |
| `get_navigation_context` | Return the selected document, current address, and containing/current procedure in one provider-neutral result. | — | status |
| `inspect_address_context` | Inspect one explicit reproducible address for its analyzed name, containing procedure, regular and inline comments, and matching bookmarks. | `address` | inspect |
