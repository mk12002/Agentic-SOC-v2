# Requirements traceability - CyberDome for NAM

Every requirement of the NAM build - the modules (M0-M13), the rules of who decides what, the guardrails and the
phase discipline - traced to where it is implemented and the tests that prove it. Status: **Built** (in code, tested
on every build), **Partial** (built in part; what is missing is named), **Open** (not built, with the reason).
Source of the requirements: the NAM design note and deck (summarised in CLAUDE.md §0), which win over this table if
they differ.

## 1. Modules

| # | Requirement | Status | Implementation | Tests |
|---|---|---|---|---|
| M0 | CyberDome branding; only what NAM asked for; no name or data of the earlier client | Built (an asset-manager sample estate is Open) | console, reports, API title; `core/scope.py` (`SOC_PRODUCT_SCOPE=nam`) | `test_scope.py`, `test_generalisation.py`, `test_variants.py` |
| M1 | Read NAM's tools, read-only first: Forcepoint DLP, Silverfort, Trend Micro, Trellix ePO, the AD / CMDB export | Partial: fake mode on placeholder APIs; Arcon, Cloudflare, SIEM / SOAR products Open | `connectors/tools/{forcepoint_dlp,silverfort,trend_micro,trellix_epo,directory_export}.py`, `_paged.py` | `test_connector_nam_stack.py`, `test_connector_conformance.py`, `test_live_wire.py` |
| M2 | Tool health: silent agents > 24 h, failed / late jobs, certificate days, unmapped users; warn ahead; recommend a ticket or re-push; "wherever the tool reports them" | Built | `intelligence/tool_health.py`, `health` streams, capability matrix | `test_controls_posture.py` |
| M3 | Control coverage: baseline × controls; devices missing a control; devices a tool sees the baseline lacks; users in no DLP policy group; ranked by sensitive data | Built | `core/controls.py`, `intelligence/control_coverage.py` | `test_controls_posture.py` |
| M4 | DLP domain: intake, personal-data flags, computed disposition, cases; triage with identity, PAM and endpoint context | Built (PAM context waits for Arcon) | `domains/dlp/service.py`, `models.py` | `test_dlp.py`, `test_dlp_api.py` |
| M5 | Earned autonomy: decision types; shadow → recommend → decide; AI decision record; promotion proposed with evidence; drift demotes | Built for shadow / recommend; decide refused in code | `core/decisions.py` | `test_decisions.py` |
| M6 | AI investigator: read-only look-ups from a fixed menu within a step and time budget; every finding cited | Built | `domains/dlp/investigator.py` | `test_dlp_investigator.py` |
| M7 | DLP tuning proposals: false positives per rule, effect on past alerts, engineer approves and makes it; overrides feed it; classification quality (OCR, fingerprints, EDM) | Built | `domains/dlp/tuning.py` | `test_dlp_tuning.py` |
| M8 | Cross-tool cases: joining sign-in risk, privileged check-out, DLP exfiltration, encryption off; computed severity ("N tools agree"); reversible actions by AI, containment by two approvers | Partial: privileged check-outs wait for Arcon | `intelligence/crosstool.py`, Silverfort / Trend Micro actions, `core/policy.py` | `test_crosstool.py`, `test_core_governance.py` |
| M9 | SOAR execution backend | Open: product unknown | - | - |
| M10 | Dome Score and CISO view: published, versioned formula; five domain scores; "why did it drop" from computed factors; board report | Built | `intelligence/posture.py`, `posture_weights.py`, `ciso.py`, `reporting/builder.py` | `test_controls_posture.py`, `test_posture_weights.py`, `test_ciso.py`, `test_dlp_api.py` |
| M11 | Change baseline: snapshot before a change where the tool can export it; drift; posture before / after | Built | `intelligence/config_snapshots.py` | `test_config_snapshots.py` |
| M12 | Compliance packs: SEBI CSCRF, DPDP, CERT-In catalogue mapped to evidence tests; share with current evidence; audit pack; personal-data case → breach assessment; clocks from a person's "reportable"; AI drafts; 180-day log retention per tool | Built (NAM's control list and confirmed deadlines Open) | `reporting/regimes.py`, `reporting/breach.py` | `test_comply_pilot.py` |
| M13 | Pilot scorecard: DLP alerts reaching an analyst vs the week-2 baseline, outages found by users, AI agreement per decision type; QA re-checks apart | Built | `reporting/pilot.py` | `test_comply_pilot.py` |

## 2. Who decides what (CLAUDE.md §0.4.1)

| Requirement | Status | Implementation | Tests |
|---|---|---|---|
| Look-ups chosen by the AI from a fixed menu only (no free-form calls, no URLs) | Built | `investigator.MENU`, names off the menu dropped | `test_dlp_investigator.py::test_the_model_chooses_from_the_menu_and_everything_else_is_dropped` |
| DLP disposition by the AI only once its type is promoted | Built | `core/decisions.py` stages | `test_decisions.py` |
| Forcepoint rule change: AI proposes, engineer approves and makes it | Built | `domains/dlp/tuning.py` | `test_dlp_tuning.py::test_two_leads_an_engineer_and_a_check_that_it_took_effect` |
| Reversible actions at L3 / L4 per type | Built (policy-driven; default L2) | `core/policy.py` | `test_core_governance.py` |
| Containment by people, four-eyes, always | Built (engine-enforced, round 39) | `policy.CONTAINMENT` | `test_core_governance.py::test_containment_stays_with_two_people_whatever_a_policy_document_says` |
| Reportability and notification by a person; the AI drafts | Built | `reporting/breach.py` | `test_comply_pilot.py::test_a_person_decides_reportability_and_the_clocks_start_then` |
| Every figure, score, severity computed in code | Built | posture, coverage, dispose, severity | `test_consistency.py`, `test_ciso.py::test_the_brief_states_only_computed_figures` |

## 3. Guardrails (CLAUDE.md §0.4.2) - each with a test that fails when removed

| Guardrail | Implementation | Test |
|---|---|---|
| Never auto-closed: high / critical, privileged, deception, KEV host, block watch list | `tuning.guard`, `DlpService` never-auto | `test_dlp.py::test_high_severity_and_privileged_senders_are_never_closed_automatically`, `::test_a_person_on_the_block_list_and_a_device_with_a_known_exploited_flaw_are_never_automatic` |
| The AI may escalate alone; close only when the computed disposition agrees | `core/decisions.py` | `test_decisions.py::test_the_ai_may_escalate_alone_but_closes_only_with_the_computed_check_and_off_the_never_list` |
| Insider text fenced; decisions on structured facts; no severity lowered on content | `DlpService._facts`, `_fence`, `_domain` | `test_dlp.py::test_text_the_sender_wrote_never_changes_an_outcome_a_severity_or_a_fact`, `::test_a_model_that_obeys_an_injected_instruction_still_cannot_close_what_the_rules_escalate`, `test_pentest_nam.py::test_text_a_sender_writes_never_becomes_the_destination_fact` |
| Without a valid citation → the computed path | `DlpService.ai_decide` | `test_dlp.py::test_a_decision_without_a_valid_citation_or_outcome_falls_back_to_the_computed_path` |
| Every AI decision stores model, version, prompt version, evidence hash, output, stage | `ai_decisions` | `test_dlp.py::test_the_ai_decision_is_stored_beside_the_computed_one_and_can_be_replayed` |
| Model off / failing / over budget → computed, figures identical | gateway fallbacks | `test_dlp.py::test_with_the_model_off_refused_or_failing_nothing_is_stored_and_the_figures_are_identical`, `test_consistency.py` |
| 1 in 10 AI closures re-checked by a person, permanently | stable-hash QA sample | `test_decisions.py`, `test_comply_pilot.py` (QA re-checks reported apart) |

## 4. The ladder, consistency, compliance wording, phases, residency (CLAUDE.md §0.4.3-8)

| Requirement | Status | Implementation | Tests |
|---|---|---|---|
| Promotion versioned, audited, a second lead; demotion on drift needs nobody; targets set by NAM's SOC lead, no default | Built | `core/decisions.py` | `test_decisions.py::test_promotion_needs_the_sample_the_agreement_and_a_second_lead`, `::test_falling_agreement_demotes_without_a_person`, `::test_a_shift_in_what_the_ai_decides_demotes_even_while_it_agrees` |
| "LLM on / off identical" kept for figures and computed outcomes | Built | - | `test_consistency.py` |
| Never "compliant"; mapping as data validated by NAM; regulatory facts only from the source, with the source named | Built | `reporting/regimes.py` (draft catalogue, sources, "to verify") | `test_comply_pilot.py::test_controls_carry_computed_evidence_and_never_claim_compliance`, `::test_the_draft_catalogue_is_well_formed_and_says_it_is_a_draft` |
| Phase 1-2 connectors at `read` / `recommend`; writes per action in Phase 3 through `ActionService` | Built (stages); SOAR backend Open | connector stages, `ActionService` | `test_connector_admin.py`, `test_core_governance.py` |
| Health and snapshots "wherever the tool reports / exports them" as a capability matrix on screen | Built | `config_snapshots.capable()`, tool health "not reported" | `test_config_snapshots.py::test_only_tools_that_export_their_configuration_are_read_and_the_rest_say_so`, `test_controls_posture.py::test_with_nothing_reported_health_says_so_and_never_invents_a_finding` |
| The model in NAM's environment or an Indian region, or off; pseudonymisation on; raw logs in region | Built (configuration); the region is to decide | `llm/redaction.py`, approved endpoints | `test_resilience_security.py`, `test_go_live_hardening.py` |

## 5. Product scope (CLAUDE.md §0.4a)

| Requirement | Status | Tests |
|---|---|---|
| NAM's tools and modules plus the platform essentials; inherited modules switched off (registry, jobs, routes 404, screens hidden, report sections, engine never loads) | Built | `test_scope.py` (7 tests) |
| A typo in a connector name still caught in the NAM scope | Built | `test_scope.py::test_the_nam_scope_offers_only_nams_tools` |

## 6. Security requirements of the NAM surface (round 39)

| Requirement | Tests |
|---|---|
| Only a lead in person with MFA decides weights, catalogue, pilot figures, reportability, targets, promotions | `test_pentest_nam.py::test_only_a_lead_in_person_with_mfa_decides_what_the_ciso_and_the_regulator_see` |
| Concurrent decisions decided once, one audit event | `test_pentest_nam.py::test_racing_approvals_decide_once_and_leave_one_audit_event` |
| Hostile documents and values refused before storage | `test_pentest_nam.py::test_hostile_documents_and_values_are_refused_before_they_are_stored` |
| A manual run never beside the scheduled job | `test_pentest_nam.py::test_a_manual_run_never_runs_beside_the_scheduled_one` |
| Audit pack only to evidence exporters; cross-domain screens only with all-domain scope | `test_pentest_nam.py::test_the_audit_pack_goes_only_to_those_who_export_evidence`, `::test_domain_scoped_people_get_no_cross_domain_nam_screen` |

## 7. Open, with the reason

| Item | Why open |
|---|---|
| Live connectors for NAM's tools | versions and licensed APIs not yet known (CLAUDE.md §0.5) |
| Arcon, Cloudflare, SIEM and SOAR connectors; M9 | Phase 2-3; products unknown |
| Decide stage | Phase 3; needs the adversarial DLP-content test set and NAM's auditors' answer on named closures |
| NAM's control list, confirmed deadlines | NAM's compliance team |
| Agreement targets, Dome Score weights | NAM's SOC lead and CISO |
| An Indian asset-manager sample estate | not built |
