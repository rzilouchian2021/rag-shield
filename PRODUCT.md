# Product

## Register

product

## Users

Primarily a Cyber Risk Modeling class and its instructor. They watch a group presentation (24 November 2026) where the dashboard is driven live on a projector. Most viewers have not seen RAG poisoning before and are reading the screen from across a classroom, often on a washed-out projector at around 1280×720 to 1920×1080. Secondary users are the group members themselves, who use it on laptops to rehearse, run drills, and confirm evaluation verdicts.

Within the fiction, the assistant serves field technicians at an invented compressor station ("Station 41"). That framing shapes the content, but the real audience is the classroom.

## Product Purpose

A local simulation showing that an AI assistant can be misled by a poisoned document, and that a defensive layer (RAG Shield) measurably reduces that risk. The comparison is between Baseline RAG and RAG Shield on the same documents, questions, and model. Success means the class understands, within a few minutes of live demo, what the attack does, what the Shield changes, what the measured results are, and where the Shield still fails. Every number shown must be a real measured result, never decoration.

## Brand Personality

Calm, precise, evidence-first. It should feel like a credible security console that a consultant would show a client: quiet confidence, plain language, and honest about limits. The data and the before/after contrast carry the drama, not the styling.

## Anti-references

- Hacker or cyber aesthetics: neon on black, matrix green, glitch effects, skulls and padlocks.
- SaaS marketing dashboards: hero metrics with gradient accents, vanity KPIs, celebratory confetti.
- The default untouched Streamlit demo look, where everything is the same weight and nothing guides the eye.
- Alarmist red-everywhere security dashboards that make every state look like an emergency.

## Design Principles

1. **Readable from the back of the room.** Text, numbers, and contrasts must survive a projector. If a key fact can't be read at a distance, it isn't shown.
2. **Show the contrast, then the evidence.** Baseline vs Shield is the story; put that comparison first and let detail sit one click deeper.
3. **Honest by construction.** Show limitations and failures with the same clarity as successes. Measured, not marketed.
4. **Earned familiarity.** Standard controls and predictable layout so the presenter never fumbles live.
5. **Severity means something.** Reserve warning and danger styling for real security events, so they register when they appear.

## Accessibility & Inclusion

- Target WCAG 2.2 AA, with extra margin for projector legibility: body text effectively 16px or larger, key figures much larger, contrast well above 4.5:1 where possible.
- Color-blind safe. Never rely on red versus green alone, especially for Baseline versus Shield or success versus failure; pair color with text, labels, or shape.
- Keyboard operable for the presenter. Respect reduced-motion preferences.
