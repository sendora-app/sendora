# Custom translations (examples)

Ready-to-import language files for **Admin → Languages** (interface) and
**Admin → Email templates** (mail). Nothing here is bundled in the app: import a
file to add or replace a language at runtime, without rebuilding.

| Folder | Language | Interface (`sendora-ui-<code>.json`) | Email (`sendora-email-<code>.json`) |
|---|---|---|---|
| `de/` | Deutsch (alternative to the built-in German, which is complete since 0.2.0) | all texts | built in |
| `fr/` | Français (alternative to the built-in French, which is complete since 0.2.0) | all texts | built in |
| `es/` | Español (alternative to the built-in Spanish, which is complete since 0.2.0) | all texts | built in |
| `it/` | Italiano | all texts | all 8 events |
| `pt-br/` | Português (Brasil) | all texts | all 8 events |
| `pl/` | Polski | all texts | all 8 events |
| `ja/` | 日本語 (Japanese) | all texts | all 8 events |
| `fy/` | Frysk (West Frisian) | all texts | all 8 events |
| `eo/` | Esperanto | all texts | all 8 events |
| `en-pirate/` | Pirate English (just for fun) | all texts | all 8 events |
| `tlh/` | tlhIngan Hol (Klingon, just for fun) | all texts | all 8 events |

Importing `de`, `fr` or `es` stores overrides for the built-in language: every text becomes translated instead of falling back to English. A test checks that every file here only uses known texts and keeps all placeholders.

## Import

- **Interface:** Admin → Languages → *Add a language* → *Import JSON* (or *Import JSON* on an existing row).
- **Email:** Admin → Email templates → select the language → *Upload translation JSON*, review, then *Confirm import*.

## File formats

Interface file:

```json
{ "code": "ja", "name": "日本語", "translations": { "English text": "translated text" } }
```

The English text is the key. Keep placeholders such as `{n}`, `{year}`, `%s` unchanged. Unknown keys are rejected; missing keys fall back to English.

Email file: `format` `sendora-email-templates`, `version` `1`, `language`, `name`, and a `templates` object with a `subject` and `body` per event. Keep `{{.Variable}}` placeholders unchanged.

## Make your own language

Download the current file of a language from the admin screens, translate the values (never the keys, event names or placeholders), change `code` and `name`, and import it.

## Note

These translations are machine-assisted (Klingon and Pirate English are playful examples) and have not been reviewed by native speakers. Review them before production use. They contain no personal or deployment-specific data and are released under the project's license.
