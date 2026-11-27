// SPDX-License-Identifier: AGPL-3.0-or-later

import { tr } from './i18n/mark.mjs'
import forestDawn from './assets/forest-dawn.svg?no-inline'
import koenigssee from './assets/backgrounds/koenigssee.jpg?no-inline'
import medicineBow from './assets/backgrounds/medicine-bow.jpg?no-inline'
import hakkoda from './assets/backgrounds/hakkoda.jpg?no-inline'
import northernLights from './assets/backgrounds/northern-lights.jpg?no-inline'
import starryFjord from './assets/backgrounds/starry-fjord.jpg?no-inline'

// Bundled backgrounds. Ids must match bundledBackgroundIDs in internal/app/branding_background.go.
// Photo credits and licences are listed in assets/backgrounds/CREDITS.md.
export const bundledBackgrounds = [
  { id: 'koenigssee', name: tr('Misty lake'), url: koenigssee, credit: 'Mataksim (CC0)' },
  { id: 'medicine-bow', name: tr('Mountain lake'), url: medicineBow, credit: 'Colby Thomas (CC0)' },
  { id: 'hakkoda', name: tr('Autumn reflection'), url: hakkoda, credit: 'lumoplank (CC0)' },
  { id: 'northern-lights', name: tr('Northern lights'), url: northernLights, credit: 'Sebastian Kowalski (CC0)' },
  { id: 'starry-fjord', name: tr('Starry fjord'), url: starryFjord, credit: 'W.carter (CC0)' },
  { id: 'forest-dawn', name: tr('Forest illustration'), url: forestDawn, credit: 'Sendora (MIT)' },
]

// id → image URL, or '' for "none" / unknown ids.
export function bundledUrl(id) { return bundledBackgrounds.find(b => b.id === id)?.url || '' }
