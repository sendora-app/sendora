// SPDX-License-Identifier: AGPL-3.0-or-later

package store

// securityMailDefaults holds the notification mails for administrator actions
// on a user's account. They only use the shared placeholder names. The links
// are one-time and only ever sent by email, never shown to the administrator.
func securityMailDefaults(event, language string) (string, string, bool) {
	type text struct{ subject, body map[string]string }
	texts := map[string]text{
		"admin_password_reset": {
			subject: map[string]string{
				"en": "An administrator asked you to reset your {{.ApplicationName}} password",
				"nl": "Een beheerder vraagt je je {{.ApplicationName}}-wachtwoord opnieuw in te stellen",
				"de": "Ein Administrator bittet dich, dein {{.ApplicationName}}-Passwort zurückzusetzen",
				"fr": "Un administrateur vous demande de réinitialiser votre mot de passe {{.ApplicationName}}",
				"es": "Un administrador te pide restablecer tu contraseña de {{.ApplicationName}}",
			},
			body: map[string]string{
				"en": "Hi {{.RecipientName}},\n\nAn administrator of {{.ApplicationName}} requested a password reset for your account. Choose a new password here (the link works once and is valid for 1 hour):\n{{.URL}}\n\nYour current password keeps working until you do this. If you did not expect this email, you can ignore it.",
				"nl": "Hallo {{.RecipientName}},\n\nEen beheerder van {{.ApplicationName}} heeft een wachtwoordherstel voor je account aangevraagd. Kies hier een nieuw wachtwoord (de link werkt één keer en is 1 uur geldig):\n{{.URL}}\n\nJe huidige wachtwoord blijft werken tot je dit doet. Als je deze e-mail niet verwachtte, kun je hem negeren.",
				"de": "Hallo {{.RecipientName}},\n\nEin Administrator von {{.ApplicationName}} hat das Zurücksetzen des Passworts für dein Konto angefordert. Wähle hier ein neues Passwort (der Link funktioniert einmal und ist 1 Stunde gültig):\n{{.URL}}\n\nDein aktuelles Passwort funktioniert weiter, bis du das tust. Wenn du diese E-Mail nicht erwartet hast, kannst du sie ignorieren.",
				"fr": "Bonjour {{.RecipientName}},\n\nUn administrateur de {{.ApplicationName}} a demandé la réinitialisation du mot de passe de votre compte. Choisissez un nouveau mot de passe ici (le lien ne fonctionne qu’une fois et reste valable 1 heure) :\n{{.URL}}\n\nVotre mot de passe actuel reste valable tant que vous ne le faites pas. Si vous n’attendiez pas cet e-mail, vous pouvez l’ignorer.",
				"es": "Hola {{.RecipientName}},\n\nUn administrador de {{.ApplicationName}} ha solicitado restablecer la contraseña de tu cuenta. Elige aquí una nueva contraseña (el enlace funciona una vez y es válido durante 1 hora):\n{{.URL}}\n\nTu contraseña actual sigue funcionando hasta que lo hagas. Si no esperabas este correo, puedes ignorarlo.",
			},
		},
		"account_email_changed_notice": {
			subject: map[string]string{
				"en": "The email address of your {{.ApplicationName}} account was changed",
				"nl": "Het e-mailadres van je {{.ApplicationName}}-account is gewijzigd",
				"de": "Die E-Mail-Adresse deines {{.ApplicationName}}-Kontos wurde geändert",
				"fr": "L’adresse e-mail de votre compte {{.ApplicationName}} a été modifiée",
				"es": "Se ha cambiado el correo electrónico de tu cuenta de {{.ApplicationName}}",
			},
			body: map[string]string{
				"en": "Hi {{.RecipientName}},\n\nAn administrator of {{.ApplicationName}} changed the email address of your account (username: {{.Username}}). This address no longer belongs to the account, and you were signed out everywhere.\n\nIf you did not expect this, contact your administrator.",
				"nl": "Hallo {{.RecipientName}},\n\nEen beheerder van {{.ApplicationName}} heeft het e-mailadres van je account (gebruikersnaam: {{.Username}}) gewijzigd. Dit adres hoort niet meer bij het account en je bent overal afgemeld.\n\nAls je dit niet verwachtte, neem dan contact op met je beheerder.",
				"de": "Hallo {{.RecipientName}},\n\nEin Administrator von {{.ApplicationName}} hat die E-Mail-Adresse deines Kontos (Benutzername: {{.Username}}) geändert. Diese Adresse gehört nicht mehr zum Konto, und du wurdest überall abgemeldet.\n\nWenn du das nicht erwartet hast, wende dich an deinen Administrator.",
				"fr": "Bonjour {{.RecipientName}},\n\nUn administrateur de {{.ApplicationName}} a modifié l’adresse e-mail de votre compte (nom d’utilisateur : {{.Username}}). Cette adresse n’appartient plus au compte et vous avez été déconnecté partout.\n\nSi vous ne vous y attendiez pas, contactez votre administrateur.",
				"es": "Hola {{.RecipientName}},\n\nUn administrador de {{.ApplicationName}} ha cambiado el correo electrónico de tu cuenta (usuario: {{.Username}}). Esta dirección ya no pertenece a la cuenta y se ha cerrado tu sesión en todas partes.\n\nSi no esperabas este cambio, contacta con tu administrador.",
			},
		},
		"mfa_reset_requested": {
			subject: map[string]string{
				"en": "Confirm the reset of your two-step verification",
				"nl": "Bevestig het resetten van je tweestapsverificatie",
				"de": "Bestätige das Zurücksetzen deiner Zwei-Schritt-Bestätigung",
				"fr": "Confirmez la réinitialisation de votre validation en deux étapes",
				"es": "Confirma el restablecimiento de tu verificación en dos pasos",
			},
			body: map[string]string{
				"en": "Hi {{.RecipientName}},\n\nAn administrator of {{.ApplicationName}} asked to remove the two-step verification (authenticator app, security keys and recovery codes) from your account. Nothing changes until you confirm. Open this link to confirm (it works once and is valid for 24 hours):\n{{.URL}}\n\nIf you did not ask for this, do not open the link; your account stays protected.",
				"nl": "Hallo {{.RecipientName}},\n\nEen beheerder van {{.ApplicationName}} wil de tweestapsverificatie (authenticator-app, beveiligingssleutels en herstelcodes) van je account verwijderen. Er verandert niets totdat je bevestigt. Open deze link om te bevestigen (hij werkt één keer en is 24 uur geldig):\n{{.URL}}\n\nAls je hier niet om hebt gevraagd, open de link dan niet; je account blijft beschermd.",
				"de": "Hallo {{.RecipientName}},\n\nEin Administrator von {{.ApplicationName}} möchte die Zwei-Schritt-Bestätigung (Authenticator-App, Sicherheitsschlüssel und Wiederherstellungscodes) von deinem Konto entfernen. Es ändert sich nichts, bis du bestätigst. Öffne diesen Link zur Bestätigung (er funktioniert einmal und ist 24 Stunden gültig):\n{{.URL}}\n\nWenn du das nicht angefordert hast, öffne den Link nicht; dein Konto bleibt geschützt.",
				"fr": "Bonjour {{.RecipientName}},\n\nUn administrateur de {{.ApplicationName}} souhaite supprimer la validation en deux étapes (application d’authentification, clés de sécurité et codes de récupération) de votre compte. Rien ne change tant que vous n’avez pas confirmé. Ouvrez ce lien pour confirmer (il ne fonctionne qu’une fois et reste valable 24 heures) :\n{{.URL}}\n\nSi vous n’avez rien demandé, n’ouvrez pas le lien ; votre compte reste protégé.",
				"es": "Hola {{.RecipientName}},\n\nUn administrador de {{.ApplicationName}} ha pedido eliminar la verificación en dos pasos (aplicación de autenticación, llaves de seguridad y códigos de recuperación) de tu cuenta. No cambia nada hasta que confirmes. Abre este enlace para confirmar (funciona una vez y es válido durante 24 horas):\n{{.URL}}\n\nSi no lo has pedido, no abras el enlace; tu cuenta sigue protegida.",
			},
		},
		"mfa_reset_done": {
			subject: map[string]string{
				"en": "Your two-step verification was reset",
				"nl": "Je tweestapsverificatie is gereset",
				"de": "Deine Zwei-Schritt-Bestätigung wurde zurückgesetzt",
				"fr": "Votre validation en deux étapes a été réinitialisée",
				"es": "Tu verificación en dos pasos se ha restablecido",
			},
			body: map[string]string{
				"en": "Hi {{.RecipientName}},\n\nThe two-step verification of your {{.ApplicationName}} account was removed after you confirmed it, and you were signed out everywhere. Sign in again and set up two-step verification again.\n\nIf this was not you, change your password and contact your administrator.",
				"nl": "Hallo {{.RecipientName}},\n\nDe tweestapsverificatie van je {{.ApplicationName}}-account is verwijderd nadat je dit bevestigde, en je bent overal afgemeld. Meld je opnieuw aan en stel tweestapsverificatie opnieuw in.\n\nAls jij dit niet was, wijzig dan je wachtwoord en neem contact op met je beheerder.",
				"de": "Hallo {{.RecipientName}},\n\nDie Zwei-Schritt-Bestätigung deines {{.ApplicationName}}-Kontos wurde nach deiner Bestätigung entfernt, und du wurdest überall abgemeldet. Melde dich erneut an und richte die Zwei-Schritt-Bestätigung neu ein.\n\nWenn du das nicht warst, ändere dein Passwort und wende dich an deinen Administrator.",
				"fr": "Bonjour {{.RecipientName}},\n\nLa validation en deux étapes de votre compte {{.ApplicationName}} a été supprimée après votre confirmation et vous avez été déconnecté partout. Reconnectez-vous et configurez à nouveau la validation en deux étapes.\n\nSi ce n’était pas vous, changez votre mot de passe et contactez votre administrateur.",
				"es": "Hola {{.RecipientName}},\n\nLa verificación en dos pasos de tu cuenta de {{.ApplicationName}} se eliminó tras tu confirmación y se cerró tu sesión en todas partes. Inicia sesión de nuevo y vuelve a configurar la verificación en dos pasos.\n\nSi no fuiste tú, cambia tu contraseña y contacta con tu administrador.",
			},
		},
	}
	t, ok := texts[event]
	if !ok {
		return "", "", false
	}
	if !ValidLanguage(language) {
		language = "en"
	}
	return t.subject[language], t.body[language], true
}
