// SPDX-License-Identifier: AGPL-3.0-or-later

package store

// accountMailDefaults holds the security notifications sent to the owner of an
// account after a change to its sign-in protection or a sign-in from an unknown
// browser or network. They never contain a secret, a link or a full address:
// only the approximate time ({{.Time}}) and the browser family ({{.Browser}}).
func accountMailDefaults(event, language string) (string, string, bool) {
	type text struct{ subject, body map[string]string }
	texts := map[string]text{
		"password_changed": {
			subject: map[string]string{
				"en": "The password of your {{.ApplicationName}} account was changed",
				"nl": "Het wachtwoord van je {{.ApplicationName}}-account is gewijzigd",
				"de": "Das Passwort deines {{.ApplicationName}}-Kontos wurde geändert",
				"fr": "Le mot de passe de votre compte {{.ApplicationName}} a été modifié",
				"es": "Se ha cambiado la contraseña de tu cuenta de {{.ApplicationName}}",
			},
			body: map[string]string{
				"en": "Hi {{.RecipientName}},\n\nThe password of your {{.ApplicationName}} account ({{.Username}}) was changed.\n\nWhen: about {{.Time}}\nBrowser: {{.Browser}}\n\nIf this was you, you do not need to do anything. If this was not you, choose a new password right away with 'Forgot password?' on the sign-in page and contact your administrator.",
				"nl": "Hallo {{.RecipientName}},\n\nHet wachtwoord van je {{.ApplicationName}}-account ({{.Username}}) is gewijzigd.\n\nWanneer: rond {{.Time}}\nBrowser: {{.Browser}}\n\nWas jij dit, dan hoef je niets te doen. Was jij dit niet, kies dan meteen een nieuw wachtwoord via 'Wachtwoord vergeten?' op de aanmeldpagina en neem contact op met je beheerder.",
				"de": "Hallo {{.RecipientName}},\n\nDas Passwort deines {{.ApplicationName}}-Kontos ({{.Username}}) wurde geändert.\n\nWann: etwa {{.Time}}\nBrowser: {{.Browser}}\n\nWenn du das warst, musst du nichts tun. Wenn du das nicht warst, wähle sofort über 'Passwort vergessen?' auf der Anmeldeseite ein neues Passwort und wende dich an deinen Administrator.",
				"fr": "Bonjour {{.RecipientName}},\n\nLe mot de passe de votre compte {{.ApplicationName}} ({{.Username}}) a été modifié.\n\nQuand : vers {{.Time}}\nNavigateur : {{.Browser}}\n\nSi c’était vous, vous n’avez rien à faire. Si ce n’était pas vous, choisissez immédiatement un nouveau mot de passe avec « Mot de passe oublié ? » sur la page de connexion et contactez votre administrateur.",
				"es": "Hola {{.RecipientName}},\n\nSe ha cambiado la contraseña de tu cuenta de {{.ApplicationName}} ({{.Username}}).\n\nCuándo: hacia {{.Time}}\nNavegador: {{.Browser}}\n\nSi fuiste tú, no tienes que hacer nada. Si no fuiste tú, elige enseguida una nueva contraseña con «¿Has olvidado tu contraseña?» en la página de inicio de sesión y contacta con tu administrador.",
			},
		},
		"mfa_factor_changed": {
			subject: map[string]string{
				"en": "The two-step verification of your {{.ApplicationName}} account was changed",
				"nl": "De tweestapsverificatie van je {{.ApplicationName}}-account is gewijzigd",
				"de": "Die Zwei-Schritt-Bestätigung deines {{.ApplicationName}}-Kontos wurde geändert",
				"fr": "La validation en deux étapes de votre compte {{.ApplicationName}} a été modifiée",
				"es": "Se ha cambiado la verificación en dos pasos de tu cuenta de {{.ApplicationName}}",
			},
			body: map[string]string{
				"en": "Hi {{.RecipientName}},\n\nA two-step verification method (authenticator app or security key) was added to or removed from your {{.ApplicationName}} account ({{.Username}}).\n\nWhen: about {{.Time}}\nBrowser: {{.Browser}}\n\nIf this was you, you do not need to do anything. If this was not you, change your password right away, check the two-step verification on your profile and contact your administrator.",
				"nl": "Hallo {{.RecipientName}},\n\nEr is een methode voor tweestapsverificatie (authenticator-app of beveiligingssleutel) toegevoegd aan of verwijderd van je {{.ApplicationName}}-account ({{.Username}}).\n\nWanneer: rond {{.Time}}\nBrowser: {{.Browser}}\n\nWas jij dit, dan hoef je niets te doen. Was jij dit niet, wijzig dan meteen je wachtwoord, controleer de tweestapsverificatie in je profiel en neem contact op met je beheerder.",
				"de": "Hallo {{.RecipientName}},\n\nEine Methode der Zwei-Schritt-Bestätigung (Authenticator-App oder Sicherheitsschlüssel) wurde deinem {{.ApplicationName}}-Konto ({{.Username}}) hinzugefügt oder davon entfernt.\n\nWann: etwa {{.Time}}\nBrowser: {{.Browser}}\n\nWenn du das warst, musst du nichts tun. Wenn du das nicht warst, ändere sofort dein Passwort, prüfe die Zwei-Schritt-Bestätigung in deinem Profil und wende dich an deinen Administrator.",
				"fr": "Bonjour {{.RecipientName}},\n\nUne méthode de validation en deux étapes (application d’authentification ou clé de sécurité) a été ajoutée à votre compte {{.ApplicationName}} ({{.Username}}) ou en a été retirée.\n\nQuand : vers {{.Time}}\nNavigateur : {{.Browser}}\n\nSi c’était vous, vous n’avez rien à faire. Si ce n’était pas vous, changez immédiatement votre mot de passe, vérifiez la validation en deux étapes dans votre profil et contactez votre administrateur.",
				"es": "Hola {{.RecipientName}},\n\nSe ha añadido o eliminado un método de verificación en dos pasos (aplicación de autenticación o llave de seguridad) en tu cuenta de {{.ApplicationName}} ({{.Username}}).\n\nCuándo: hacia {{.Time}}\nNavegador: {{.Browser}}\n\nSi fuiste tú, no tienes que hacer nada. Si no fuiste tú, cambia enseguida tu contraseña, revisa la verificación en dos pasos en tu perfil y contacta con tu administrador.",
			},
		},
		"recovery_codes_regenerated": {
			subject: map[string]string{
				"en": "New recovery codes were created for your {{.ApplicationName}} account",
				"nl": "Er zijn nieuwe herstelcodes gemaakt voor je {{.ApplicationName}}-account",
				"de": "Für dein {{.ApplicationName}}-Konto wurden neue Wiederherstellungscodes erstellt",
				"fr": "De nouveaux codes de récupération ont été créés pour votre compte {{.ApplicationName}}",
				"es": "Se han creado nuevos códigos de recuperación para tu cuenta de {{.ApplicationName}}",
			},
			body: map[string]string{
				"en": "Hi {{.RecipientName}},\n\nNew recovery codes were created for your {{.ApplicationName}} account ({{.Username}}). The previous codes no longer work.\n\nWhen: about {{.Time}}\nBrowser: {{.Browser}}\n\nIf this was you, you do not need to do anything. If this was not you, change your password right away and contact your administrator.",
				"nl": "Hallo {{.RecipientName}},\n\nEr zijn nieuwe herstelcodes gemaakt voor je {{.ApplicationName}}-account ({{.Username}}). De vorige codes werken niet meer.\n\nWanneer: rond {{.Time}}\nBrowser: {{.Browser}}\n\nWas jij dit, dan hoef je niets te doen. Was jij dit niet, wijzig dan meteen je wachtwoord en neem contact op met je beheerder.",
				"de": "Hallo {{.RecipientName}},\n\nFür dein {{.ApplicationName}}-Konto ({{.Username}}) wurden neue Wiederherstellungscodes erstellt. Die bisherigen Codes funktionieren nicht mehr.\n\nWann: etwa {{.Time}}\nBrowser: {{.Browser}}\n\nWenn du das warst, musst du nichts tun. Wenn du das nicht warst, ändere sofort dein Passwort und wende dich an deinen Administrator.",
				"fr": "Bonjour {{.RecipientName}},\n\nDe nouveaux codes de récupération ont été créés pour votre compte {{.ApplicationName}} ({{.Username}}). Les codes précédents ne fonctionnent plus.\n\nQuand : vers {{.Time}}\nNavigateur : {{.Browser}}\n\nSi c’était vous, vous n’avez rien à faire. Si ce n’était pas vous, changez immédiatement votre mot de passe et contactez votre administrateur.",
				"es": "Hola {{.RecipientName}},\n\nSe han creado nuevos códigos de recuperación para tu cuenta de {{.ApplicationName}} ({{.Username}}). Los códigos anteriores ya no funcionan.\n\nCuándo: hacia {{.Time}}\nNavegador: {{.Browser}}\n\nSi fuiste tú, no tienes que hacer nada. Si no fuiste tú, cambia enseguida tu contraseña y contacta con tu administrador.",
			},
		},
		"new_signin": {
			subject: map[string]string{
				"en": "New sign-in to your {{.ApplicationName}} account",
				"nl": "Nieuwe aanmelding bij je {{.ApplicationName}}-account",
				"de": "Neue Anmeldung bei deinem {{.ApplicationName}}-Konto",
				"fr": "Nouvelle connexion à votre compte {{.ApplicationName}}",
				"es": "Nuevo inicio de sesión en tu cuenta de {{.ApplicationName}}",
			},
			body: map[string]string{
				"en": "Hi {{.RecipientName}},\n\nSomeone signed in to your {{.ApplicationName}} account ({{.Username}}) from a browser or network that was not used for this account in the last 30 days.\n\nWhen: about {{.Time}}\nBrowser: {{.Browser}}\n\nIf this was you, you do not need to do anything. If this was not you, change your password right away, set up two-step verification if you have not yet and contact your administrator.",
				"nl": "Hallo {{.RecipientName}},\n\nEr is aangemeld bij je {{.ApplicationName}}-account ({{.Username}}) vanuit een browser of netwerk dat de afgelopen 30 dagen niet voor dit account is gebruikt.\n\nWanneer: rond {{.Time}}\nBrowser: {{.Browser}}\n\nWas jij dit, dan hoef je niets te doen. Was jij dit niet, wijzig dan meteen je wachtwoord, stel tweestapsverificatie in als je dat nog niet hebt gedaan en neem contact op met je beheerder.",
				"de": "Hallo {{.RecipientName}},\n\nJemand hat sich bei deinem {{.ApplicationName}}-Konto ({{.Username}}) aus einem Browser oder Netzwerk angemeldet, das in den letzten 30 Tagen nicht für dieses Konto verwendet wurde.\n\nWann: etwa {{.Time}}\nBrowser: {{.Browser}}\n\nWenn du das warst, musst du nichts tun. Wenn du das nicht warst, ändere sofort dein Passwort, richte die Zwei-Schritt-Bestätigung ein, falls noch nicht geschehen, und wende dich an deinen Administrator.",
				"fr": "Bonjour {{.RecipientName}},\n\nQuelqu’un s’est connecté à votre compte {{.ApplicationName}} ({{.Username}}) depuis un navigateur ou un réseau qui n’a pas été utilisé pour ce compte au cours des 30 derniers jours.\n\nQuand : vers {{.Time}}\nNavigateur : {{.Browser}}\n\nSi c’était vous, vous n’avez rien à faire. Si ce n’était pas vous, changez immédiatement votre mot de passe, activez la validation en deux étapes si ce n’est pas déjà fait et contactez votre administrateur.",
				"es": "Hola {{.RecipientName}},\n\nAlguien ha iniciado sesión en tu cuenta de {{.ApplicationName}} ({{.Username}}) desde un navegador o una red que no se ha usado para esta cuenta en los últimos 30 días.\n\nCuándo: hacia {{.Time}}\nNavegador: {{.Browser}}\n\nSi fuiste tú, no tienes que hacer nada. Si no fuiste tú, cambia enseguida tu contraseña, configura la verificación en dos pasos si aún no lo has hecho y contacta con tu administrador.",
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
