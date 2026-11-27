// SPDX-License-Identifier: AGPL-3.0-or-later

package store

// passwordMailDefaults holds the reminder sent to the owner of an account whose
// password reaches its maximum age (account_password_max_age_days) within a
// week. It contains a link to the profile page, never a secret or a token.
func passwordMailDefaults(event, language string) (string, string, bool) {
	if event != "password_expiry_warning" {
		return "", "", false
	}
	subjects := map[string]string{
		"en": "Your {{.ApplicationName}} password expires in {{.ExpiresDays}} days",
		"nl": "Je {{.ApplicationName}}-wachtwoord verloopt over {{.ExpiresDays}} dagen",
		"de": "Dein {{.ApplicationName}}-Passwort läuft in {{.ExpiresDays}} Tagen ab",
		"fr": "Votre mot de passe {{.ApplicationName}} expire dans {{.ExpiresDays}} jours",
		"es": "Tu contraseña de {{.ApplicationName}} caduca dentro de {{.ExpiresDays}} días",
	}
	bodies := map[string]string{
		"en": "Hi {{.RecipientName}},\n\nThe password of your {{.ApplicationName}} account ({{.Username}}) expires in {{.ExpiresDays}} days, on {{.Expires}}. After that you must choose a new password before you can continue.\n\nChange it now on your profile page:\n{{.URL}}\n\nYou only get this reminder once for this password.",
		"nl": "Hallo {{.RecipientName}},\n\nHet wachtwoord van je {{.ApplicationName}}-account ({{.Username}}) verloopt over {{.ExpiresDays}} dagen, op {{.Expires}}. Daarna moet je eerst een nieuw wachtwoord kiezen voordat je verder kunt.\n\nWijzig het nu op je profielpagina:\n{{.URL}}\n\nJe krijgt deze herinnering maar één keer voor dit wachtwoord.",
		"de": "Hallo {{.RecipientName}},\n\nDas Passwort deines {{.ApplicationName}}-Kontos ({{.Username}}) läuft in {{.ExpiresDays}} Tagen ab, am {{.Expires}}. Danach musst du zuerst ein neues Passwort wählen, bevor du weitermachen kannst.\n\nÄndere es jetzt auf deiner Profilseite:\n{{.URL}}\n\nDu erhältst diese Erinnerung für dieses Passwort nur einmal.",
		"fr": "Bonjour {{.RecipientName}},\n\nLe mot de passe de votre compte {{.ApplicationName}} ({{.Username}}) expire dans {{.ExpiresDays}} jours, le {{.Expires}}. Ensuite, vous devrez choisir un nouveau mot de passe avant de pouvoir continuer.\n\nModifiez-le dès maintenant sur votre page de profil :\n{{.URL}}\n\nVous ne recevez ce rappel qu’une seule fois pour ce mot de passe.",
		"es": "Hola {{.RecipientName}},\n\nLa contraseña de tu cuenta de {{.ApplicationName}} ({{.Username}}) caduca dentro de {{.ExpiresDays}} días, el {{.Expires}}. Después tendrás que elegir una nueva contraseña antes de poder continuar.\n\nCámbiala ahora en tu página de perfil:\n{{.URL}}\n\nSolo recibirás este recordatorio una vez para esta contraseña.",
	}
	if !ValidLanguage(language) {
		language = "en"
	}
	return subjects[language], bodies[language], true
}
