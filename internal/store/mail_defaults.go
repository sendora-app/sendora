// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"fmt"

	"github.com/sendora-app/sendora/internal/adapters/sqlite"
)

var MailLanguages = []string{"en", "nl", "de", "fr", "es"}
var MailEvents = []string{"share_created", "share_downloaded", "share_expiring", "password_reset", "verify_email", "reverse_invite", "reverse_completed", "welcome",
	"admin_password_reset", "account_email_changed_notice", "mfa_reset_requested", "mfa_reset_done",
	"password_changed", "mfa_factor_changed", "recovery_codes_regenerated", "new_signin", "password_expiry_warning"}

// OptionalMailEvents were added after the first translation-file format; a file
// without them still imports and keeps the current text of those events.
var OptionalMailEvents = []string{"welcome", "admin_password_reset", "account_email_changed_notice", "mfa_reset_requested", "mfa_reset_done",
	"password_changed", "mfa_factor_changed", "recovery_codes_regenerated", "new_signin", "password_expiry_warning"}

// IsOptionalMailEvent reports whether a translation file may omit the event.
func IsOptionalMailEvent(event string) bool {
	for _, e := range OptionalMailEvents {
		if e == event {
			return true
		}
	}
	return false
}

func ValidLanguage(language string) bool {
	for _, l := range MailLanguages {
		if language == l {
			return true
		}
	}
	return false
}

// MailDefaults uses the same variable names in every language. Existing English
// templates are copied during migration, never overwritten by these defaults.
func MailDefaults(event, language string) (string, string) {
	if event == "welcome" {
		return welcomeMailDefaults(language)
	}
	if subject, body, ok := securityMailDefaults(event, language); ok {
		return subject, body
	}
	if subject, body, ok := accountMailDefaults(event, language); ok {
		return subject, body
	}
	if subject, body, ok := passwordMailDefaults(event, language); ok {
		return subject, body
	}
	if event != "share_downloaded" {
		return legacyMailDefaults(event, language)
	}
	if !ValidLanguage(language) {
		language = "en"
	}
	subjects := map[string]string{
		"en": "A download of your share started",
		"nl": "Een download van je gedeelde bestanden is gestart",
		"de": "Ein Download deiner Freigabe wurde gestartet",
		"fr": "Un téléchargement de votre partage a commencé",
		"es": "Se ha iniciado una descarga de tus archivos",
	}
	bodies := map[string]string{
		"en": "A download of your share \"{{.ShareName}}\" started.\n\nFiles: {{.FileNames}}\nStarted at: {{.StartedAt}}\nDownload count: {{.DownloadCount}}\n\nThis records the start of file serving, not a completed transfer or confirmation that the recipient saved or read the files.",
		"nl": "Een download van je gedeelde bestanden \"{{.ShareName}}\" is gestart.\n\nBestanden: {{.FileNames}}\nGestart op: {{.StartedAt}}\nAantal downloads: {{.DownloadCount}}\n\nDit registreert de start van het aanbieden van bestanden, niet een voltooide overdracht of een bevestiging dat de ontvanger de bestanden heeft opgeslagen of gelezen.",
		"de": "Ein Download deiner Freigabe \"{{.ShareName}}\" wurde gestartet.\n\nDateien: {{.FileNames}}\nGestartet um: {{.StartedAt}}\nDownload-Anzahl: {{.DownloadCount}}\n\nDies erfasst den Beginn der Dateibereitstellung, nicht eine abgeschlossene Übertragung oder eine Bestätigung, dass der Empfänger die Dateien gespeichert oder gelesen hat.",
		"fr": "Un téléchargement de votre partage \"{{.ShareName}}\" a commencé.\n\nFichiers : {{.FileNames}}\nHeure de début : {{.StartedAt}}\nNombre de téléchargements : {{.DownloadCount}}\n\nCela indique le début de l’envoi des fichiers, pas un transfert terminé ni une confirmation que le destinataire a enregistré ou lu les fichiers.",
		"es": "Se ha iniciado una descarga de tus archivos \"{{.ShareName}}\".\n\nArchivos: {{.FileNames}}\nInicio: {{.StartedAt}}\nNúmero de descargas: {{.DownloadCount}}\n\nEsto registra el inicio del envío de archivos, no una transferencia completada ni una confirmación de que el destinatario haya guardado o leído los archivos.",
	}
	return subjects[language], bodies[language]
}

// welcomeMailDefaults is the mail an administrator-created user receives. It
// never contains a password: only the username, the sign-in link and a one-time
// link for choosing their own password.
func welcomeMailDefaults(language string) (string, string) {
	if !ValidLanguage(language) {
		language = "en"
	}
	subjects := map[string]string{
		"en": "Your {{.ApplicationName}} account is ready",
		"nl": "Je {{.ApplicationName}}-account staat klaar",
		"de": "Dein {{.ApplicationName}}-Konto ist bereit",
		"fr": "Votre compte {{.ApplicationName}} est prêt",
		"es": "Tu cuenta de {{.ApplicationName}} está lista",
	}
	bodies := map[string]string{
		"en": "Hi {{.RecipientName}},\n\nAn account was created for you on {{.ApplicationName}}.\n\nUsername: {{.Username}}\nSign in: {{.LoginURL}}\n\nChoose your own password here (the link works once and is valid for {{.ExpiresDays}} days):\n{{.SetPasswordURL}}\n\nIf you did not expect this email, you can ignore it.",
		"nl": "Hallo {{.RecipientName}},\n\nEr is een account voor je aangemaakt op {{.ApplicationName}}.\n\nGebruikersnaam: {{.Username}}\nAanmelden: {{.LoginURL}}\n\nKies hier je eigen wachtwoord (de link werkt één keer en is {{.ExpiresDays}} dagen geldig):\n{{.SetPasswordURL}}\n\nAls je deze e-mail niet verwachtte, kun je hem negeren.",
		"de": "Hallo {{.RecipientName}},\n\nFür dich wurde ein Konto bei {{.ApplicationName}} erstellt.\n\nBenutzername: {{.Username}}\nAnmelden: {{.LoginURL}}\n\nWähle hier dein eigenes Passwort (der Link funktioniert einmal und ist {{.ExpiresDays}} Tage gültig):\n{{.SetPasswordURL}}\n\nWenn du diese E-Mail nicht erwartet hast, kannst du sie ignorieren.",
		"fr": "Bonjour {{.RecipientName}},\n\nUn compte a été créé pour vous sur {{.ApplicationName}}.\n\nNom d’utilisateur : {{.Username}}\nConnexion : {{.LoginURL}}\n\nChoisissez ici votre mot de passe (le lien ne fonctionne qu’une fois et reste valable {{.ExpiresDays}} jours) :\n{{.SetPasswordURL}}\n\nSi vous n’attendiez pas cet e-mail, vous pouvez l’ignorer.",
		"es": "Hola {{.RecipientName}},\n\nSe ha creado una cuenta para ti en {{.ApplicationName}}.\n\nUsuario: {{.Username}}\nIniciar sesión: {{.LoginURL}}\n\nElige aquí tu propia contraseña (el enlace funciona una vez y es válido durante {{.ExpiresDays}} días):\n{{.SetPasswordURL}}\n\nSi no esperabas este correo, puedes ignorarlo.",
	}
	return subjects[language], bodies[language]
}

// TestMailText is the content of the administrator's "send test email" message.
// It is not an editable template event; it follows the recipient's language.
func TestMailText(language string) (string, string) {
	if !ValidLanguage(language) {
		language = "en"
	}
	subjects := map[string]string{
		"en": "Test email",
		"nl": "Test-e-mail",
		"de": "Test-E-Mail",
		"fr": "E-mail de test",
		"es": "Correo de prueba",
	}
	bodies := map[string]string{
		"en": "SMTP works.",
		"nl": "SMTP werkt.",
		"de": "SMTP funktioniert.",
		"fr": "SMTP fonctionne.",
		"es": "SMTP funciona.",
	}
	return subjects[language], bodies[language]
}

// refinedMailDefaults lists wording improvements to built-in defaults. A row is
// only updated while it still holds exactly the previous default, so templates an
// administrator changed are never touched.
var refinedMailDefaults = []struct{ key, previous, current string }{
	{"tpl_share_downloaded_fr",
		"Un téléchargement de votre partage \"{{.ShareName}}\" a commencé.\n\nFichiers : {{.FileNames}}\nDébut : {{.StartedAt}}\nNombre de téléchargements : {{.DownloadCount}}\n\nCela indique le début de l’envoi des fichiers, pas un transfert terminé ni une confirmation que le destinataire a enregistré ou lu les fichiers.",
		"Un téléchargement de votre partage \"{{.ShareName}}\" a commencé.\n\nFichiers : {{.FileNames}}\nHeure de début : {{.StartedAt}}\nNombre de téléchargements : {{.DownloadCount}}\n\nCela indique le début de l’envoi des fichiers, pas un transfert terminé ni une confirmation que le destinataire a enregistré ou lu les fichiers."},
	{"tpl_reverse_completed_es",
		"{{.SenderName}} ha subido archivos para ti: {{.URL}}\n\nArchivos: {{.ShareName}}",
		"{{.SenderName}} ha subido archivos para ti: {{.URL}}\n\nArchivos compartidos: {{.ShareName}}"},
}

func legacyMailDefaults(event, language string) (string, string) {
	subjects := map[string][]string{
		"en": {"{{.SenderName}} shared files with you", "Your share was downloaded", "Share expiring soon", "Password reset", "Verify your email", "{{.SenderName}} invites you to upload files", "Files uploaded to you"},
		"nl": {"{{.SenderName}} heeft bestanden met je gedeeld", "Je gedeelde bestanden zijn gedownload", "Je gedeelde bestanden verlopen binnenkort", "Wachtwoord herstellen", "Verifieer je e-mailadres", "{{.SenderName}} nodigt je uit om bestanden te uploaden", "Bestanden naar je geüpload"},
		"de": {"{{.SenderName}} hat Dateien mit dir geteilt", "Deine Dateien wurden heruntergeladen", "Deine Freigabe läuft bald ab", "Passwort zurücksetzen", "E-Mail-Adresse bestätigen", "{{.SenderName}} lädt dich zum Hochladen ein", "Dateien für dich hochgeladen"},
		"fr": {"{{.SenderName}} a partagé des fichiers avec vous", "Vos fichiers ont été téléchargés", "Votre partage expire bientôt", "Réinitialiser le mot de passe", "Vérifiez votre adresse e-mail", "{{.SenderName}} vous invite à déposer des fichiers", "Des fichiers ont été déposés pour vous"},
		"es": {"{{.SenderName}} ha compartido archivos contigo", "Tus archivos se han descargado", "Tu enlace caduca pronto", "Restablecer contraseña", "Verifica tu correo electrónico", "{{.SenderName}} te invita a subir archivos", "Han subido archivos para ti"},
	}
	bodies := map[string][]string{
		"en": {"Hi {{.RecipientName}},\n\n{{.SenderName}} shared files with you: {{.URL}}\n\n{{.Message}}\n\nExpires: {{.Expires}}", "Your share \"{{.ShareName}}\" was downloaded.", "Your share \"{{.ShareName}}\" expires on {{.Expires}}: {{.URL}}", "Reset your password: {{.URL}}\n\nLink valid for 1 hour.", "Your verification code is {{.Code}}", "Hi {{.RecipientName}},\n\n{{.SenderName}} invites you to upload files: {{.URL}}\n\n{{.Message}}", "{{.SenderName}} uploaded files for you: {{.URL}}\n\nShare: {{.ShareName}}"},
		"nl": {"Hallo {{.RecipientName}},\n\n{{.SenderName}} heeft bestanden met je gedeeld: {{.URL}}\n\n{{.Message}}\n\nVerloopt: {{.Expires}}", "Je gedeelde bestanden \"{{.ShareName}}\" zijn gedownload.", "Je gedeelde bestanden \"{{.ShareName}}\" verlopen op {{.Expires}}: {{.URL}}", "Herstel je wachtwoord: {{.URL}}\n\nDe link is 1 uur geldig.", "Je verificatiecode is {{.Code}}", "Hallo {{.RecipientName}},\n\n{{.SenderName}} nodigt je uit om bestanden te uploaden: {{.URL}}\n\n{{.Message}}", "{{.SenderName}} heeft bestanden naar je geüpload: {{.URL}}\n\nGedeelde bestanden: {{.ShareName}}"},
		"de": {"Hallo {{.RecipientName}},\n\n{{.SenderName}} hat Dateien mit dir geteilt: {{.URL}}\n\n{{.Message}}\n\nAblaufdatum: {{.Expires}}", "Deine Freigabe \"{{.ShareName}}\" wurde heruntergeladen.", "Deine Freigabe \"{{.ShareName}}\" läuft am {{.Expires}} ab: {{.URL}}", "Setze dein Passwort zurück: {{.URL}}\n\nDer Link ist 1 Stunde gültig.", "Dein Bestätigungscode lautet {{.Code}}", "Hallo {{.RecipientName}},\n\n{{.SenderName}} lädt dich zum Hochladen von Dateien ein: {{.URL}}\n\n{{.Message}}", "{{.SenderName}} hat Dateien für dich hochgeladen: {{.URL}}\n\nFreigabe: {{.ShareName}}"},
		"fr": {"Bonjour {{.RecipientName}},\n\n{{.SenderName}} a partagé des fichiers avec vous : {{.URL}}\n\n{{.Message}}\n\nExpiration : {{.Expires}}", "Votre partage \"{{.ShareName}}\" a été téléchargé.", "Votre partage \"{{.ShareName}}\" expire le {{.Expires}} : {{.URL}}", "Réinitialisez votre mot de passe : {{.URL}}\n\nLe lien est valable 1 heure.", "Votre code de vérification est {{.Code}}", "Bonjour {{.RecipientName}},\n\n{{.SenderName}} vous invite à déposer des fichiers : {{.URL}}\n\n{{.Message}}", "{{.SenderName}} a déposé des fichiers pour vous : {{.URL}}\n\nPartage : {{.ShareName}}"},
		"es": {"Hola {{.RecipientName}},\n\n{{.SenderName}} ha compartido archivos contigo: {{.URL}}\n\n{{.Message}}\n\nCaduca: {{.Expires}}", "Tus archivos \"{{.ShareName}}\" se han descargado.", "Tu enlace \"{{.ShareName}}\" caduca el {{.Expires}}: {{.URL}}", "Restablece tu contraseña: {{.URL}}\n\nEl enlace es válido durante 1 hora.", "Tu código de verificación es {{.Code}}", "Hola {{.RecipientName}},\n\n{{.SenderName}} te invita a subir archivos: {{.URL}}\n\n{{.Message}}", "{{.SenderName}} ha subido archivos para ti: {{.URL}}\n\nArchivos compartidos: {{.ShareName}}"},
	}
	if !ValidLanguage(language) {
		language = "en"
	}
	for i, e := range MailEvents {
		if event == e {
			return subjects[language][i], bodies[language][i]
		}
	}
	return "", ""
}

// mailMigrationTx is what the mail localisation steps need from their
// transaction: sqlite.MailMigrationTx, or the in-memory settings table that
// DefaultSeed replays them on.
type mailMigrationTx interface {
	ReplaceIfUnchanged(key, old, value string) error
	ReplaceLegacyDownloadedBody(body, old string) error
	Value(key string) (string, error)
	AddTemplateIfMissing(key, value string) error
}

func (s *Store) migrateMailLocalization() error {
	return sqlite.MigrateMailLocalization(s.DB, s.ColumnCodec(),
		func(tx sqlite.MailMigrationTx) error { return upgradeMailDefaults(tx) },
		func(tx sqlite.MailMigrationTx) error { return seedMailTemplates(tx) })
}

// upgradeMailDefaults upgrades only untouched historical download defaults,
// preserving custom source.
func upgradeMailDefaults(tx mailMigrationTx) error {
	for _, language := range MailLanguages {
		oldSubject, oldBody := legacyMailDefaults("share_downloaded", language)
		subject, body := MailDefaults("share_downloaded", language)
		for _, update := range []struct{ key, old, value string }{
			{"subj_share_downloaded_" + language, oldSubject, subject},
			{"tpl_share_downloaded_" + language, oldBody, body},
		} {
			if err := tx.ReplaceIfUnchanged(update.key, update.old, update.value); err != nil {
				return err
			}
		}
		if language == "en" {
			if err := tx.ReplaceLegacyDownloadedBody(body, oldBody); err != nil {
				return err
			}
		}
	}
	return nil
}

// seedMailTemplates adds the missing template texts of every event and
// language (the refined defaults replace only untouched older texts).
func seedMailTemplates(tx mailMigrationTx) error {
	for _, r := range refinedMailDefaults {
		if err := tx.ReplaceIfUnchanged(r.key, r.previous, r.current); err != nil {
			return err
		}
	}
	for _, event := range MailEvents {
		for _, language := range MailLanguages {
			subject, body := MailDefaults(event, language)
			if language == "en" {
				if old, err := tx.Value("tpl_" + event); err == nil {
					body = old
				}
			}
			for key, value := range map[string]string{"tpl_" + event + "_" + language: body, "subj_" + event + "_" + language: subject} {
				if err := tx.AddTemplateIfMissing(key, value); err != nil {
					return fmt.Errorf("seed email template: %w", err)
				}
			}
			if language == "en" {
				if err := tx.AddTemplateIfMissing("tpl_"+event, body); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
