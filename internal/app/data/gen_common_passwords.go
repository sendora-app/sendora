// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build ignore

// gen_common_passwords writes common-passwords.txt.gz: a curated list of
// genuinely common passwords (lower case, one per line, sorted, unique). It is
// deterministic, so the file can be reproduced and reviewed:
//
//	cd internal/app/data && go run gen_common_passwords.go
//
// The list combines the passwords that top every public breach statistic
// (NCSC "100k most used", the yearly top-200 lists) with the patterns those
// lists are made of: keyboard walks, digit runs, and common words, names and
// teams followed by the digits, years and symbols people append.
package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// base: passwords that appear near the top of public breach lists as they are.
var base = []string{
	"123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111", "1234567", "dragon",
	"123123", "baseball", "abc123", "football", "monkey", "letmein", "shadow", "master", "696969", "mustang",
	"666666", "qwertyuiop", "123321", "1234567890", "pussy", "superman", "654321", "1qaz2wsx", "7777777", "fuckyou",
	"qazwsx", "michael", "jordan", "jennifer", "hunter", "harley", "ranger", "iwantu", "buster", "thomas",
	"tigger", "robert", "soccer", "batman", "test", "pass", "killer", "hockey", "george", "charlie",
	"andrew", "michelle", "love", "sunshine", "jessica", "asshole", "6969", "pepper", "daniel", "access",
	"123456a", "joshua", "maggie", "starwars", "silver", "william", "dallas", "yankees", "hello", "amanda",
	"orange", "biteme", "freedom", "computer", "sexy", "thunder", "nicole", "ginger", "heather", "hammer",
	"summer", "corvette", "taylor", "austin", "1111", "merlin", "matthew", "121212", "golfer", "cheese",
	"princess", "martin", "chelsea", "patrick", "richard", "diamond", "yellow", "bigdog", "secret", "asdfgh",
	"sparky", "cowboy", "camaro", "anthony", "matrix", "falcon", "iloveyou", "bailey", "guitar", "jackson",
	"purple", "scooter", "phoenix", "aaaaaa", "morgan", "tigers", "porsche", "mickey", "maverick", "cookie",
	"nascar", "peanut", "justin", "131313", "money", "horny", "samantha", "panties", "steelers", "joseph",
	"snoopy", "boomer", "whatever", "iceman", "smokey", "gateway", "dakota", "cowboys", "eagles", "chicken",
	"dick", "black", "zxcvbn", "please", "andrea", "ferrari", "knight", "hardcore", "melissa", "compaq",
	"coffee", "booboo", "bitch", "johnny", "bulldog", "xxxxxx", "welcome", "james", "player", "ncc1701",
	"wizard", "scooby", "charles", "junior", "internet", "bigdick", "mike", "brandy", "tennis", "blowjob",
	"banana", "monster", "spider", "lakers", "miller", "rabbit", "enter", "mercedes", "brandon", "steven",
	"fender", "john", "yamaha", "diablo", "chris", "boston", "tiger", "marine", "chicago", "rangers",
	"gandalf", "winter", "bigtits", "barney", "edward", "raiders", "porn", "badboy", "blowme", "spanky",
	"bigdaddy", "johnson", "chester", "london", "midnight", "blue", "fishing", "000000", "hannah", "slayer",
	"11111111", "rachel", "sexsex", "redsox", "thx1138", "asdf", "marlboro", "panther", "zxcvbnm", "arsenal",
	"oliver", "qwerty123", "1q2w3e4r", "1q2w3e", "password1", "password123", "123qwe", "qwe123", "zaq12wsx", "!qaz2wsx",
	"aa123456", "a123456", "1234qwer", "qwer1234", "q1w2e3r4", "q1w2e3r4t5", "1q2w3e4r5t", "1qazxsw2", "123abc", "abc12345",
	"abcd1234", "admin", "admin123", "administrator", "root", "toor", "changeme", "default", "guest", "user",
	"login", "passw0rd", "p@ssw0rd", "p@ssword", "pa55word", "pa$$word", "letmein1", "trustno1", "welcome1", "iloveyou1",
	"monkey1", "dragon1", "master1", "shadow1", "sunshine1", "princess1", "football1", "baseball1", "superman1", "batman1",
	"starwars1", "qwerty1", "abc123456", "123654", "147258369", "159753", "1234561", "123123123", "112233", "123qweasd",
	"1qaz2wsx3edc", "qazwsxedc", "asdfghjkl", "asdfasdf", "zxcvbnm123", "qwertyui", "qwertyu", "azerty", "azertyuiop", "qwertz",
	"qwertzuiop", "ytrewq", "poiuytrewq", "lkjhgfdsa", "mnbvcxz", "q1w2e3", "1q2w3e4r5t6y", "zaq1zaq1", "zaq1xsw2", "!qaz@wsx",
	"987654321", "9876543210", "0987654321", "87654321", "7654321", "1111111", "11111", "111111111", "1111111111", "2222",
	"222222", "22222222", "3333", "333333", "4444", "444444", "5555", "555555", "55555555", "6666",
	"66666666", "7777", "777777", "77777777", "8888", "888888", "88888888", "9999", "999999", "99999999",
	"0000", "00000000", "0000000000", "1212", "12121212", "123123a", "121314", "131415", "102030", "112358",
	"1q1q1q1q", "a1b2c3", "a1b2c3d4", "aaaaaaaa", "abcdef", "abcdefg", "abcdefgh", "abcabc", "aabbcc", "qqqqqq",
	"iloveu", "loveme", "lovely", "lover", "loveyou", "love123", "babygirl", "baby", "angel", "angels",
	"butterfly", "flower", "flowers", "sweety", "sweetheart", "cutie", "beautiful", "pretty", "fuckme", "fuckoff",
	"letmein123", "welcome123", "welcome2024", "hello123", "hello1", "helloworld", "test123", "test1234", "testing", "testtest",
	"demo", "sample", "temp", "temppass", "temp123", "pass123", "pass1234", "passpass", "mypassword", "mypass",
	"secret123", "secret1", "god", "jesus", "jesus1", "christ", "blessed", "faith", "grace", "heaven",
	"liverpool", "manchester", "chelsea1", "barcelona", "realmadrid", "juventus", "ajax", "feyenoord", "psv", "bayern",
	"juventus1", "arsenal1", "liverpool1", "united", "manutd", "celtic", "rangers1", "everton", "tottenham", "milan",
	"pokemon", "minecraft", "fortnite", "roblox", "naruto", "zelda", "mario", "sonic", "pikachu", "batman123",
	"spiderman", "ironman", "hulk", "thor", "captain", "avengers", "matrix1", "starwars123", "darthvader", "yoda",
	"hello12", "qwerty12", "asdf1234", "zxcv1234", "1234abcd", "abcd123", "qweasd", "qweasdzxc", "asdzxc", "zxc123",
	"asd123", "qaz123", "wsx123", "edc123", "1qaz", "2wsx", "3edc", "!qaz", "q2w3e4r5", "w3e4r5t6",
	"computer1", "internet1", "samsung", "apple", "iphone", "android", "google", "facebook", "twitter", "instagram",
	"youtube", "linkedin", "microsoft", "windows", "office", "outlook", "yahoo", "hotmail", "gmail", "skype",
	"sendora", "fileshare", "upload", "download", "files", "share", "sharing", "transfer", "dropbox", "wetransfer",
	"wachtwoord", "welkom", "welkom01", "welkom123", "geheim", "hallo", "hallo123", "voetbal", "zomer", "winter1",
	"passwort", "hallo1", "schatz", "fussball", "geheim1", "willkommen", "motdepasse", "bonjour", "soleil", "doudou",
	"contraseña", "contrasena", "hola", "hola123", "amor", "teamo", "tequiero", "futbol", "123456789a", "qwerty1234",
}

// words: common words, names, pets and teams that people extend with digits.
var words = []string{
	"password", "passw0rd", "p@ssw0rd", "welcome", "welkom", "letmein", "qwerty", "admin", "monkey", "dragon",
	"master", "shadow", "sunshine", "princess", "football", "baseball", "soccer", "hockey", "superman", "batman",
	"iloveyou", "summer", "winter", "spring", "autumn", "january", "december", "michael", "jennifer", "jessica",
	"daniel", "thomas", "charlie", "ashley", "hunter", "tigger", "pepper", "ginger", "buster", "maggie",
	"secret", "freedom", "hello", "computer", "internet", "chocolate", "london", "amsterdam", "berlin", "paris",
	"family", "friends", "flower", "angel", "lovely", "liverpool", "chelsea", "arsenal", "barcelona", "company",
	"sendora", "changeme", "test", "abc", "qwe", "asd", "zxc", "love", "baby", "star",
}

// suffixes people append to a word.
var suffixes = []string{
	"1", "12", "123", "1234", "12345", "123456", "!", "1!", "123!", "01", "11", "13", "69", "99", "00", "007", "@123", "#1",
}

func main() {
	set := map[string]bool{}
	add := func(p string) {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			set[p] = true
		}
	}
	for _, p := range base {
		add(p)
	}
	for _, w := range words {
		add(w)
		for _, s := range suffixes {
			add(w + s)
		}
		for y := 1990; y <= 2030; y++ {
			if y >= 2015 || y%5 == 0 {
				add(w + strconv.Itoa(y))
			}
		}
	}
	// Digit runs and their reverses of every length from 4 to 12.
	digits := "1234567890123"
	for n := 4; n <= 12; n++ {
		add(digits[:n])
		add(reverse(digits[:n]))
	}
	// Keyboard walks, also reversed, doubled and with a trailing digit run.
	walks := []string{"qwerty", "qwertyui", "qwertyuiop", "asdfgh", "asdfghjk", "asdfghjkl", "zxcvbn", "zxcvbnm", "azerty", "qwertz", "1qaz2wsx", "qazwsx", "1q2w3e4r", "q1w2e3r4", "zaq12wsx", "!qaz2wsx"}
	for _, w := range walks {
		add(w)
		add(reverse(w))
		add(w + w)
		add(w + "1")
		add(w + "123")
		add(w + "!")
	}
	// Years and dates people use on their own.
	for y := 1950; y <= 2030; y++ {
		add(strconv.Itoa(y))
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	zw.Write([]byte(strings.Join(out, "\n") + "\n"))
	zw.Close()
	if err := os.WriteFile("common-passwords.txt.gz", buf.Bytes(), 0o644); err != nil {
		panic(err)
	}
	fmt.Println(len(out), "passwords")
}

func reverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}
