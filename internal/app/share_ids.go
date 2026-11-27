// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sendora-app/sendora/internal/ports"
)

const (
	shareIDNumberMin     = 1000000
	shareIDNumberChoices = 9000000
	shareIDClaimAttempts = 16
)

// Original, hand-curated neutral English words; no external dictionary is used.
// With at least 256 choices, five independent words and two independent numbers
// provide at least 5*log2(256) + 2*log2(9000000) = 86.20 bits of entropy.
var shareIDWords = strings.Fields(`
acorn alder almond amber anchor apple apron arch arrow ash atlas autumn avocado azalea bamboo banana
basket beach bean beech beetle bell berry birch bird biscuit blanket blossom blueberry board boat book
bottle bowl branch bread breeze brick bridge brook brush bucket button cabin cactus cake camel candle
canvas canyon carrot castle cedar celery chair cherry chest chick clay cliff clock cloud clover coast
cocoa coconut comet compass coral cork corn cotton cove crane creek cricket crown crystal cube cucumber
daisy dawn deer desk diamond dolphin dove dragonfly drift drum dune eagle earth elm feather fern field
fig finch fir flannel flax flower flute foam forest fork fountain fox frame frost garden garlic gate
gazelle ginger glass globe glove goat grain grape grass gravel grove guitar harbor hare harp hazel heron
hill honey horse iceberg iris island ivy jacket jar jasmine jelly jewel jug juniper kettle key kiwi
kite kitten lake lamb lantern lark leaf lemon lentil leopard lettuce lilac lime linen lion loaf lotus
maple marble meadow melon mint mirror mitten moon moss moth mountain mug mushroom napkin nectarine nest
nettle nut oak oat ocean olive onion orange orchid otter owl paddle palm panda paper peach pear pebble
pelican pencil pepper petal piano pigeon pillow pine plank plate plum pocket pond poplar potato prism pumpkin
quartz quilt rabbit radish rain rainbow raven reed reef ribbon rice ridge river robin rock root rose
rosemary rowboat sail sand scarf seal seed shell shore silk slate snail snow soap sparrow spoon spring spruce
squash squirrel star stone stream string summit sunflower swan table tangerine teal thyme tiger tile timber toast
tomato towel trail tree trout tulip turtle valley vase velvet violet walnut waterfall wave wax wheat wheel willow
window wing winter wood wool wren yarn zebra zipper zucchini apricot badger bluebell butter cup daffodil fabric bike stair
`)

func newShareID() (string, error) { return generateShareID(rand.Reader) }

// A reader parameter makes entropy failures and rejection sampling testable
// without changing the randomness used by concurrent requests or other secrets.
func generateShareID(entropy io.Reader) (string, error) {
	segments := make([]string, 7)
	for i := range segments {
		choices := len(shareIDWords)
		if i == 3 || i == 5 {
			choices = shareIDNumberChoices
		}
		// crypto/rand.Int uses rejection sampling, not a biased modulo reduction.
		n, err := rand.Int(entropy, big.NewInt(int64(choices)))
		if err != nil {
			return "", fmt.Errorf("share ID entropy unavailable: %w", err)
		}
		if i == 3 || i == 5 {
			segments[i] = strconv.Itoa(shareIDNumberMin + int(n.Int64()))
		} else {
			segments[i] = shareIDWords[n.Int64()]
		}
	}
	return strings.Join(segments, "-"), nil
}

// Claim before staging and before opening the completion transaction: the store
// may have only one DB connection. The unique DB constraint remains a backstop.
// Success transfers ownership of this newly created directory to the caller;
// errors never remove or modify any pre-existing path or database row.
func claimShareDir(shares ports.ShareRepository, root string, generate func() (string, error)) (string, string, error) {
	for attempt := 0; attempt < shareIDClaimAttempts; attempt++ {
		id, err := generate()
		if err != nil {
			return "", "", err
		}
		exists, err := shares.LongIDExists(context.Background(), id)
		if err != nil {
			return "", "", fmt.Errorf("share ID lookup failed: %w", err)
		}
		if exists {
			continue
		}
		dest := filepath.Join(root, id)
		if err := os.Mkdir(dest, 0o700); err != nil {
			if os.IsExist(err) {
				continue
			}
			return "", "", fmt.Errorf("share directory claim failed: %w", err)
		}
		return id, dest, nil
	}
	return "", "", fmt.Errorf("share ID collision retry limit reached")
}
