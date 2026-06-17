# How to format a ciphertext

*What's cooler than a crypto bug? A crypto bug that affects OpenSSL, wolfSSL, Bouncy Castle, and GnuPG.*

A few nights ago Thomas Ptacek shared a link to [CVE-2026-34182](https://openssl-library.org/news/vulnerabilities/#CVE-2026-34182) in OpenSSL with the note:

>one-byte tag vulnerability, everyone has to take a drink, that's the rule.

The same bug turned out to be in [wolfSSL](https://github.com/wolfSSL/wolfssl/releases/tag/v5.9.1-stable) (CVE-2026-5500), Bouncy Castle, and GnuPG's S/MIME tool `gpgsm`. Four independent crypto stacks all got it wrong in exactly the same place.

The place is PKCS#7 / CMS parsing, and the bug is almost too dumb to believe. So let me use it as an excuse to talk about something I've been ranting about for years: how to format a ciphertext. It sounds trivial. It is not. Almost everything anyone has ever added to a ciphertext has, sooner or later, led to a vulnerability.

Full disclosure on disclosure: the wolfSSL and OpenSSL bugs were discovered back in the spring, in our collaboration with Anthropic Research. We reported the wolfSSL one because we were already working with wolfSSL on other findings. The OpenSSL one we sat on, because it didn't clear the severity bar we'd set for ourselves. We try [not](https://blog.calif.io/i/199661444/how-we-work) to flood open-source maintainers with medium-severity paperwork. When Thomas linked the OpenSSL CVE, I went back and asked Claude whether anything *else* had the same pattern, and it came back with GnuPG's gpgsm plus Bouncy Castle. We've sent reports to Bouncy Castle and GnuPG, noting that the bugs are considered public, because anyone with a decent LLM can easily discover them now that the OpenSSL and wolfSSL bugs have been disclosed. None of this is critical, but the story behind them is still pretty fun to share.

## The one-byte tag

CMS (the Cryptographic Message Syntax, the descendant of PKCS#7) lets you wrap a message in `AuthEnvelopedData` using an [AEAD](https://developers.google.com/tink/aead) like AES-GCM. AES-GCM produces an authentication tag, normally 16 bytes, and that tag is the only thing standing between you and an attacker who wants to forge or tamper with the message. Verify the tag, the message is authentic. Skip it, you have no integrity at all.

Here's the catch. The CMS format for AES-GCM ([RFC 5084](https://www.rfc-editor.org/rfc/rfc5084)) puts the tag length *inside the message*, as a field the sender controls:

```
GCMParameters ::= SEQUENCE {
  aes-nonce   OCTET STRING,
  aes-ICVlen  AES-GCM-ICVlen DEFAULT 12 }

AES-GCM-ICVlen ::= INTEGER (12 | 13 | 14 | 15 | 16)
```

`aes-ICVlen` is the tag length in bytes, and the structure actually hands an attacker *two* ways to shrink the tag: this parameter, and the length of the outer `mac` OCTET STRING that carries the tag itself. Across these libraries, both fields got trusted.

OpenSSL takes `aes-ICVlen` at face value and passes it to the AEAD as the expected tag length, with no lower bound. Set it to 1 and the receiver compares a single byte. The ASN.1 nominally constrains the value to [12, 16], but DER decoders don't enforce value-range constraints, so the 1 sails straight through.

wolfSSL got there by a different route. It ignores `aes-ICVlen` entirely and uses the length of the `mac` field as the tag length, so you leave the parameter alone and re-encode the `mac` octet string as `04 01 XX`, a one-byte string, and the receiver again checks a single byte.

Either way, a one-byte tag lets an attacker forge a valid message by brute force with probability 1/256 per attempt, which online is no protection at all.

Bouncy Castle manages to be both better and worse. Its GCM engine has a hard floor of 4 bytes, so for AES-GCM the attacker can't get below a four-byte tag. But CMS also allows AES-CCM, which carries the same `aes-ICVlen` field, and Bouncy Castle's CCM engine only validates the tag length on *encrypt*. On decrypt the range check is skipped entirely, and even `aes-ICVlen = 0` is accepted.

GnuPG's `gpgsm` takes the wolfSSL route (the length of the `mac` field becomes the tag length) but gets partially saved one layer down. libgcrypt, the primitive library underneath, rejects GCM tag lengths outside the NIST-approved set. Unfortunately that set goes down to 4 bytes, so the attacker's floor is a four-byte tag rather than a one-byte one, roughly four billion tries per forgery instead of 256. That's a much higher bar, but it's still well short of the 12 bytes the spec calls for, and `gpgsm` accepts it silently.

I did hope the spec would warn against this, but it doesn't. RFC 5084 says only that `aes-ICVlen` "MUST match the size in octets of the value in the AuthEnvelopedData mac field," and that "a length of 12 octets is RECOMMENDED." That is the whole of the guidance, with nothing about the danger of a short tag, no hint that the field is attacker-controlled, and no warning that a one-octet ICV reduces authentication to a single byte.

Thomas's verdict, which I'm stealing for the rest of this post: "it is one of the all-time crypto format misfeatures."

## The real bug is the format

The tag length is a property of the key and the algorithm. It has no business being a tunable knob that travels with the ciphertext, where an adversary can reach it. The moment you let the ciphertext carry that parameter, you've handed the attacker a dial, and someone, in some library, will eventually trust the dial.

This is the pattern I want to convince you of. Every parameter you bake into a ciphertext format is a parameter an attacker can change. The tag length here, the algorithm identifier in JWT: each one is a place where the receiver has to make a decision based on data the sender controls, and each decision is a chance to get pwned.

There's a meta-point worth making. CMS exists for one job, to specify how a cryptographic message is laid out, and it still got this wrong. When the document whose entire purpose is formatting the ciphertext ships a footgun this sharp, that tells you both how hard the problem really is and how much the format is overreaching. A whole RFC of optional parameters, algorithm identifiers, and length fields is an enormous amount of surface for something that, done right, is a key id followed by an opaque blob.

CMS is one example. The other canonical disaster is JWT, which puts a whole pile of parameters in the header: the algorithm, the key id, and sometimes a URL pointing at the key. Every one of those has produced real CVEs: the infamous `alg: none`, the RS256-to-HS256 confusion, and more.

## The most secure format carries nothing

So what's the right answer? In the abstract, the most secure ciphertext format is the one that adds no metadata at all. Just the AEAD output. Nothing for the attacker to flip, because there's nothing there. Everything the receiver needs to decrypt, the key, the algorithm, the tag length, lives in the key record on the receiver's side, not in the ciphertext.

That's clean until you hit a practical wall: how does the receiver know *which* key to use? If you only ever have one key, fine. The moment you rotate keys, or serve multiple tenants, you need to identify the key for a given ciphertext. You could try every key you have and see which one works. That actually works and leaks the least, but it's slow, and it falls apart when you have thousands of tenants with thousands of keys.

So in practice you need some kind of key id. The least problematic format I know of is simply:

```
key_id || ciphertext
```

The `key_id` should be sufficient to look up the raw key material *and every other parameter required for decryption*. The ciphertext itself carries nothing else. All metadata, algorithm, tag length, everything, is derived from the key record the `key_id` points to. The tag-length bug literally cannot exist in this design, because the tag length comes from your key record, not from the wire.

Worth being honest about the cost: a key id breaks semantic security, because it makes ciphertexts distinguishable from random. Usually that's fine. Sometimes it isn't. If you use a distinct key id per user, the key id becomes a user identifier, and leaking it can leak who a message belongs to. In a privacy-sensitive setting that can matter a lot. Know which regime you're in before you pick.

## Even key_id || ciphertext can go wrong

When I told Thomas that `key_id || ciphertext` is the least bad option, he immediately asked:

>Shouldn't the key id go in the associated data? Bind it with the AEAD's AAD so it can't be tampered with?

It doesn't help, and the reason is worth internalizing. AEAD authentication is always *relative to a key*: verifying the tag proves only that whoever produced the ciphertext held the key you decrypted with. It says nothing about whether that key was the *right* one. The dangerous step happens before any of that, at the lookup: the receiver reads `key_id`, fetches whatever key it names, and only then checks the tag. Binding `key_id` into the AAD doesn't change that order. If an attacker can make `key_id` resolve to a key *they* control, they simply encrypt under that key with that same `key_id` as AAD, and everything verifies. You've authenticated the message, correctly, under the wrong key.

This is exactly one of the attacks I found in AWS KMS years ago ([advisory here](https://vnhacker.substack.com/p/advisory-security-issues-in-aws-kms-and)). AWS KMS used a *global* key id namespace: a key id specified a globally unique key, including keys belonging to other accounts. So I could take a ciphertext encrypted under *my* key, keep my key id on it, and hand it to your application. Your application reads the key id, asks AWS KMS to decrypt, AWS KMS happily uses my key because the id resolves globally, and suddenly your application is accepting plaintext that I chose. Putting the key id in the AAD changes nothing, because my ciphertext is perfectly valid under my key.

I've seen a JWT implementation that accepted a *URL* as the key id and then fetched the key from that URL. Attacker-controlled key location, fetched server-side, is a textbook SSRF. Worse, point that URL at a server you control and the application fetches *your* key, which is the key-substitution attack from above all over again. So please: never use a URL as a key id. The key id should be an opaque local handle, nothing more.

I'll add one more data point, because it convinced me this isn't niche knowledge that everyone already has. After AWS KMS, I found the identical global-key-id bug in the standard crypto library at a major tech company, one that employed some of the best security engineers and cryptographers in the world. If they missed it, it's not well known enough.

## How to actually do it

The fix for the lookup problem depends on whether you're multi-tenant.

If you're **not** multi-tenant, use a *local* key id. This is what we did in [Google Tink](https://developers.google.com/tink/design/keys), copying a design from the internal Keymaster library. Disclosure: I was one of Tink's original maintainers, so weigh my enthusiasm for it accordingly. The key idea, and it's the whole point of this post, is that a Tink key contains not just the key material but *everything needed for the primitive to work*: the algorithm, the parameters, the tag length, all of it. The id is just a small local integer that indexes into your own keyset. It means nothing outside your application. An attacker can change it, but they can only ever make it point at one of *your* keys, which buys them nothing.

If you **are** multi-tenant, things get sharp very fast, because now the id space is inherently shared, and a naive global id walks you straight back into the AWS KMS attack. The better approach, I think, is to keep the global namespace out of the ciphertext entirely. Let each tenant create named keysets, the way S3 lets you create named buckets, and have the application reference the keyset by name in its own code or config. The names can be randomized to avoid collisions. The wire format then carries only a *local* key id, scoped to whichever keyset the application already selected. Because that keyset is chosen by trusted code rather than by attacker-controlled bytes, a local id can only ever resolve to a key inside the intended keyset, so the cross-tenant substitution has nowhere to land. You do still pay the aforementioned small semantic security and privacy cost.

As far as I can tell, AWS KMS didn't go that way. It keeps a global key id on the wire and protects it by encrypting that id under another master key. That works, but it is solving a crypto problem with more crypto, at the cost of an extra encryption on every operation and some ciphertext expansion. The wrapping key has to be a single, fixed, global key. And now you have a master key to rotate, which is its own headache, whereas naming the keyset out of band keeps the global id off the wire in the first place.

## Takeaways

The one-byte tag bug is the same lesson over and over: the ciphertext format is the attack surface. Every parameter you let a ciphertext carry is a parameter an attacker gets to choose, and the history of AWS KMS, CMS, and JWT is a long record of attackers choosing wisely.

As Lea Kissner put it:

>Cryptography is a tool for turning a whole swathe of problems into key management problems.

So build your keys so they carry their own parameters, keep your ciphertexts as close to "opaque blob plus a local key handle" as you can, and treat every field you're tempted to add to the wire format as a future risk until proven otherwise. It usually is.

That principle reaches past wire formats and into APIs. Years ago Thomas wrote that [if you're typing the letters A-E-S into your code, you're doing it wrong](https://people.eecs.berkeley.edu/~daw/teaching/cs261-f12/misc/if.html), the point being that a good crypto API doesn't make you hand-pick the primitive. The tag length is the same kind of choice: if you're typing it in at all, it's time to switch to [a better API](https://developers.google.com/tink/).

*Thanks to Thomas Ptacek for the conversation that prompted this, and for inspiring me to work on crypto in the first place.*