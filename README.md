## Usage

```shell
jwt-verify on  main [?] via 🐹 v1.22.1 on ☁️  (us-west-1) took 16s
❯ go run main.go -j https://example.com/.well-known/jwks/default.json
Paste your JWT, then press Enter:
eyJhbGciOiJ<snip>jDAw
🔓 Decoded JWT Claims:
{
  "aud": [
    "openchami"
  ],
  "exp": 1728604922,
  "groups": [
    "admins"
  ],
  "iat": 1728568922,
  "iss": "default",
  "jti": "dd3d7b43-11d1-4bb2-865e-b1e3b7ba4bd5",
  "nbf": 1728568922,
  "roles": [
    "admin"
  ],
  "sub": "admin@openchami.org"
}
⏳ Expiration: 2024-10-10 20:02:02 -0400 EDT (in 9h49m58.123466s)
✅ Issued At: 2024-10-10 10:02:02 -0400 EDT (since: 10m1.876728s)
✅ Not Before: 2024-10-10 10:02:02 -0400 EDT (since: 10m1.876737s)
✅ JWT signature is valid!
```
