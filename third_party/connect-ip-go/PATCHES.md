# connect-ip-go compatibility snapshot

This directory is based on `Diniboy1123/connect-ip-go` commit `66cba32d7d33e0fb3ba9d1cdaac664379271a54b`, which usque needs for Cloudflare WARP-specific HTTP/2, non-RFC CONNECT-IP behavior, and the zero-copy packet APIs.

`conn.go` carries the quic-go v0.61+ capsule-parser migration: the removed one-shot `http3.ParseCapsule` call is replaced with the stateful `http3.NewCapsuleParser(...).Next()` API. The compatible source blob comes from `confeden/Nova-Android`, which independently maintained the same Cloudflare fork and already made this migration; its only additional change in that file is factoring the existing datagram composition logic into an exported helper without changing the path used by usque.

The root module keeps the original fork pseudo-version in `require` as provenance and uses a local `replace` so the compatibility patch is reproducible. Remove this snapshot when the Cloudflare-specific upstream fork itself supports the selected quic-go line.
