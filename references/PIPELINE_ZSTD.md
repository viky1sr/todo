# Zstandard pipeline and compressed-byte segmentation

## Pipeline variants and comparability

| Mode | Compression semantics | AEAD semantics | Thesis use |
|---|---|---|---|
| `single-frame-sequential` | one Zstd frame, stable level/dictionary | one message/tag, serial POLYVAL | baseline primary |
| `single-frame-parallel` | **identical** compressed bytes vs sequential | one message/tag, parallel POLYVAL | primary experiment |
| `independent-frames` | split original input into independent Zstd frames | one message/tag unless explicitly otherwise | compression penalty comparison |
| `segment-aead` | any encoder scheme | many messages/nonces/tags | different architecture; not equivalent |
| `producer-consumer` | one stateful frame across bounded compressed buffers | one tag after all compressed bytes are authenticated | memory/latency engineering |

Zstandard allows concatenated frames, but distinct frames reset compression history. Separating compressed-byte work segments **after a single stateful encoder** does not require a new frame for each segment. Keep frame_count and POLYVAL_segment_count distinct in metadata.

## Last known observation from user log (not independently re-benchmarked)

- Original input: 4,194,304 B.
- Independent frames: 32 frames @128 KiB of original data, compressed 3,936 B.
- Single frame: compressed 496 B.
- POLYVAL segmented by 65,536 B => **one** segment (because compressed length < chunk threshold).
- Compression time 2,666 us, encryption 19 us, decryption+decompression 2,365 us.
- Reported one-message tag matched seq/par/upstream and lossless roundtrip succeeded. These do **not** demonstrate multi-segment pipeline speedup.

## Correct producer-consumer-stateful design

```text
source -> single Zstd Encoder -> bounded compressed buffers -> carry-16B + POLYVAL blocks
                                |                                  |
                                +---- secure compressed spool -----+-- ordered reduction
                                                                  -> RFC 8452 tag
                                                    spool rewind -> AES-CTR -> ciphertext||tag
```

- Use bounded queue `max_queued_bytes`, capped spool size, and backpressure metrics; no unbounded Vec or tokio mpsc with unlimited memory.
- A single message tag requires all compressed plaintext bytes to be known before CTR encryption. Do not label compressed internal output as client-visible encrypted output.
- Preserve bytes identically between seq/par modes; pin compression level, checksum mode, content size flag, frame format, dictionary and streaming flush behavior.
- Keep `segment_bytes` independent from `frame_bytes`; chunk on 16B boundaries in authenticator. If last chunk partial, pad **once** at end of actual compressed plaintext, then append one length block.
- Decoder must accept the chosen frame sequence; don't trust decompressed content size header alone; enforce output limit, compression ratio threshold by policy, CPU/time budget where possible.
- On tag failure, delete unsafe spool/temp artifacts, do not deliver decompressed content.

## Performance cautions

- For highly compressible data, authentication input shrinks drastically; try incompressible and mixed-entropy workloads.
- For 3,936 compressed bytes, segmentation 64 KiB yields one segment. To test parallelism, create samples whose **compressed output** exceeds two or more segment thresholds.
- Compress once to frozen compressed byte fixtures for crypto-only fairness. Separately benchmark Zstd's effect on total throughput.
- First output latency: `t_compressed_internal`, `t_tag_ready`, `t_first_ciphertext_written`, `t_first_http_byte` are different clocks.
- Counterintuitive results (e.g., frame penalty for repetitive data) belong in thesis, not as bugs to hide.

Official technical specs: RFC 8878 (Zstandard), https://www.rfc-editor.org/rfc/rfc8878 ; Zstd frame format https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md .
