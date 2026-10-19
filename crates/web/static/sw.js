/**
 * IPFS Trustless Verified-Fetch Service Worker powered by WebAssembly.
 * Intercepts /ipfs/<cid> and /api/v1/ipfs/sw/<cid> requests,
 * fetches raw blocks (?format=raw) from trustless IPFS gateways,
 * verifies SHA2-256 multihashes via WASM, and returns verified responses.
 */

const SW_VERSION = "todo-sw-v1.0.0";
const WASM_URL = "/static/wasm/todo_wasm.wasm";

// Configurable gateway list (primary + fallbacks)
let trustlessGateways = [
  "http://127.0.0.1:8080/ipfs/",
  "https://trustless-gateway.link/ipfs/",
  "https://ipfs.io/ipfs/",
  "https://dweb.link/ipfs/",
  "https://cloudflare-ipfs.com/ipfs/"
];

let wasmInstance = null;
let wasmInitPromise = null;

async function getWasm() {
  if (wasmInstance) return wasmInstance;
  if (!wasmInitPromise) {
    wasmInitPromise = (async () => {
      try {
        let response = await fetch(WASM_URL);
        let wasmModule;
        if (typeof WebAssembly.instantiateStreaming === "function") {
          try {
            wasmModule = await WebAssembly.instantiateStreaming(response);
          } catch (_) {
            const buf = await (await fetch(WASM_URL)).arrayBuffer();
            wasmModule = await WebAssembly.instantiate(buf);
          }
        } else {
          const buf = await response.arrayBuffer();
          wasmModule = await WebAssembly.instantiate(buf);
        }
        wasmInstance = wasmModule.instance.exports;
        return wasmInstance;
      } catch (err) {
        console.error("[SW-WASM] Failed to initialize WASM module:", err);
        wasmInitPromise = null;
        throw err;
      }
    })();
  }
  return wasmInitPromise;
}

/**
 * Verify raw block bytes against a CID string using WASM.
 * @param {Uint8Array} rawBytes
 * @param {string} cidStr
 * @returns {Promise<boolean>}
 */
async function wasmVerifyBlock(rawBytes, cidStr) {
  const wasm = await getWasm();
  const encoder = new TextEncoder();
  const cidBytes = encoder.encode(cidStr.trim());

  const dataPtr = wasm.todo_wasm_alloc(rawBytes.length);
  const cidPtr = wasm.todo_wasm_alloc(cidBytes.length);

  try {
    new Uint8Array(wasm.memory.buffer).set(rawBytes, dataPtr);
    new Uint8Array(wasm.memory.buffer).set(cidBytes, cidPtr);

    const result = wasm.todo_wasm_verify_block(dataPtr, rawBytes.length, cidPtr, cidBytes.length);
    return result === 1;
  } finally {
    wasm.todo_wasm_free(dataPtr, rawBytes.length);
    wasm.todo_wasm_free(cidPtr, cidBytes.length);
  }
}

/**
 * Parse DAG-JSON manifest bytes using WASM.
 * @param {Uint8Array} manifestBytes
 * @returns {Promise<Object>}
 */
async function wasmParseManifest(manifestBytes) {
  const wasm = await getWasm();
  const dataPtr = wasm.todo_wasm_alloc(manifestBytes.length);

  // Allocate pointer buffers for output (2 * 4 bytes for 32-bit WASM pointers/sizes)
  const ptrBuf = wasm.todo_wasm_alloc(8);
  const lenBuf = wasm.todo_wasm_alloc(8);

  try {
    new Uint8Array(wasm.memory.buffer).set(manifestBytes, dataPtr);
    const status = wasm.todo_wasm_parse_manifest(dataPtr, manifestBytes.length, ptrBuf, lenBuf);
    if (status < 0) {
      throw new Error(`Invalid DAG-JSON manifest (status code ${status})`);
    }

    const view = new DataView(wasm.memory.buffer);
    const outPtr = view.getUint32(ptrBuf, true);
    const outLen = view.getUint32(lenBuf, true);

    const jsonBytes = new Uint8Array(wasm.memory.buffer, outPtr, outLen);
    const jsonStr = new TextDecoder().decode(jsonBytes);
    const manifest = JSON.parse(jsonStr);

    wasm.todo_wasm_free(outPtr, outLen);
    return manifest;
  } finally {
    wasm.todo_wasm_free(dataPtr, manifestBytes.length);
    wasm.todo_wasm_free(ptrBuf, 8);
    wasm.todo_wasm_free(lenBuf, 8);
  }
}

/**
 * Decrypt AES-256-GCM-SIV ciphertext and decompress Zstandard payload via WASM.
 * @param {Uint8Array} ciphertextWithTag
 * @param {string} keyHex
 * @param {string} nonceHex
 * @returns {Promise<Uint8Array>}
 */
async function wasmDecryptDecompress(ciphertextWithTag, keyHex, nonceHex) {
  const wasm = await getWasm();
  const encoder = new TextEncoder();
  const keyBytes = encoder.encode(keyHex.trim());
  const nonceBytes = encoder.encode(nonceHex.trim());

  const ctPtr = wasm.todo_wasm_alloc(ciphertextWithTag.length);
  const keyPtr = wasm.todo_wasm_alloc(keyBytes.length);
  const noncePtr = wasm.todo_wasm_alloc(nonceBytes.length);

  const ptrBuf = wasm.todo_wasm_alloc(8);
  const lenBuf = wasm.todo_wasm_alloc(8);

  try {
    new Uint8Array(wasm.memory.buffer).set(ciphertextWithTag, ctPtr);
    new Uint8Array(wasm.memory.buffer).set(keyBytes, keyPtr);
    new Uint8Array(wasm.memory.buffer).set(nonceBytes, noncePtr);

    const status = wasm.todo_wasm_decrypt_decompress(
      ctPtr,
      ciphertextWithTag.length,
      keyPtr,
      keyBytes.length,
      noncePtr,
      nonceBytes.length,
      ptrBuf,
      lenBuf
    );

    if (status < 0) {
      throw new Error(`AEAD tag verification or decompression failed (code ${status})`);
    }

    const view = new DataView(wasm.memory.buffer);
    const outPtr = view.getUint32(ptrBuf, true);
    const outLen = view.getUint32(lenBuf, true);

    const result = new Uint8Array(new Uint8Array(wasm.memory.buffer, outPtr, outLen));
    wasm.todo_wasm_free(outPtr, outLen);
    return result;
  } finally {
    wasm.todo_wasm_free(ctPtr, ciphertextWithTag.length);
    wasm.todo_wasm_free(keyPtr, keyBytes.length);
    wasm.todo_wasm_free(noncePtr, nonceBytes.length);
    wasm.todo_wasm_free(ptrBuf, 8);
    wasm.todo_wasm_free(lenBuf, 8);
  }
}

/**
 * Fetch raw block from trustless gateways with fallback.
 * @param {string} cid
 * @returns {Promise<{ bytes: Uint8Array, gateway: string }>}
 */
async function fetchRawBlockFromGateways(cid) {
  let lastErr = null;
  for (const gw of trustlessGateways) {
    const url = `${gw.replace(/\/+$/, "")}/${cid}?format=raw`;
    try {
      const resp = await fetch(url, {
        headers: { Accept: "application/vnd.ipld.raw" },
        mode: "cors"
      });
      if (resp.ok) {
        const buf = await resp.arrayBuffer();
        const bytes = new Uint8Array(buf);
        return { bytes, gateway: gw };
      }
    } catch (e) {
      lastErr = e;
    }
  }
  throw new Error(`Failed to retrieve raw block ${cid} from any configured gateway: ${lastErr ? lastErr.message : "All gateways unreachable"}`);
}

/**
 * Verified-Fetch handler for IPFS CIDs.
 * 1. Fetch raw block bytes.
 * 2. Verify SHA2-256 multihash in WASM.
 * 3. If DAG-JSON manifest, fetch and verify all chunk blocks in sequence.
 * 4. Return reconstructed Response with X-IPFS-Verified header.
 */
async function handleVerifiedIpfsFetch(cid, url) {
  try {
    const { bytes: rootBytes, gateway } = await fetchRawBlockFromGateways(cid);

    const isValid = await wasmVerifyBlock(rootBytes, cid);
    if (!isValid) {
      return new Response(
        JSON.stringify({
          error: "IPFS Multihash Verification Failed",
          detail: `Block retrieved from gateway '${gateway}' failed SHA2-256 cryptographic verification against CID ${cid}. Data rejected.`,
          cid
        }),
        {
          status: 502,
          headers: {
            "Content-Type": "application/json",
            "X-IPFS-Verified": "false"
          }
        }
      );
    }

    // Check if caller explicitly requested raw block only
    const params = new URL(url).searchParams;
    if (params.get("format") === "raw") {
      return new Response(rootBytes, {
        status: 200,
        headers: {
          "Content-Type": "application/vnd.ipld.raw",
          "X-IPFS-Verified": "true",
          "X-IPFS-Gateway": gateway,
          "X-IPFS-CID": cid
        }
      });
    }

    // Attempt to parse as DAG-JSON manifest
    let manifest = null;
    try {
      manifest = await wasmParseManifest(rootBytes);
    } catch (_) {
      // Not a DAG-JSON manifest -> single raw block
    }

    if (manifest && manifest.blocks && manifest.blocks.length > 0) {
      // Fetch and verify all chunk blocks
      const chunkBuffers = [];
      for (const blockLink of manifest.blocks) {
        const { bytes: chunkBytes, gateway: chunkGw } = await fetchRawBlockFromGateways(blockLink.cid);
        const chunkValid = await wasmVerifyBlock(chunkBytes, blockLink.cid);
        if (!chunkValid) {
          return new Response(
            JSON.stringify({
              error: "Chunk Multihash Verification Failed",
              detail: `Chunk block ${blockLink.cid} failed SHA2-256 verification from gateway ${chunkGw}.`,
              cid: blockLink.cid,
              root_cid: cid
            }),
            {
              status: 502,
              headers: {
                "Content-Type": "application/json",
                "X-IPFS-Verified": "false"
              }
            }
          );
        }
        chunkBuffers.push(chunkBytes);
      }

      // Reassemble chunks
      let totalLen = chunkBuffers.reduce((sum, c) => sum + c.length, 0);
      let combined = new Uint8Array(totalLen);
      let offset = 0;
      for (const buf of chunkBuffers) {
        combined.set(buf, offset);
        offset += buf.length;
      }

      return new Response(combined, {
        status: 200,
        headers: {
          "Content-Type": "application/octet-stream",
          "X-IPFS-Verified": "true",
          "X-IPFS-Root-CID": cid,
          "X-IPFS-Object-ID": manifest.object_id,
          "X-IPFS-Total-Size": String(manifest.total_size),
          "X-IPFS-Chunks-Count": String(manifest.blocks.length)
        }
      });
    }

    // Single verified block response
    return new Response(rootBytes, {
      status: 200,
      headers: {
        "Content-Type": "application/octet-stream",
        "X-IPFS-Verified": "true",
        "X-IPFS-Root-CID": cid
      }
    });
  } catch (err) {
    return new Response(
      JSON.stringify({
        error: "IPFS Verified Fetch Error",
        message: err.message
      }),
      {
        status: 500,
        headers: { "Content-Type": "application/json", "X-IPFS-Verified": "false" }
      }
    );
  }
}

// ---------------------------------------------------------------------------
// Service Worker Lifecycle
// ---------------------------------------------------------------------------

self.addEventListener("install", (event) => {
  event.waitUntil(
    (async () => {
      // Pre-warm WASM module
      await getWasm().catch((err) => console.warn("[SW] WASM pre-warm deferred:", err));
      await self.skipWaiting();
    })()
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);

  // Intercept /ipfs/<cid> and /api/v1/ipfs/sw/<cid>
  const ipfsMatch = url.pathname.match(/^\/ipfs\/([A-Za-z0-9]+)/) ||
                    url.pathname.match(/^\/api\/v1\/ipfs\/sw\/([A-Za-z0-9]+)/);

  if (ipfsMatch) {
    const cid = ipfsMatch[1];
    event.respondWith(handleVerifiedIpfsFetch(cid, event.request.url));
  }
});

self.addEventListener("message", (event) => {
  const data = event.data;
  if (!data || !data.type) return;

  if (data.type === "GET_STATUS") {
    event.ports[0]?.postMessage({
      version: SW_VERSION,
      wasmReady: wasmInstance !== null,
      gateways: trustlessGateways
    });
  } else if (data.type === "SET_GATEWAYS") {
    if (Array.isArray(data.gateways) && data.gateways.length > 0) {
      trustlessGateways = data.gateways;
      event.ports[0]?.postMessage({ success: true, gateways: trustlessGateways });
    }
  } else if (data.type === "VERIFY_BLOCK") {
    (async () => {
      try {
        const valid = await wasmVerifyBlock(new Uint8Array(data.bytes), data.cid);
        event.ports[0]?.postMessage({ valid, cid: data.cid });
      } catch (e) {
        event.ports[0]?.postMessage({ error: e.message });
      }
    })();
  } else if (data.type === "DECRYPT_PAYLOAD") {
    (async () => {
      try {
        const decrypted = await wasmDecryptDecompress(
          new Uint8Array(data.ciphertext),
          data.keyHex,
          data.nonceHex
        );
        event.ports[0]?.postMessage({ success: true, plaintext: decrypted });
      } catch (e) {
        event.ports[0]?.postMessage({ error: e.message });
      }
    })();
  }
});
