// Bitcoin signature verification: BIP-137 + BIP-322 simple (P2WPKH)
// Pure JS, Cloudflare Worker compatible via @noble/curves

import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { bech32 } from '@scure/base';

// --- Utilities ---

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const len = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(len);
  let offset = 0;
  for (const a of arrays) { result.set(a, offset); offset += a.length; }
  return result;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function writeU32LE(value: number): Uint8Array {
  const buf = new Uint8Array(4);
  buf[0] = value & 0xff;
  buf[1] = (value >> 8) & 0xff;
  buf[2] = (value >> 16) & 0xff;
  buf[3] = (value >> 24) & 0xff;
  return buf;
}

function writeU64LE(value: number): Uint8Array {
  const buf = new Uint8Array(8);
  buf[0] = value & 0xff;
  buf[1] = (value >> 8) & 0xff;
  buf[2] = (value >> 16) & 0xff;
  buf[3] = (value >> 24) & 0xff;
  return buf;
}

function encodeVarint(n: number): Uint8Array {
  if (n < 0xfd) return new Uint8Array([n]);
  if (n <= 0xffff) return new Uint8Array([0xfd, n & 0xff, (n >> 8) & 0xff]);
  return new Uint8Array([0xfe, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff]);
}

// --- Hash functions ---

function hash160(data: Uint8Array): Uint8Array {
  return ripemd160(sha256(data));
}

function doubleSha256(data: Uint8Array): Uint8Array {
  return sha256(sha256(data));
}

/** BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg) */
function taggedHash(tag: string, msg: Uint8Array): Uint8Array {
  const tagHash = sha256(new TextEncoder().encode(tag));
  return sha256(concatBytes(tagHash, tagHash, msg));
}

// --- Bitcoin message hash (BIP-137) ---

function bitcoinMessageHash(message: string): Uint8Array {
  const prefix = new TextEncoder().encode('\x18Bitcoin Signed Message:\n');
  const msgBytes = new TextEncoder().encode(message);
  const msgLen = encodeVarint(msgBytes.length);
  return doubleSha256(concatBytes(prefix, msgLen, msgBytes));
}

// --- Address derivation ---

function pubkeyToP2WPKH(pubkey: Uint8Array): string {
  const h = hash160(pubkey);
  const words = bech32.toWords(h);
  words.unshift(0); // witness version 0
  return bech32.encode('bc', words);
}

// --- BIP-137 verification ---

function verifyBIP137(
  message: string, sigBase64: string, expectedAddress: string
): { valid: boolean; error?: string } {
  let sigBytes: Uint8Array;
  try { sigBytes = base64ToBytes(sigBase64); }
  catch { return { valid: false, error: 'Invalid base64 signature' }; }

  if (sigBytes.length !== 65) {
    return { valid: false, error: `BIP-137 signature must be 65 bytes, got ${sigBytes.length}` };
  }

  const flag = sigBytes[0];
  const compactSig = sigBytes.slice(1, 65);

  let recoveryId: number;
  let compressed: boolean;

  if (flag >= 27 && flag <= 30) {
    recoveryId = flag - 27; compressed = false;
  } else if (flag >= 31 && flag <= 34) {
    recoveryId = flag - 31; compressed = true;
  } else if (flag >= 35 && flag <= 38) {
    recoveryId = flag - 35; compressed = true;
  } else if (flag >= 39 && flag <= 42) {
    recoveryId = flag - 39; compressed = true;
  } else {
    return { valid: false, error: `Unknown BIP-137 recovery flag: ${flag}` };
  }

  const msgHash = bitcoinMessageHash(message);

  try {
    const r = BigInt('0x' + bytesToHex(compactSig.slice(0, 32)));
    const s = BigInt('0x' + bytesToHex(compactSig.slice(32, 64)));
    const sig = new secp256k1.Signature(r, s, recoveryId);
    const pubkey = sig.recoverPublicKey(msgHash);
    const pubkeyBytes = compressed ? pubkey.toRawBytes(true) : pubkey.toRawBytes(false);

    // Derive P2WPKH address (bc1q) — the primary address type for AIBTC agents
    const derivedAddress = pubkeyToP2WPKH(compressed ? pubkeyBytes : pubkey.toRawBytes(true));
    if (derivedAddress.toLowerCase() !== expectedAddress.toLowerCase()) {
      return { valid: false, error: `Recovered address '${derivedAddress}' does not match '${expectedAddress}'` };
    }
    return { valid: true };
  } catch (e: any) {
    return { valid: false, error: `Signature recovery failed: ${e.message}` };
  }
}

// --- BIP-322 simple verification (P2WPKH / bc1q) ---

function verifyBIP322Simple(
  message: string, sigBase64: string, expectedAddress: string
): { valid: boolean; error?: string } {
  let witnessBytes: Uint8Array;
  try { witnessBytes = base64ToBytes(sigBase64); }
  catch { return { valid: false, error: 'Invalid base64 signature' }; }

  // Parse witness stack: [num_items] [len1] [item1] [len2] [item2]
  if (witnessBytes.length < 2) return { valid: false, error: 'Witness too short' };
  const numItems = witnessBytes[0];
  if (numItems !== 2) return { valid: false, error: `Expected 2 witness items, got ${numItems}` };

  let off = 1;
  const sigLen = witnessBytes[off++];
  if (off + sigLen > witnessBytes.length) return { valid: false, error: 'Witness signature truncated' };
  const derSig = witnessBytes.slice(off, off + sigLen);
  off += sigLen;

  const pkLen = witnessBytes[off++];
  if (pkLen !== 33) return { valid: false, error: `Expected 33-byte compressed pubkey, got ${pkLen}` };
  if (off + pkLen > witnessBytes.length) return { valid: false, error: 'Witness pubkey truncated' };
  const pubkeyBytes = witnessBytes.slice(off, off + pkLen);

  // Verify pubkey derives to claimed address
  const derivedAddress = pubkeyToP2WPKH(pubkeyBytes);
  if (derivedAddress.toLowerCase() !== expectedAddress.toLowerCase()) {
    return { valid: false, error: `Pubkey derives to '${derivedAddress}', not '${expectedAddress}'` };
  }

  // Construct BIP-322 to_spend transaction
  const pkHash = hash160(pubkeyBytes);
  const scriptPubKey = concatBytes(new Uint8Array([0x00, 0x14]), pkHash);
  const messageBytes = new TextEncoder().encode(message);
  const messageHash = taggedHash('BIP0322-signed-message', messageBytes);
  const toSpendScriptSig = concatBytes(new Uint8Array([0x00, 0x20]), messageHash);

  const toSpend = concatBytes(
    writeU32LE(0),                          // version
    new Uint8Array([0x01]),                 // input count
    new Uint8Array(32),                     // prev txid (zeros)
    writeU32LE(0xFFFFFFFF),                 // prev vout
    encodeVarint(toSpendScriptSig.length),
    toSpendScriptSig,
    writeU32LE(0),                          // sequence
    new Uint8Array([0x01]),                 // output count
    writeU64LE(0),                          // value
    encodeVarint(scriptPubKey.length),
    scriptPubKey,
    writeU32LE(0)                           // locktime
  );
  const toSpendTxid = doubleSha256(toSpend);

  // BIP-143 sighash for to_sign input 0
  const prevout = concatBytes(toSpendTxid, writeU32LE(0));
  const hashPrevouts = doubleSha256(prevout);
  const hashSequence = doubleSha256(writeU32LE(0));
  const opReturnOutput = concatBytes(writeU64LE(0), new Uint8Array([0x01, 0x6a]));
  const hashOutputs = doubleSha256(opReturnOutput);
  const scriptCode = concatBytes(
    new Uint8Array([0x76, 0xa9, 0x14]), pkHash, new Uint8Array([0x88, 0xac])
  );

  const sighashPreimage = concatBytes(
    writeU32LE(0),                          // version
    hashPrevouts,
    hashSequence,
    toSpendTxid, writeU32LE(0),             // outpoint
    encodeVarint(scriptCode.length),
    scriptCode,
    writeU64LE(0),                          // amount
    writeU32LE(0),                          // sequence
    hashOutputs,
    writeU32LE(0),                          // locktime
    writeU32LE(1)                           // SIGHASH_ALL
  );
  const sighash = doubleSha256(sighashPreimage);

  // Verify ECDSA signature (strip trailing SIGHASH_ALL byte if present)
  try {
    let sigToVerify = derSig;
    if (sigToVerify.length > 0 && sigToVerify[sigToVerify.length - 1] === 0x01) {
      sigToVerify = sigToVerify.slice(0, -1);
    }
    const isValid = secp256k1.verify(sigToVerify, sighash, pubkeyBytes);
    if (!isValid) {
      return { valid: false, error: 'BIP-322 ECDSA signature verification failed' };
    }
    return { valid: true };
  } catch (e: any) {
    return { valid: false, error: `BIP-322 verification error: ${e.message}` };
  }
}

// --- Main entry point ---

/**
 * Verify a Bitcoin signature (BIP-137 or BIP-322 simple) against a message and address.
 * Supports P2WPKH (bc1q) addresses used by AIBTC agents.
 */
export function verifyBitcoinSignature(
  message: string, signatureBase64: string, expectedAddress: string
): { valid: boolean; error?: string } {
  let sigBytes: Uint8Array;
  try { sigBytes = base64ToBytes(signatureBase64); }
  catch { return { valid: false, error: 'Invalid base64 signature' }; }

  // BIP-137: exactly 65 bytes, first byte is recovery flag 27-42
  if (sigBytes.length === 65 && sigBytes[0] >= 27 && sigBytes[0] <= 42) {
    return verifyBIP137(message, signatureBase64, expectedAddress);
  }

  // BIP-322 simple (P2WPKH): witness format, first byte = 0x02 (2 witness items)
  if (sigBytes.length > 65 && sigBytes[0] === 0x02) {
    return verifyBIP322Simple(message, signatureBase64, expectedAddress);
  }

  return {
    valid: false,
    error: `Unknown signature format (${sigBytes.length} bytes, first byte: 0x${sigBytes[0].toString(16)})`
  };
}
