import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';

// Bech32 encoding for bc1q addresses
const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

function bech32Polymod(values: number[]): number {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const b = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) {
      if ((b >> i) & 1) chk ^= GEN[i];
    }
  }
  return chk;
}

function bech32HrpExpand(hrp: string): number[] {
  const ret: number[] = [];
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) >> 5);
  ret.push(0);
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) & 31);
  return ret;
}

function bech32CreateChecksum(hrp: string, data: number[]): number[] {
  const values = bech32HrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
  const polymod = bech32Polymod(values) ^ 1;
  const ret: number[] = [];
  for (let i = 0; i < 6; i++) ret.push((polymod >> (5 * (5 - i))) & 31);
  return ret;
}

function bech32Encode(hrp: string, data: number[]): string {
  const combined = data.concat(bech32CreateChecksum(hrp, data));
  let ret = hrp + '1';
  for (const d of combined) ret += BECH32_CHARSET[d];
  return ret;
}

function convertBits(data: Uint8Array, fromBits: number, toBits: number, pad: boolean): number[] {
  let acc = 0, bits = 0;
  const ret: number[] = [];
  const maxv = (1 << toBits) - 1;
  for (const value of data) {
    acc = (acc << fromBits) | value;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      ret.push((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) ret.push((acc << (toBits - bits)) & maxv);
  }
  return ret;
}

function pubkeyToP2wpkhAddress(pubkey: Uint8Array): string {
  const h = ripemd160(sha256(pubkey));
  const words = [0].concat(convertBits(h, 8, 5, true)); // witness version 0
  return bech32Encode('bc', words);
}

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(bytes: Uint8Array): string {
  let num = BigInt(0);
  for (const b of bytes) num = num * 256n + BigInt(b);
  let str = '';
  while (num > 0n) {
    str = BASE58_ALPHABET[Number(num % 58n)] + str;
    num = num / 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    str = '1' + str;
  }
  return str;
}

function pubkeyToP2pkhAddress(pubkey: Uint8Array): string {
  const h = ripemd160(sha256(pubkey));
  // Base58Check encode with version 0x00
  const versioned = new Uint8Array(21);
  versioned[0] = 0x00;
  versioned.set(h, 1);
  const checksum = sha256(sha256(versioned)).slice(0, 4);
  const full = new Uint8Array(25);
  full.set(versioned);
  full.set(checksum, 21);
  return base58Encode(full);
}

// Bitcoin signed message format
function bitcoinMessageHash(message: string): Uint8Array {
  const prefix = '\x18Bitcoin Signed Message:\n';
  const msgBytes = new TextEncoder().encode(message);
  const prefixBytes = new TextEncoder().encode(prefix);

  // Varint encode message length
  const lenBytes = varintEncode(msgBytes.length);

  const buf = new Uint8Array(prefixBytes.length + lenBytes.length + msgBytes.length);
  buf.set(prefixBytes, 0);
  buf.set(lenBytes, prefixBytes.length);
  buf.set(msgBytes, prefixBytes.length + lenBytes.length);

  return sha256(sha256(buf));
}

function varintEncode(n: number): Uint8Array {
  if (n < 253) return new Uint8Array([n]);
  if (n <= 0xffff) {
    const buf = new Uint8Array(3);
    buf[0] = 253;
    buf[1] = n & 0xff;
    buf[2] = (n >> 8) & 0xff;
    return buf;
  }
  // Shouldn't need larger for message lengths
  const buf = new Uint8Array(5);
  buf[0] = 254;
  buf[1] = n & 0xff;
  buf[2] = (n >> 8) & 0xff;
  buf[3] = (n >> 16) & 0xff;
  buf[4] = (n >> 24) & 0xff;
  return buf;
}

/**
 * Verify a BIP-137 Bitcoin message signature.
 * Returns the recovered address or null on failure.
 *
 * Recovery flag ranges:
 * 27-30: uncompressed P2PKH
 * 31-34: compressed P2PKH
 * 35-38: compressed P2SH-P2WPKH
 * 39-42: compressed P2WPKH (native SegWit, bc1q)
 */
export function verifyBip137(message: string, signatureBase64: string): string | null {
  try {
    // Decode base64
    const sigBytes = Uint8Array.from(atob(signatureBase64), c => c.charCodeAt(0));
    if (sigBytes.length !== 65) return null;

    const flag = sigBytes[0];
    if (flag < 27 || flag > 42) return null;

    const r = sigBytes.slice(1, 33);
    const s = sigBytes.slice(33, 65);

    // Determine recovery ID and address type
    let recoveryId: number;
    let addressType: 'p2pkh' | 'p2pkh-compressed' | 'p2sh-p2wpkh' | 'p2wpkh';

    if (flag >= 39) {
      recoveryId = flag - 39;
      addressType = 'p2wpkh';
    } else if (flag >= 35) {
      recoveryId = flag - 35;
      addressType = 'p2sh-p2wpkh';
    } else if (flag >= 31) {
      recoveryId = flag - 31;
      addressType = 'p2pkh-compressed';
    } else {
      recoveryId = flag - 27;
      addressType = 'p2pkh';
    }

    // Hash the message
    const msgHash = bitcoinMessageHash(message);

    // Build the signature for noble/curves
    const sig = new secp256k1.Signature(
      BigInt('0x' + Array.from(r).map(b => b.toString(16).padStart(2, '0')).join('')),
      BigInt('0x' + Array.from(s).map(b => b.toString(16).padStart(2, '0')).join(''))
    ).addRecoveryBit(recoveryId);

    // Recover the public key
    const pubkey = sig.recoverPublicKey(msgHash);

    // Get compressed or uncompressed pubkey bytes
    if (addressType === 'p2pkh') {
      const addr = pubkeyToP2pkhAddress(pubkey.toRawBytes(false)); // uncompressed
      return addr;
    }

    const compressedPubkey = pubkey.toRawBytes(true); // compressed

    if (addressType === 'p2pkh-compressed') {
      return pubkeyToP2pkhAddress(compressedPubkey);
    } else if (addressType === 'p2wpkh') {
      return pubkeyToP2wpkhAddress(compressedPubkey);
    } else {
      // P2SH-P2WPKH — derive the underlying P2WPKH address for comparison
      return pubkeyToP2wpkhAddress(compressedPubkey);
    }
  } catch {
    return null;
  }
}
