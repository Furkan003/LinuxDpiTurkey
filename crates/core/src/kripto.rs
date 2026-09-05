//! QUIC Initial paketleri için gereken kriptografi.
//!
//! ## Neden elle yazılıyor
//!
//! Motor root olarak çalışıyor. Bir kripto kütüphanesi eklemek, yanında
//! onlarca dolaylı paketi de root yetkisiyle çalışan koda sokmak demek —
//! tedarik zincirine sızılırsa kuran herkeste root. Ayrıca yaygın arka uçlar
//! (`ring`, `aws-lc-rs`) C ve assembly içeriyor ve motorun statik musl
//! derlemesini kırma riski taşıyor; "her dağıtımda çalışır" özelliği bu
//! derlemeye bağlı.
//!
//! Bize gereken çok dar bir küme: SHA-256, HMAC, HKDF ve AES-128 (GCM ve tek
//! blok). Hepsi RFC ve NIST test vektörleriyle **birebir** doğrulanabiliyor,
//! testler aşağıda. Gizli veri üretmiyoruz; bu kod yalnızca sahte bir paket
//! kuruyor ve o paketin içeriği zaten atılacak.
//!
//! ## Sabit zamanlılık
//!
//! Bu kod bir sırrı korumuyor: ürettiğimiz anahtar herkesin bildiği bir
//! sabitten türüyor (QUIC Initial anahtarları bağlantı kimliğinden çıkar ve
//! kimlik açıkta gider). Yan kanal saldırısının çalacağı bir şey yok.

/// SHA-256 özet uzunluğu.
pub const SHA256_LEN: usize = 32;

// ---------------------------------------------------------------- SHA-256

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256 özeti.
pub fn sha256(veri: &[u8]) -> [u8; SHA256_LEN] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    // Doldurma: 0x80, sonra sıfırlar, sonra 64 bit uzunluk.
    let mut m = veri.to_vec();
    let bit_uzunluk = (veri.len() as u64) * 8;
    m.push(0x80);
    while m.len() % 64 != 56 {
        m.push(0);
    }
    m.extend_from_slice(&bit_uzunluk.to_be_bytes());

    for blok in m.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, p) in blok.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([p[0], p[1], p[2], p[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (i, v) in [a, b, c, d, e, f, g, hh].into_iter().enumerate() {
            h[i] = h[i].wrapping_add(v);
        }
    }

    let mut out = [0u8; SHA256_LEN];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

// -------------------------------------------------------------- HMAC/HKDF

/// HMAC-SHA256.
pub fn hmac_sha256(anahtar: &[u8], veri: &[u8]) -> [u8; SHA256_LEN] {
    let mut k = [0u8; 64];
    if anahtar.len() > 64 {
        k[..SHA256_LEN].copy_from_slice(&sha256(anahtar));
    } else {
        k[..anahtar.len()].copy_from_slice(anahtar);
    }

    let mut ic = Vec::with_capacity(64 + veri.len());
    let mut oc = Vec::with_capacity(64 + SHA256_LEN);
    for b in k {
        ic.push(b ^ 0x36);
        oc.push(b ^ 0x5c);
    }
    ic.extend_from_slice(veri);
    oc.extend_from_slice(&sha256(&ic));
    sha256(&oc)
}

/// HKDF-Extract (RFC 5869).
pub fn hkdf_extract(tuz: &[u8], girdi: &[u8]) -> [u8; SHA256_LEN] {
    hmac_sha256(tuz, girdi)
}

/// HKDF-Expand (RFC 5869).
pub fn hkdf_expand(gizli: &[u8], bilgi: &[u8], uzunluk: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(uzunluk);
    let mut onceki: Vec<u8> = Vec::new();
    let mut sayac: u8 = 1;
    while out.len() < uzunluk {
        let mut girdi = onceki.clone();
        girdi.extend_from_slice(bilgi);
        girdi.push(sayac);
        onceki = hmac_sha256(gizli, &girdi).to_vec();
        out.extend_from_slice(&onceki);
        sayac += 1;
    }
    out.truncate(uzunluk);
    out
}

/// TLS 1.3 / QUIC `HKDF-Expand-Label` (RFC 8446 §7.1).
///
/// Etiketin başına `tls13 ` ekleniyor ve yapı `Length | LabelLen | Label |
/// ContextLen | Context` biçiminde kodlanıyor.
pub fn hkdf_expand_label(gizli: &[u8], etiket: &str, uzunluk: usize) -> Vec<u8> {
    let tam = format!("tls13 {etiket}");
    let mut bilgi = Vec::with_capacity(4 + tam.len());
    bilgi.extend_from_slice(&(uzunluk as u16).to_be_bytes());
    bilgi.push(tam.len() as u8);
    bilgi.extend_from_slice(tam.as_bytes());
    bilgi.push(0); // boş bağlam
    hkdf_expand(gizli, &bilgi, uzunluk)
}

// ------------------------------------------------------------------- AES

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// AES-128 anahtar programı (11 tur anahtarı).
pub struct Aes128 {
    tur_anahtarlari: [[u8; 16]; 11],
}

impl Aes128 {
    /// 16 baytlık anahtardan tur anahtarlarını türetir.
    pub fn new(anahtar: &[u8; 16]) -> Self {
        let mut w = [[0u8; 4]; 44];
        for i in 0..4 {
            w[i].copy_from_slice(&anahtar[i * 4..i * 4 + 4]);
        }
        for i in 4..44 {
            let mut t = w[i - 1];
            if i % 4 == 0 {
                t.rotate_left(1);
                for b in t.iter_mut() {
                    *b = SBOX[*b as usize];
                }
                t[0] ^= RCON[i / 4 - 1];
            }
            for j in 0..4 {
                w[i][j] = w[i - 4][j] ^ t[j];
            }
        }

        let mut tur_anahtarlari = [[0u8; 16]; 11];
        for tur in 0..11 {
            for k in 0..4 {
                tur_anahtarlari[tur][k * 4..k * 4 + 4].copy_from_slice(&w[tur * 4 + k]);
            }
        }
        Self { tur_anahtarlari }
    }

    /// Tek bloğu şifreler (ECB'nin çekirdeği).
    pub fn blok_sifrele(&self, blok: &[u8; 16]) -> [u8; 16] {
        let mut s = *blok;
        xor(&mut s, &self.tur_anahtarlari[0]);
        for tur in 1..10 {
            alt_bytes(&mut s);
            satir_kaydir(&mut s);
            sutun_karistir(&mut s);
            xor(&mut s, &self.tur_anahtarlari[tur]);
        }
        alt_bytes(&mut s);
        satir_kaydir(&mut s);
        xor(&mut s, &self.tur_anahtarlari[10]);
        s
    }
}

fn xor(a: &mut [u8; 16], b: &[u8; 16]) {
    for i in 0..16 {
        a[i] ^= b[i];
    }
}

fn alt_bytes(s: &mut [u8; 16]) {
    for b in s.iter_mut() {
        *b = SBOX[*b as usize];
    }
}

/// Durum sütun sıralı tutuluyor: `s[c*4 + r]`.
fn satir_kaydir(s: &mut [u8; 16]) {
    let g = *s;
    for r in 1..4 {
        for c in 0..4 {
            s[c * 4 + r] = g[((c + r) % 4) * 4 + r];
        }
    }
}

fn carp2(x: u8) -> u8 {
    (x << 1) ^ if x & 0x80 != 0 { 0x1b } else { 0 }
}

fn sutun_karistir(s: &mut [u8; 16]) {
    for c in 0..4 {
        let k = &mut s[c * 4..c * 4 + 4];
        let (a0, a1, a2, a3) = (k[0], k[1], k[2], k[3]);
        let t = a0 ^ a1 ^ a2 ^ a3;
        k[0] = a0 ^ t ^ carp2(a0 ^ a1);
        k[1] = a1 ^ t ^ carp2(a1 ^ a2);
        k[2] = a2 ^ t ^ carp2(a2 ^ a3);
        k[3] = a3 ^ t ^ carp2(a3 ^ a0);
    }
}

// ------------------------------------------------------------- AES-128-GCM

/// GF(2^128) çarpımı (GHASH için).
fn ghash_carp(x: u128, y: u128) -> u128 {
    let mut z: u128 = 0;
    let mut v = y;
    for i in 0..128 {
        if x >> (127 - i) & 1 == 1 {
            z ^= v;
        }
        let dusen = v & 1;
        v >>= 1;
        if dusen == 1 {
            v ^= 0xe100_0000_0000_0000_0000_0000_0000_0000;
        }
    }
    z
}

fn ghash(h: u128, veri: &[u8]) -> u128 {
    let mut y: u128 = 0;
    for blok in veri.chunks(16) {
        let mut b = [0u8; 16];
        b[..blok.len()].copy_from_slice(blok);
        y = ghash_carp(y ^ u128::from_be_bytes(b), h);
    }
    y
}

/// AES-128-GCM şifreleme. Şifreli metin + 16 baytlık etiket döner.
pub fn aes128_gcm_sifrele(anahtar: &[u8; 16], nonce: &[u8; 12], ek: &[u8], acik: &[u8]) -> Vec<u8> {
    let aes = Aes128::new(anahtar);
    let h = u128::from_be_bytes(aes.blok_sifrele(&[0u8; 16]));

    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;

    // CTR: sayaç J0+1'den başlıyor.
    let mut sifreli = Vec::with_capacity(acik.len());
    let mut sayac = u32::from_be_bytes([j0[12], j0[13], j0[14], j0[15]]);
    for parca in acik.chunks(16) {
        sayac = sayac.wrapping_add(1);
        let mut blok = j0;
        blok[12..16].copy_from_slice(&sayac.to_be_bytes());
        let akis = aes.blok_sifrele(&blok);
        for (i, b) in parca.iter().enumerate() {
            sifreli.push(b ^ akis[i]);
        }
    }

    // GHASH: ek veri + şifreli metin, ikisi de 16'ya tamamlanıyor.
    let mut g = Vec::new();
    g.extend_from_slice(ek);
    while g.len() % 16 != 0 {
        g.push(0);
    }
    g.extend_from_slice(&sifreli);
    while g.len() % 16 != 0 {
        g.push(0);
    }
    g.extend_from_slice(&((ek.len() as u64) * 8).to_be_bytes());
    g.extend_from_slice(&((sifreli.len() as u64) * 8).to_be_bytes());

    let s = ghash(h, &g);
    let etiket = s ^ u128::from_be_bytes(aes.blok_sifrele(&j0));
    sifreli.extend_from_slice(&etiket.to_be_bytes());
    sifreli
}

#[cfg(test)]
mod tests {
    use super::*;

    fn onaltilik(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect()
    }

    fn yaz(v: &[u8]) -> String {
        v.iter().map(|b| format!("{b:02x}")).collect()
    }

    // --- SHA-256 (FIPS 180-4 örnekleri) ---

    #[test]
    fn sha256_bos() {
        assert_eq!(
            yaz(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_abc() {
        assert_eq!(
            yaz(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// Blok sınırını aşan girdi: doldurma mantığı burada kırılır.
    #[test]
    fn sha256_uzun() {
        assert_eq!(
            yaz(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    // --- HMAC-SHA256 (RFC 4231) ---

    #[test]
    fn hmac_rfc4231_1() {
        let anahtar = vec![0x0b; 20];
        assert_eq!(
            yaz(&hmac_sha256(&anahtar, b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    /// Bloktan uzun anahtar önce özetlenmeli.
    #[test]
    fn hmac_uzun_anahtar() {
        let anahtar = vec![0xaa; 131];
        assert_eq!(
            yaz(&hmac_sha256(
                &anahtar,
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    // --- HKDF (RFC 5869 Test Case 1) ---

    #[test]
    fn hkdf_rfc5869_1() {
        let ikm = vec![0x0b; 22];
        let tuz = onaltilik("000102030405060708090a0b0c");
        let bilgi = onaltilik("f0f1f2f3f4f5f6f7f8f9");
        let prk = hkdf_extract(&tuz, &ikm);
        assert_eq!(
            yaz(&prk),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );
        assert_eq!(
            yaz(&hkdf_expand(&prk, &bilgi, 42)),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    // --- AES-128 (FIPS 197 örneği) ---

    #[test]
    fn aes128_fips197() {
        let anahtar: [u8; 16] = onaltilik("000102030405060708090a0b0c0d0e0f")
            .try_into()
            .unwrap();
        let acik: [u8; 16] = onaltilik("00112233445566778899aabbccddeeff")
            .try_into()
            .unwrap();
        let aes = Aes128::new(&anahtar);
        assert_eq!(yaz(&aes.blok_sifrele(&acik)), "69c4e0d86a7b0430d8cdb78070b4c55a");
    }

    // --- AES-128-GCM (NIST GCM test vektörleri) ---

    #[test]
    fn gcm_bos_metin() {
        let k = [0u8; 16];
        let n = [0u8; 12];
        let sonuc = aes128_gcm_sifrele(&k, &n, &[], &[]);
        assert_eq!(yaz(&sonuc), "58e2fccefa7e3061367f1d57a4e7455a");
    }

    #[test]
    fn gcm_tek_blok() {
        let k = [0u8; 16];
        let n = [0u8; 12];
        let acik = [0u8; 16];
        let sonuc = aes128_gcm_sifrele(&k, &n, &[], &acik);
        assert_eq!(
            yaz(&sonuc),
            "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf"
        );
    }

    #[test]
    fn gcm_ek_veriyle() {
        let k: [u8; 16] = onaltilik("feffe9928665731c6d6a8f9467308308")
            .try_into()
            .unwrap();
        let n: [u8; 12] = onaltilik("cafebabefacedbaddecaf888").try_into().unwrap();
        let acik = onaltilik(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );
        let ek = onaltilik("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let sonuc = aes128_gcm_sifrele(&k, &n, &ek, &acik);
        assert_eq!(
            yaz(&sonuc),
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e0915bc94fbc3221a5db94fae95ae7121a47"
        );
    }
}
