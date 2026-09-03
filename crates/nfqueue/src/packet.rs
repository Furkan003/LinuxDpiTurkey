//! IPv4 + TCP paket ayrıştırma ve sağlama toplamı.
//!
//! Tümü saf fonksiyondur ve her platformda test edilir. Sağlama toplamı yanlış
//! hesaplanırsa üretilen sahte paket ilk yönlendiricide düşer ve motor sessizce
//! hiçbir işe yaramaz — bu yüzden burası en çok test edilen yer.
//!
//! Girdi ağdan geldiği için hiçbir uzunluk alanına güvenilmez; her erişim
//! sınır kontrollüdür ve bozuk paket panik değil `None` üretir.

/// IPv4 başlığının en küçük boyutu.
pub const IPV4_MIN_HEADER: usize = 20;
/// TCP başlığının en küçük boyutu.
pub const TCP_MIN_HEADER: usize = 20;
/// IPv4 protokol numarası: TCP.
pub const PROTO_TCP: u8 = 6;

/// Çözümlenmiş bir IPv4 + TCP paketi.
///
/// Alanlar ham tampona göre konumdur; tampon kopyalanmaz.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpPacket {
    /// IPv4 başlığının uzunluğu (bayt).
    pub ip_header_len: usize,
    /// TCP başlığının uzunluğu (bayt).
    pub tcp_header_len: usize,
    /// Yükün başladığı konum.
    pub payload_offset: usize,
    /// Yükün uzunluğu.
    pub payload_len: usize,
    /// Kaynak adres.
    pub src: [u8; 4],
    /// Hedef adres.
    pub dst: [u8; 4],
    /// Kaynak port.
    pub src_port: u16,
    /// Hedef port.
    pub dst_port: u16,
    /// Sıra numarası.
    pub seq: u32,
    /// Yaşam süresi.
    pub ttl: u8,
}

impl TcpPacket {
    /// Ham bir IPv4 paketini çözümler.
    ///
    /// TCP olmayan, parçalanmış veya tutarsız uzunluk taşıyan paketler için
    /// `None` döner.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < IPV4_MIN_HEADER {
            return None;
        }
        if buf[0] >> 4 != 4 {
            return None;
        }

        let ip_header_len = (buf[0] & 0x0F) as usize * 4;
        if ip_header_len < IPV4_MIN_HEADER || buf.len() < ip_header_len {
            return None;
        }
        if buf[9] != PROTO_TCP {
            return None;
        }

        // Parçalanmış paketlere dokunmuyoruz: yük tam değildir.
        let frag = u16::from_be_bytes([buf[6], buf[7]]);
        if frag & 0x1FFF != 0 {
            return None;
        }

        let total_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        // Toplam uzunluk tampondan büyük olamaz; olursa paket bozuktur.
        if total_len < ip_header_len + TCP_MIN_HEADER || total_len > buf.len() {
            return None;
        }

        let tcp = buf.get(ip_header_len..total_len)?;
        if tcp.len() < TCP_MIN_HEADER {
            return None;
        }

        let tcp_header_len = (tcp[12] >> 4) as usize * 4;
        if tcp_header_len < TCP_MIN_HEADER || tcp_header_len > tcp.len() {
            return None;
        }

        let payload_offset = ip_header_len + tcp_header_len;
        let payload_len = total_len - payload_offset;

        Some(TcpPacket {
            ip_header_len,
            tcp_header_len,
            payload_offset,
            payload_len,
            src: [buf[12], buf[13], buf[14], buf[15]],
            dst: [buf[16], buf[17], buf[18], buf[19]],
            src_port: u16::from_be_bytes([tcp[0], tcp[1]]),
            dst_port: u16::from_be_bytes([tcp[2], tcp[3]]),
            seq: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
            ttl: buf[8],
        })
    }

    /// Yükü döner.
    pub fn payload<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        buf.get(self.payload_offset..self.payload_offset + self.payload_len)
            .unwrap_or(&[])
    }
}

/// İnternet sağlama toplamı: 16-bit sözcüklerin birler tümleyeni toplamı.
pub fn checksum(data: &[u8]) -> u16 {
    checksum_with(data, 0)
}

/// Bir ön toplamla başlayarak sağlama toplamı hesaplar.
///
/// TCP sözde başlığı (pseudo-header) bu şekilde eklenir.
fn checksum_with(data: &[u8], start: u32) -> u16 {
    let mut sum = start;

    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    // Tek bayt kalırsa sıfırla doldurulur.
    if let [last] = chunks.remainder() {
        sum += u32::from(u16::from_be_bytes([*last, 0]));
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// IPv4 başlığının sağlama toplamını yeniden hesaplar ve yerine yazar.
///
/// TTL değiştirildiğinde bu **zorunludur**; aksi halde paket ilk
/// yönlendiricide düşer.
pub fn fix_ipv4_checksum(buf: &mut [u8], ip_header_len: usize) -> Option<()> {
    let header = buf.get_mut(..ip_header_len)?;
    header[10] = 0;
    header[11] = 0;
    let ck = checksum(header).to_be_bytes();
    buf[10] = ck[0];
    buf[11] = ck[1];
    Some(())
}

/// TCP sağlama toplamını yeniden hesaplar ve yerine yazar.
///
/// Yük değiştirildiğinde zorunludur.
pub fn fix_tcp_checksum(buf: &mut [u8], pkt: &TcpPacket) -> Option<()> {
    let tcp_len = buf.len().checked_sub(pkt.ip_header_len)?;
    if tcp_len < TCP_MIN_HEADER {
        return None;
    }

    // Sözde başlık: kaynak, hedef, sıfır, protokol, TCP uzunluğu.
    let mut pseudo: u32 = 0;
    for pair in [
        [pkt.src[0], pkt.src[1]],
        [pkt.src[2], pkt.src[3]],
        [pkt.dst[0], pkt.dst[1]],
        [pkt.dst[2], pkt.dst[3]],
        [0, PROTO_TCP],
        (tcp_len as u16).to_be_bytes(),
    ] {
        pseudo += u32::from(u16::from_be_bytes(pair));
    }

    let tcp = buf.get_mut(pkt.ip_header_len..)?;
    tcp[16] = 0;
    tcp[17] = 0;
    let ck = checksum_with(tcp, pseudo).to_be_bytes();
    tcp[16] = ck[0];
    tcp[17] = ck[1];
    Some(())
}

/// Testlerin sözde başlıkla toplam hesaplaması için.
#[cfg(test)]
pub(crate) fn checksum_for_test(data: &[u8], start: u32) -> u16 {
    checksum_with(data, start)
}

/// Bir IPv4 başlığının sağlama toplamının doğru olup olmadığı.
///
/// Doğru bir başlığın kendi sağlama toplamıyla birlikte toplamı sıfırdır.
pub fn ipv4_checksum_valid(buf: &[u8], ip_header_len: usize) -> bool {
    buf.get(..ip_header_len).is_some_and(|h| checksum(h) == 0)
}

#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;

    /// Test için IPv4 + TCP paketi kurar.
    pub fn build(payload: &[u8], ttl: u8) -> Vec<u8> {
        let total = IPV4_MIN_HEADER + TCP_MIN_HEADER + payload.len();
        let mut b = vec![0u8; total];

        b[0] = 0x45; // sürüm 4, IHL 5
        b[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        b[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        b[6] = 0x40; // don't fragment
        b[8] = ttl;
        b[9] = PROTO_TCP;
        b[12..16].copy_from_slice(&[192, 168, 1, 10]);
        b[16..20].copy_from_slice(&[93, 184, 216, 34]);

        let t = IPV4_MIN_HEADER;
        b[t..t + 2].copy_from_slice(&54321u16.to_be_bytes());
        b[t + 2..t + 4].copy_from_slice(&443u16.to_be_bytes());
        b[t + 4..t + 8].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
        b[t + 12] = 5 << 4; // veri konumu
        b[t + 13] = 0x18; // PSH + ACK
        b[t + 14..t + 16].copy_from_slice(&64240u16.to_be_bytes());

        b[t + TCP_MIN_HEADER..].copy_from_slice(payload);

        let pkt = TcpPacket::parse(&b).expect("kurulan paket çözümlenemedi");
        fix_ipv4_checksum(&mut b, pkt.ip_header_len).unwrap();
        fix_tcp_checksum(&mut b, &pkt).unwrap();
        b
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::build;
    use super::*;

    #[test]
    fn paket_cozumleniyor() {
        let p = build(b"merhaba", 64);
        let pkt = TcpPacket::parse(&p).unwrap();

        assert_eq!(pkt.ip_header_len, 20);
        assert_eq!(pkt.tcp_header_len, 20);
        assert_eq!(pkt.src_port, 54321);
        assert_eq!(pkt.dst_port, 443);
        assert_eq!(pkt.seq, 0xDEADBEEF);
        assert_eq!(pkt.ttl, 64);
        assert_eq!(pkt.payload(&p), b"merhaba");
    }

    /// Sağlama toplamının tanımlayıcı özelliği: doğru bir başlığın kendi
    /// toplamıyla birlikte toplamı sıfırdır.
    #[test]
    fn ipv4_saglama_toplami_dogrulaniyor() {
        let p = build(b"x", 64);
        assert!(ipv4_checksum_valid(&p, 20));
    }

    #[test]
    fn tcp_saglama_toplami_dogrulaniyor() {
        let p = build(b"merhaba dunya", 64);
        let pkt = TcpPacket::parse(&p).unwrap();

        // Aynı sözde başlıkla yeniden toplandığında sonuç sıfır olmalı.
        let mut pseudo: u32 = 0;
        for pair in [
            [pkt.src[0], pkt.src[1]],
            [pkt.src[2], pkt.src[3]],
            [pkt.dst[0], pkt.dst[1]],
            [pkt.dst[2], pkt.dst[3]],
            [0, PROTO_TCP],
            ((p.len() - 20) as u16).to_be_bytes(),
        ] {
            pseudo += u32::from(u16::from_be_bytes(pair));
        }
        assert_eq!(checksum_with(&p[20..], pseudo), 0);
    }

    /// TTL değişince IPv4 toplamı bozulur ve düzeltilmelidir.
    #[test]
    fn ttl_degisince_toplam_yeniden_hesaplanmali() {
        let mut p = build(b"x", 64);
        assert!(ipv4_checksum_valid(&p, 20));

        p[8] = 5;
        assert!(
            !ipv4_checksum_valid(&p, 20),
            "toplam kendiliğinden bozulmalıydı"
        );

        fix_ipv4_checksum(&mut p, 20).unwrap();
        assert!(ipv4_checksum_valid(&p, 20));
        assert_eq!(p[8], 5);
    }

    #[test]
    fn bilinen_vektor() {
        // RFC 1071 örneği.
        assert_eq!(
            checksum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]),
            0x220d
        );
    }

    #[test]
    fn tek_bayt_toplami_panik_yapmiyor() {
        assert_eq!(checksum(&[0xFF]), checksum(&[0xFF, 0x00]));
        let _ = checksum(&[]);
    }

    #[test]
    fn tcp_olmayan_paket_reddediliyor() {
        let mut p = build(b"x", 64);
        p[9] = 17; // UDP
        assert!(TcpPacket::parse(&p).is_none());
    }

    #[test]
    fn parcalanmis_paket_reddediliyor() {
        let mut p = build(b"x", 64);
        p[6] = 0x00;
        p[7] = 0x10; // sıfır olmayan parça konumu
        assert!(TcpPacket::parse(&p).is_none());
    }

    #[test]
    fn ipv6_reddediliyor() {
        let mut p = build(b"x", 64);
        p[0] = 0x60;
        assert!(TcpPacket::parse(&p).is_none());
    }

    /// Uzunluk alanı tampondan büyükse paket bozuktur; okumaya kalkışılmamalı.
    #[test]
    fn yalanci_uzunluk_reddediliyor() {
        let mut p = build(b"x", 64);
        p[2..4].copy_from_slice(&9999u16.to_be_bytes());
        assert!(TcpPacket::parse(&p).is_none());
    }

    #[test]
    fn kirpilmis_paket_panik_yapmiyor() {
        let p = build(b"merhaba dunya bu bir testtir", 64);
        for n in 0..p.len() {
            let _ = TcpPacket::parse(&p[..n]);
        }
    }

    #[test]
    fn bozulmus_baytlar_panik_yapmiyor() {
        let base = build(b"merhaba", 64);
        for i in 0..base.len() {
            for v in [0x00u8, 0x01, 0x45, 0x7F, 0xFF] {
                let mut b = base.clone();
                b[i] = v;
                if let Some(pkt) = TcpPacket::parse(&b) {
                    // Çözümlenebiliyorsa yük erişimi de güvenli olmalı.
                    let _ = pkt.payload(&b);
                }
            }
        }
    }

    #[test]
    fn bos_yuklu_paket_calisiyor() {
        let p = build(b"", 64);
        let pkt = TcpPacket::parse(&p).unwrap();
        assert_eq!(pkt.payload_len, 0);
        assert!(pkt.payload(&p).is_empty());
    }
}
