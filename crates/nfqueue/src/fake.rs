//! Düşük TTL'li sahte paket üretimi.
//!
//! ## Yöntem
//!
//! Giden gerçek ClientHello paketini görünce, ondan önce **aynı sıra
//! numarasını taşıyan sahte bir kopya** gönderiyoruz. Sahte kopyanın TTL'i
//! düşüktür: araya giren inceleme donanımına ulaşır ama gerçek sunucuya
//! varmadan yolda ölür.
//!
//! ```text
//! biz ──[sahte, TTL 5, zararsız alan adı]──> DPI ──X  (TTL bitti)
//! biz ──[gerçek, TTL 64, asıl alan adı ]──> DPI ────> sunucu
//! ```
//!
//! İnceleme donanımı akıştaki o konum için kararını sahte pakete bakarak
//! verir; arkasından gelen gerçek paketi aynı konumda beklemediği için
//! eşleştiremez. Sunucu yalnızca gerçek paketi görür.
//!
//! ## Neden yerel proxy bunu yapamaz
//!
//! TTL, IP başlığında yaşar. Kullanıcı alanındaki bir soket paket başlığına
//! dokunamaz; bu yüzden bu teknik yalnızca ham paket erişimiyle mümkündür.

use trdpi_proxy::clienthello;

use crate::packet::{self, TcpPacket};

/// Sahte pakette kullanılacak zararsız alan adı.
///
/// Uzunluk eşleşmesi için gerektiği kadar tekrarlanır: sahte paketin
/// gerçeğiyle **aynı uzunlukta** olması, akış konumlarının hizalı kalmasını
/// sağlar.
pub const DEFAULT_FAKE_HOST: &[u8] = b"www.microsoft.com";

/// Sahte paket üretimi başarısız olduğunda sebebi.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FakeError {
    /// Paket IPv4 + TCP olarak çözümlenemedi.
    #[error("paket çözümlenemedi")]
    NotParsable,
    /// Yük bir ClientHello değil.
    #[error("ClientHello değil")]
    NotClientHello,
    /// Sağlama toplamı yazılamadı.
    #[error("sağlama toplamı hesaplanamadı")]
    ChecksumFailed,
}

/// Verilen gerçek paketten düşük TTL'li sahte bir kopya üretir.
///
/// Dönen paket gerçeğiyle **aynı uzunlukta ve aynı sıra numarasındadır**;
/// yalnızca TTL'i ve SNI alanı farklıdır.
pub fn build_fake(real: &[u8], ttl: u8, fake_host: &[u8]) -> Result<Vec<u8>, FakeError> {
    let pkt = TcpPacket::parse(real).ok_or(FakeError::NotParsable)?;

    let payload = pkt.payload(real);
    let sni = clienthello::find_sni(payload).ok_or(FakeError::NotClientHello)?;

    let mut fake = real.to_vec();
    fake[8] = ttl;

    // SNI'yı yükün içinde bulduk; tampondaki mutlak konuma çeviriyoruz.
    let start = pkt.payload_offset + sni.range.start;
    let end = pkt.payload_offset + sni.range.end;
    let host_bytes = fake.get_mut(start..end).ok_or(FakeError::NotParsable)?;

    // Uzunluğu koru: zararsız adı gerektiği kadar tekrarla.
    let source = if fake_host.is_empty() {
        DEFAULT_FAKE_HOST
    } else {
        fake_host
    };
    for (i, b) in host_bytes.iter_mut().enumerate() {
        *b = source[i % source.len()];
    }

    packet::fix_tcp_checksum(&mut fake, &pkt).ok_or(FakeError::ChecksumFailed)?;
    packet::fix_ipv4_checksum(&mut fake, pkt.ip_header_len).ok_or(FakeError::ChecksumFailed)?;

    Ok(fake)
}

/// Bu paketin sahte kopya üretmeye değer olup olmadığı.
///
/// Yalnızca ClientHello taşıyan paketlere dokunuyoruz; diğer her şey
/// olduğu gibi geçer.
pub fn should_fake(buf: &[u8]) -> bool {
    TcpPacket::parse(buf)
        .map(|pkt| clienthello::is_client_hello(pkt.payload(buf)))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::tests_support::build;

    /// Test için gerçekçi bir ClientHello yükü.
    fn hello(sni: &str) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0xAA; 32]);
        body.push(0); // session_id yok
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x02]);
        body.extend_from_slice(&[0x01, 0x00]);

        let host = sni.as_bytes();
        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
        sni_ext.push(0x00);
        sni_ext.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(host);

        let mut ext = Vec::new();
        ext.extend_from_slice(&0x0000u16.to_be_bytes());
        ext.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni_ext);

        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let mut hs = vec![0x01];
        let l = body.len();
        hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        hs.extend_from_slice(&body);

        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn sahte_paket_ayni_uzunluk_ve_sirada() {
        let real = build(&hello("discord.com"), 64);
        let fake = build_fake(&real, 5, DEFAULT_FAKE_HOST).unwrap();

        assert_eq!(fake.len(), real.len(), "uzunluk değişmemeli");

        let rp = TcpPacket::parse(&real).unwrap();
        let fp = TcpPacket::parse(&fake).unwrap();
        assert_eq!(fp.seq, rp.seq, "sıra numarası aynı olmalı");
        assert_eq!(fp.src_port, rp.src_port);
        assert_eq!(fp.dst_port, rp.dst_port);
        assert_eq!(fp.src, rp.src);
        assert_eq!(fp.dst, rp.dst);
    }

    #[test]
    fn ttl_dusuruluyor() {
        let real = build(&hello("discord.com"), 64);
        let fake = build_fake(&real, 5, DEFAULT_FAKE_HOST).unwrap();

        assert_eq!(TcpPacket::parse(&fake).unwrap().ttl, 5);
        assert_eq!(
            TcpPacket::parse(&real).unwrap().ttl,
            64,
            "gerçek paket bozulmamalı"
        );
    }

    /// En kritik değişmez: TTL ve yük değişti, iki sağlama toplamı da doğru
    /// olmalı. Yanlışsa paket ilk yönlendiricide sessizce düşer.
    #[test]
    fn her_iki_saglama_toplami_dogru() {
        let real = build(&hello("discord.com"), 64);
        let fake = build_fake(&real, 3, DEFAULT_FAKE_HOST).unwrap();
        let fp = TcpPacket::parse(&fake).unwrap();

        assert!(packet::ipv4_checksum_valid(&fake, fp.ip_header_len));

        let mut pseudo: u32 = 0;
        for pair in [
            [fp.src[0], fp.src[1]],
            [fp.src[2], fp.src[3]],
            [fp.dst[0], fp.dst[1]],
            [fp.dst[2], fp.dst[3]],
            [0, packet::PROTO_TCP],
            ((fake.len() - fp.ip_header_len) as u16).to_be_bytes(),
        ] {
            pseudo += u32::from(u16::from_be_bytes(pair));
        }
        assert_eq!(
            packet::checksum_for_test(&fake[fp.ip_header_len..], pseudo),
            0,
            "TCP sağlama toplamı yanlış"
        );
    }

    #[test]
    fn gercek_alan_adi_sahte_pakette_gorunmuyor() {
        let real = build(&hello("discord.com"), 64);
        let fake = build_fake(&real, 5, DEFAULT_FAKE_HOST).unwrap();

        assert!(
            fake.windows(11).all(|w| w != b"discord.com"),
            "sahte paket gerçek alan adını taşıyor"
        );
        assert!(
            real.windows(11).any(|w| w == b"discord.com"),
            "gerçek paket bozulmuş"
        );
    }

    #[test]
    fn kisa_ve_uzun_alan_adlari_calisiyor() {
        for host in ["a.co", "discord.com", "cok-uzun-bir-alan-adi.example.test"] {
            let real = build(&hello(host), 64);
            let fake = build_fake(&real, 5, DEFAULT_FAKE_HOST).unwrap();

            assert_eq!(fake.len(), real.len(), "{host}");
            assert!(
                !fake.windows(host.len()).any(|w| w == host.as_bytes()),
                "{host} sahte pakette görünüyor"
            );
        }
    }

    #[test]
    fn client_hello_olmayan_paket_reddediliyor() {
        let real = build(b"GET / HTTP/1.1\r\n\r\n", 64);
        assert_eq!(
            build_fake(&real, 5, DEFAULT_FAKE_HOST).unwrap_err(),
            FakeError::NotClientHello
        );
        assert!(!should_fake(&real));
    }

    #[test]
    fn should_fake_dogru_ayirt_ediyor() {
        assert!(should_fake(&build(&hello("discord.com"), 64)));
        assert!(!should_fake(&build(b"", 64)));
        assert!(!should_fake(b"cop"));
    }

    #[test]
    fn bozuk_paket_panik_yapmiyor() {
        let base = build(&hello("discord.com"), 64);
        for i in 0..base.len().min(120) {
            for v in [0x00u8, 0x16, 0x45, 0xFF] {
                let mut b = base.clone();
                b[i] = v;
                let _ = build_fake(&b, 5, DEFAULT_FAKE_HOST);
                let _ = should_fake(&b);
            }
        }
    }

    #[test]
    fn bos_sahte_ad_varsayilana_dusuyor() {
        let real = build(&hello("discord.com"), 64);
        let fake = build_fake(&real, 5, b"").unwrap();
        assert_eq!(fake.len(), real.len());
    }
}
