//! TR-DPI arayüzü.
//!
//! Aç, düğmeye bas, biter. Terminal yok.
//!
//! ## Neden bu araç seti
//!
//! Aynı pencereyi OpenGL tabanlı bir arayüzle de yazdık ve ölçtük:
//!
//! ```text
//!            bellek     dosya
//! FLTK       16 MB      1.1 MB
//! OpenGL    115 MB      7.3 MB
//! ```
//!
//! Karşılaştırma için aynı makinedeki dosya yöneticisi 42 MB kullanıyor.
//! Kullanıcı düşük bellek istedi; ölçüm kararı verdi.

#![deny(unsafe_code)]

mod engine;
mod update;

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fltk::{
    app,
    button::{Button, CheckButton},
    enums::{Align, Color, FrameType},
    frame::Frame,
    prelude::*,
    window::Window,
};

/// Durum kontrolü sıklığı (saniye).
///
/// Sık kontrol boşuna işlem; seyrek kontrol düğmeye basınca geç tepki.
const KONTROL_ARALIGI: f64 = 0.7;

/// Geçiş bu süre içinde tamamlanmazsa kullanıcı vazgeçmiş sayılır.
const GECIS_SINIRI: Duration = Duration::from_secs(45);

/// Kullanıcıya gösterilen durum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Durum {
    Kapali,
    Baslatiliyor,
    Acik,
    Durduruluyor,
    PkexecYok,
}

impl Durum {
    fn baslik(self) -> &'static str {
        match self {
            Self::Kapali => "Koruma kapalı",
            Self::Baslatiliyor => "Başlatılıyor...",
            Self::Acik => "Koruma açık",
            Self::Durduruluyor => "Durduruluyor...",
            Self::PkexecYok => "Kullanılamıyor",
        }
    }

    fn aciklama(self) -> &'static str {
        match self {
            Self::Kapali => "Engellenen siteler açılmayabilir.",
            Self::Baslatiliyor => "Parola penceresi açılacak.",
            Self::Acik => "Bütün uygulamalar kapsam içinde.",
            Self::Durduruluyor => "Ayarlar eski haline getiriliyor.",
            Self::PkexecYok => "Bu sistemde yönetici izni istenemiyor.",
        }
    }

    fn renk(self) -> Color {
        match self {
            Self::Acik => Color::from_rgb(80, 200, 120),
            Self::Kapali => Color::from_rgb(150, 150, 155),
            Self::PkexecYok => Color::from_rgb(220, 100, 90),
            _ => Color::from_rgb(230, 180, 80),
        }
    }

    fn dugme_yazisi(self) -> &'static str {
        match self {
            Self::Kapali => "BAŞLAT",
            Self::Acik => "DURDUR",
            Self::PkexecYok => "KULLANILAMIYOR",
            _ => "LÜTFEN BEKLE",
        }
    }

    fn dugme_etkin(self) -> bool {
        matches!(self, Self::Kapali | Self::Acik)
    }
}

/// Pencerenin değişen parçaları ve durumu.
struct Uygulama {
    durum: Durum,
    /// Geçiş beklemeye başladığımız an; iptal edilen parola penceresini yakalar.
    gecis_basladi: Option<Instant>,
    isik: Frame,
    baslik: Frame,
    aciklama: Frame,
    dugme: Button,
    /// Motor çalışırken sayaçları gösteren satır.
    ozet: Frame,
    alt_bilgi: Frame,
    guncelleme: Arc<Mutex<Option<update::UpdateStatus>>>,
}

impl Uygulama {
    /// Ekranı duruma göre tazeler.
    fn ciz(&mut self) {
        self.isik.set_color(self.durum.renk());
        self.baslik.set_label(self.durum.baslik());
        self.baslik.set_label_color(self.durum.renk());
        self.aciklama.set_label(self.durum.aciklama());
        self.dugme.set_label(self.durum.dugme_yazisi());

        if self.durum.dugme_etkin() {
            self.dugme.activate();
        } else {
            self.dugme.deactivate();
        }

        if let Some(g) = self
            .guncelleme
            .lock()
            .ok()
            .and_then(|g| g.as_ref().and_then(|s| s.message()))
        {
            self.alt_bilgi.set_label(&g);
            self.alt_bilgi
                .set_label_color(Color::from_rgb(230, 180, 80));
        }

        // Canlı özet: yalnızca motor çalışırken anlamlı.
        let metin = match engine::durum() {
            Some(d) if self.durum == Durum::Acik => format!(
                "bağlantı {} · kurulan {} · QUIC engeli aşılan {}
yöntem: {}
adres çözümleme: {}",
                d.baglanti, d.kurulan, d.quic_asilan, d.teknik, d.dns
            ),
            _ => String::new(),
        };
        self.ozet.set_label(&metin);
        self.ozet.redraw();

        self.isik.redraw();
        self.baslik.redraw();
        self.aciklama.redraw();
        self.dugme.redraw();
        self.alt_bilgi.redraw();
    }

    /// Gerçek durumu okuyup ekrandakiyle eşitler.
    fn tazele(&mut self) {
        if self.durum == Durum::PkexecYok {
            return;
        }
        let calisiyor = engine::is_running();
        match self.durum {
            Durum::Baslatiliyor if calisiyor => {
                self.durum = Durum::Acik;
                self.gecis_basladi = None;
            }
            Durum::Durduruluyor if !calisiyor => {
                self.durum = Durum::Kapali;
                self.gecis_basladi = None;
            }
            Durum::Baslatiliyor | Durum::Durduruluyor => {
                // Parola penceresi iptal edildiyse sonsuza kadar beklemeyelim.
                if self
                    .gecis_basladi
                    .is_some_and(|t| t.elapsed() > GECIS_SINIRI)
                {
                    self.durum = if calisiyor {
                        Durum::Acik
                    } else {
                        Durum::Kapali
                    };
                    self.gecis_basladi = None;
                }
            }
            // Motor dışarıdan başlatılmış ya da durdurulmuş olabilir.
            Durum::Acik if !calisiyor => self.durum = Durum::Kapali,
            Durum::Kapali if calisiyor => self.durum = Durum::Acik,
            _ => {}
        }
        self.ciz();
    }

    fn dugmeye_basildi(&mut self) {
        let sonuc = match self.durum {
            Durum::Kapali => engine::start().map(|()| Durum::Baslatiliyor),
            Durum::Acik => engine::stop().map(|()| Durum::Durduruluyor),
            _ => return,
        };
        match sonuc {
            Ok(yeni) => {
                self.durum = yeni;
                self.gecis_basladi = Some(Instant::now());
            }
            Err(e) => {
                self.aciklama.set_label(&format!("Olmadı: {e}"));
                self.aciklama.set_label_color(Color::from_rgb(220, 100, 90));
            }
        }
        self.ciz();
    }
}

fn main() {
    let uygulama = app::App::default();
    app::background(24, 26, 30);
    app::foreground(230, 232, 235);

    let mut pencere = Window::new(100, 100, 420, 380, "TR-DPI");
    pencere.set_color(Color::from_rgb(24, 26, 30));

    // Durum ışığı: yuvarlak, dolu.
    let mut isik = Frame::new(201, 30, 18, 18, "");
    isik.set_frame(FrameType::OFlatBox);

    let mut baslik = Frame::new(0, 60, 420, 32, "");
    baslik.set_label_size(20);
    baslik.set_align(Align::Center | Align::Inside);

    let mut aciklama = Frame::new(0, 94, 420, 22, "");
    aciklama.set_label_size(12);
    aciklama.set_label_color(Color::from_rgb(160, 162, 168));
    aciklama.set_align(Align::Center | Align::Inside);

    let mut dugme = Button::new(110, 150, 200, 52, "");
    dugme.set_label_size(16);
    dugme.set_color(Color::from_rgb(45, 48, 55));
    dugme.set_selection_color(Color::from_rgb(60, 64, 72));
    dugme.set_label_color(Color::from_rgb(235, 237, 240));
    dugme.set_frame(FrameType::FlatBox);

    // Motor çalışırken doldurulan canlı özet.
    let mut ozet = Frame::new(0, 210, 420, 54, "");
    ozet.set_label_size(11);
    ozet.set_label_color(Color::from_rgb(150, 152, 158));
    ozet.set_align(Align::Center | Align::Inside);

    let mut acilista = CheckButton::new(100, 272, 240, 22, " Açılışta kendiliğinden başlat");
    acilista.set_label_size(12);
    acilista.set_label_color(Color::from_rgb(180, 182, 188));
    acilista.set_value(engine::acilista_acik());

    let mut alt_bilgi = Frame::new(
        0,
        342,
        420,
        20,
        "Oyunların gerçek zamanlı bağlantısı kapsam dışı",
    );
    alt_bilgi.set_label_size(11);
    alt_bilgi.set_label_color(Color::from_rgb(110, 112, 118));
    alt_bilgi.set_align(Align::Center | Align::Inside);

    pencere.end();
    pencere.show();

    // Güncelleme kontrolü ağa çıkar; pencerenin açılmasını geciktirmesin.
    let guncelleme: Arc<Mutex<Option<update::UpdateStatus>>> = Arc::new(Mutex::new(None));
    {
        let hedef = Arc::clone(&guncelleme);
        std::thread::spawn(move || {
            let sonuc = update::check(update::VERSION_URL, Duration::from_secs(6));
            if let Ok(mut g) = hedef.lock() {
                *g = Some(sonuc);
            }
        });
    }

    let baslangic = if !engine::has_pkexec() {
        Durum::PkexecYok
    } else if engine::is_running() {
        Durum::Acik
    } else {
        Durum::Kapali
    };

    let durum = Rc::new(RefCell::new(Uygulama {
        durum: baslangic,
        gecis_basladi: None,
        isik,
        baslik,
        aciklama,
        dugme: dugme.clone(),
        ozet,
        alt_bilgi,
        guncelleme,
    }));
    durum.borrow_mut().ciz();

    {
        let d = Rc::clone(&durum);
        dugme.set_callback(move |_| d.borrow_mut().dugmeye_basildi());
    }

    {
        // Açılışta başlatma yetki istiyor; kullanıcı vazgeçerse kutuyu eski
        // haline döndürüyoruz ki ekran yalan söylemesin.
        acilista.set_callback(move |k| {
            let istenen = k.value();
            if engine::acilista_ayarla(istenen).is_err() {
                k.set_value(!istenen);
                return;
            }
            k.set_value(engine::acilista_acik());
        });
    }

    // Durumu düzenli aralıklarla gerçekle eşitle.
    {
        let d = Rc::clone(&durum);
        app::add_timeout3(KONTROL_ARALIGI, move |handle| {
            d.borrow_mut().tazele();
            app::repeat_timeout3(KONTROL_ARALIGI, handle);
        });
    }

    uygulama
        .run()
        .unwrap_or_else(|e| eprintln!("Arayüz hatası: {e}"));
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEPSI: [Durum; 5] = [
        Durum::Kapali,
        Durum::Baslatiliyor,
        Durum::Acik,
        Durum::Durduruluyor,
        Durum::PkexecYok,
    ];

    #[test]
    fn her_durumun_metni_var() {
        for d in HEPSI {
            assert!(!d.baslik().is_empty(), "{d:?}");
            assert!(!d.aciklama().is_empty(), "{d:?}");
            assert!(!d.dugme_yazisi().is_empty(), "{d:?}");
        }
    }

    /// Geçiş sırasında düğmeye basılamamalı; iki kez başlatmak çakışır.
    #[test]
    fn gecis_sirasinda_dugme_kapali() {
        for d in [Durum::Baslatiliyor, Durum::Durduruluyor, Durum::PkexecYok] {
            assert!(!d.dugme_etkin(), "{d:?}");
        }
        for d in [Durum::Kapali, Durum::Acik] {
            assert!(d.dugme_etkin(), "{d:?}");
        }
    }

    #[test]
    fn dugme_yazisi_duruma_gore_degisiyor() {
        assert_eq!(Durum::Kapali.dugme_yazisi(), "BAŞLAT");
        assert_eq!(Durum::Acik.dugme_yazisi(), "DURDUR");
    }

    /// Kullanıcı parola penceresini iptal ederse arayüz kilitli kalmamalı.
    #[test]
    fn iptal_edilen_gecis_sonsuza_kadar_beklemiyor() {
        assert!(GECIS_SINIRI <= Duration::from_secs(60));
        assert!(GECIS_SINIRI >= Duration::from_secs(20));
    }

    /// Açık ve kapalı durum aynı renkte olmamalı; renk tek başına
    /// bilgi taşımasa da ayırt edici olmalı.
    #[test]
    fn acik_ve_kapali_farkli_gorunuyor() {
        assert_ne!(Durum::Acik.renk(), Durum::Kapali.renk());
        assert_ne!(Durum::Acik.baslik(), Durum::Kapali.baslik());
    }

    /// Metinlerde teknik terim geçmemeli.
    #[test]
    fn arayuzde_teknik_terim_yok() {
        for d in HEPSI {
            let metin = format!("{} {}", d.baslik(), d.aciklama()).to_lowercase();
            for jargon in ["nftables", "nfqueue", "dns", "sni", "ttl", "proxy", "tcp"] {
                assert!(!metin.contains(jargon), "'{jargon}' geçiyor: {metin}");
            }
        }
    }
}
