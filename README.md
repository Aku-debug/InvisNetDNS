# 🔄 Advanced Packet Manipulator & Bypass Tool

Bu proje, Windows platformu üzerinde çalışan gelişmiş bir ağ bypass ve paket manipülasyon aracıdır. Raw socket kullanarak gelen paketleri yakalar, içeriğini analiz eder ve çeşitli tekniklerle manipüle ederek tekrar gönderir. Ayrıca analiz araçlarını tespit edip önlem alabilir. Ağ yönlendirme, DNS yanıltma ve HTTP başlık düzenleme gibi işlemleri de destekler.

## 🚀 Özellikler

- 🔍 **Paket Yakalama (Sniffing):** Raw socket ile gelen IP paketlerini analiz eder.
- 🧪 **HTTP Başlık Manipülasyonu:** `User-Agent` ve `Host` gibi HTTP başlıklarını değiştirir.
- 🎭 **DNS Maskesi:** DNS sorgularını rastgele ID ve değişmiş domain adları ile yeniden düzenler.
- 🔄 **TCP Başlık Değiştirme:** TCP sequence, ack ve window size bilgilerini değiştirir.
- 🕵️ **Analiz Aracı Tespiti:** `Wireshark`, `Fiddler`, `ProcessHacker`, `Procmon` gibi araçları kontrol eder ve varsa çalışmayı durdurur.
- 🔧 **TCP/IP Sıfırlama:** `netsh` komutları ile Winsock ve IP yapılandırmalarını sıfırlar.
- 🌐 **Ağ Arayüzü Seçimi:** Sistem üzerindeki ağ arabirimlerinden otomatik seçim yapar.
- 🧠 **Domain Karartma:** Popüler domain’leri (örneğin `google.com`) sahte alt domain’lere yönlendirir (`abc12345.google.com` gibi).

## 🧠 Çalışma Prensibi

HER BILGISAYAR DA CALISMAYABILIR!!!!

1. ⛔ Analiz araçları taranır. Tespit edilirse uygulama çalışmaz.
2. 🔄 DNS önbelleği temizlenir ve TCP/IP stack resetlenir.
3. 🌐 Ağ arayüzleri alınır ve kullanılacak IP seçilir.
4. 🧰 Raw socket ile gelen paketler dinlenir (`SOCK_RAW` + `RCVALL`).
5. ✂️ Yakalanan paketler türüne göre:
   - TCP başlığı değiştirilir (sequence, ack, timestamp),
   - HTTP başlıkları yeniden yazılır,
   - DNS içerikleri manipüle edilir.
6. 📤 Manipüle edilmiş paket tekrar ağ üzerinden gönderilir.
7. 🧹 Uygulama sonlandırıldığında kaynaklar düzgünce temizlenir.

## ⚙️ Gereksinimler

- 🪟 Windows işletim sistemi  
- 🛡️ Yönetici (admin) yetkileri  
- 🧵 Raw socket desteği (genellikle sadece admin modda aktif olur)

## ⚠️ Uyarı

🔐 Bu yazılım, sadece **eğitim** ve **güvenlik testi** amaçlıdır.  
İzinsiz ağ manipülasyonu etik dışıdır ve **yasal sonuçlar doğurabilir**.  
Lütfen yalnızca **kendi sistemlerinizde** kullanınız.

## 👨‍💻 Katkıda Bulun

İyileştirme önerilerinizi, pull request’lerinizi ve issue’larınızı memnuniyetle karşılıyoruz! 💡
