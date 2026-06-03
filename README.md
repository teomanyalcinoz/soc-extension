# 🛡️ SOC Assistant Extension (TracePoint)

SOC Assistant, Siber Güvenlik Operasyon Merkezleri (SOC) bünyesindeki siber güvenlik analistleri için tasarlanmış, güçlü, yapay zeka destekli bir Chrome eklentisidir. Hedefi, tehdit analizi süreçlerini tek bir merkezde toplamak, otomatize etmek ve analistlerin daha hızlı karar almasını sağlamaktır.

## ✨ Temel Özellikler

- 🔍 **Çoklu OSINT Entegrasyonu:** IP, Hash, Domain, URL ve E-Posta adreslerini tek tıkla VirusTotal, AbuseIPDB, URLScan, AlienVault OTX, Sucuri, USOM, HaveIBeenPwned, Spamhaus, ve daha birçok tehdit istihbarat kaynağında sorgular.
- 🧠 **Yapay Zeka Destekli Özetleme:** Analiz sonuçlarını LLM modelleri (Azure OpenAI / GPT-5.1 vb.) kullanarak saniyeler içinde yorumlar ve analiste yönetici özeti sunar.
- 🐚 **PowerShell Deobfuscation ve Analizi:** Gizlenmiş (obfuscated) PowerShell komut dosyalarını çözer (Base64 vb.) ve LLM kullanarak zararlı niyetleri tespit edip raporlar.
- 📑 **Sayfa Raporu Tarama (Page Scanner):** Açık olan sekmedeki bir tehdit istihbaratı sayfasını (veya makaleyi) analiz eder, içerisindeki tüm IOC'leri (IP, Hash, URL, Email) otomatik çeker, doğrular ve toplu halde repütasyon taraması yapar.
- 📊 **PDF Rapor Çıktısı:** Sayfa taramalarının veya bireysel analizlerin sonuçlarını profesyonel bir PDF raporu olarak dışa aktarmanıza olanak tanır.
- 🎯 **Dinamik SPL (Splunk) Sorgu Üretimi:** Seçilen IOC türüne ve OSINT analizinden çıkan bağlama (örn: Proxy, Firewall, WAF, Windows Sysmon) göre anında çalıştırılabilir gelişmiş Splunk (SPL) sorguları üretir.
- ⚡ **Splunk REST API Entegrasyonu:** Üretilen SPL sorgularını kopyalamanıza gerek kalmadan, tek bir butonla doğrudan kurumunuzun Splunk ortamında çalıştırabilir ve sonuçları eklenti arayüzünde tablo şeklinde görüntüleyebilirsiniz.

## 🛠️ Teknoloji Yığını

- **Frontend:** HTML, Vanilla CSS (Glassmorphism & Modern UI), Vanilla JavaScript, Chrome Extension API (Manifest V3)
- **Backend:** Python, FastAPI, Uvicorn, httpx, python-dotenv
- **AI / LLM:** Azure OpenAI
- **SIEM:** Splunk REST API

## 🚀 Kurulum ve Başlangıç

### 1. Backend Kurulumu

Backend servisi FastAPI ile yazılmıştır ve OSINT API'lerine ve LLM modellerine güvenli bir şekilde bağlanır.

```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

`.env` dosyasını `backend` dizininde oluşturun ve aşağıdaki değerleri kendi altyapınıza göre doldurun:

```env
SPLUNK_URL=https://your-splunk-instance:8089
SPLUNK_TOKEN=your-splunk-rest-token
SPLUNK_VERIFY_SSL=False

LLM_MODEL=gpt-5.1-ptu
LLM_URL=https://your-azure-openai-endpoint
LLM_API_VERSION=2024-12-01-preview
LLM_API_KEY=your-api-key
```

Uygulamayı başlatın:
```bash
python main.py
```

### 2. Frontend (Chrome Eklentisi) Kurulumu

1. Google Chrome veya Chromium tabanlı bir tarayıcı açın.
2. Adres çubuğuna `chrome://extensions/` yazarak uzantılar sayfasına gidin.
3. Sağ üst köşeden **"Geliştirici modu" (Developer mode)** seçeneğini aktif hale getirin.
4. Sol üstten **"Paketlenmemiş öğe yükle" (Load unpacked)** butonuna tıklayın.
5. Projedeki `frontend` klasörünü seçin.

## 💡 Nasıl Kullanılır?

- Eklenti butonuna tıkladığınızda açılan pencereden veya seçili bir metne sağ tıklayarak incelemek istediğiniz Hash, IP, Domain veya Email'i girebilirsiniz.
- Rapor sayfasındaysanız **"Sayfa Raporunu Tara"** butonuna basarak metindeki tüm IOC'lerin bulunup analiz edilmesini sağlayabilirsiniz.
- Oluşturulan Splunk sorgularını doğrudan çalıştırabilir veya kopyalayıp düzenleyebilirsiniz.

## 🤝 Katkıda Bulunma

Bu proje açık kaynaklı değildir, ancak yetkili geliştiriciler PR açarak katkıda bulunabilir. Tüm yeni eklemelerin `requirements.txt` ve mimariye uyumlu olduğundan emin olun.
