# Linux Güvenlik Sertleştirme Scripti

Debian/Ubuntu tabanlı sunucular için temel güvenlik önlemlerini otomatik uygulayan script. UFW, Fail2ban, SSH sertleştirmesi, sysctl ve otomatik güvenlik güncellemeleri kurar.

**Kaynak:** [hexarch/linux-security](https://github.com/hexarch/linux-security)

---

## ⚠️ Önemli Uyarılar

1. **SSH key şart!** Script çalışmadan önce `ssh-copy-id root@sunucu` ile SSH key ekleyin. Aksi halde sunucuya tekrar bağlanamazsınız.

2. **PermitRootLogin no** varsayılan olarak root ile SSH girişini kapatır. Root ile key ile bağlanmak için `PERMIT_ROOT_LOGIN=prohibit-password` kullanın.

3. **VPN/Port yönlendirme** kullanıyorsanız `net.ipv4.ip_forward=0` sorun çıkarabilir. Scripti çalıştırmayın.

4. **Proxmox** kullanıyorsanız port 8006 (web panel) firewall'da açık olmayacak. Nginx reverse proxy ile 443 üzerinden erişim kurun.

---

## Gereksinimler

- Root erişimi
- Debian veya Ubuntu
- SSH key (önerilir)

---

## Hızlı Başlangıç

```bash
# 1. SSH key ekle (kendi bilgisayarında)
ssh-copy-id root@sunucu-ip

# 2. Scripti indir ve çalıştır
curl -O https://raw.githubusercontent.com/hexarch/linux-security/main/script.sh
chmod +x script.sh
sudo bash script.sh
```

---

## Ortam Değişkenleri

| Değişken | Varsayılan | Açıklama |
|----------|------------|----------|
| `SSH_PORT` | 22 | SSH portu |
| `PERMIT_ROOT_LOGIN` | no | `no` = root kapalı, `prohibit-password` = root sadece key ile |
| `ALLOWED_IPS` | (boş) | Virgülle ayrılmış IP listesi. Boş = tüm IPler |
| `ALLOW_HTTP` | true | 80 portu açık |
| `ALLOW_HTTPS` | true | 443 portu açık |
| `DISABLE_SSH_PASSWORD_AUTH` | false | Şifre ile SSH kapat (SSH key şart!) |
| `ENABLE_UNATTENDED_UPGRADES` | true | Otomatik güvenlik güncellemeleri |
| `ENABLE_FAIL2BAN` | true | Brute-force koruma |
| `NONINTERACTIVE` | 0 | 1 = onay sormadan devam |
| `DRY_RUN` | 0 | 1 = değişiklik yapma, sadece simülasyon |

---

## Kullanım Örnekleri

```bash
# Normal kullanım (her adımda onay ister)
sudo bash script.sh

# Sadece belirli IPlerden erişim
ALLOWED_IPS="141.98.205.37,192.168.1.100" sudo bash script.sh

# Root sadece SSH key ile giriş yapabilsin
PERMIT_ROOT_LOGIN=prohibit-password sudo bash script.sh

# Otomatik mod (onay sormaz)
NONINTERACTIVE=1 sudo bash script.sh

# Değişiklik yapmadan ne yapacağını gör
DRY_RUN=1 sudo bash script.sh

# Şifre ile SSH tamamen kapalı (sadece key)
DISABLE_SSH_PASSWORD_AUTH=true sudo bash script.sh
```

---

## Script Ne Yapar?

1. **UFW Firewall**
   - Gelen trafik varsayılan red
   - SSH (rate limit), HTTP, HTTPS açık
   - İsteğe bağlı IP kısıtlaması

2. **sysctl**
   - Reverse path filtering, ICMP redirect kapalı
   - TCP syncookies, IP forwarding kapalı
   - Kernel bilgi sızıntısı azaltma

3. **SSH**
   - PermitRootLogin, X11Forwarding, Tunneling kısıtlamaları
   - MaxAuthTries 4, LoginGraceTime 30

4. **Fail2ban**
   - SSH brute-force koruma
   - 10 dk’da 5 hata = 1 saat ban

5. **Otomatik Güncellemeler**
   - Güvenlik yamaları otomatik kurulur

6. **Yedekleme**
   - Eski config’ler `/root/security-backups-*` altında saklanır

---

## Geri Alma

Script sonunda yedek dizini gösterilir. Geri almak için:

```bash
# SSH config
cp /root/security-backups-YYYYMMDD-HHMMSS/sshd_config.bak /etc/ssh/sshd_config
systemctl restart ssh

# sysctl
cp /root/security-backups-YYYYMMDD-HHMMSS/99-hardening.conf.bak /etc/sysctl.d/99-hardening.conf
sysctl --system
```

---

## Lisans

Orijinal repo: [hexarch/linux-security](https://github.com/hexarch/linux-security)
