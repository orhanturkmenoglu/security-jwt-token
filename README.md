Bu projede, JWT token tabanlı güvenlik özelliklerini geliştirdim. Bu projede şunlar yer alıyor:

🔑 JWT token üretimi ve refresh token mekanizması
🔓 Logout işlemleri ve özel accessDeniedHandler ile güvenli kimlik doğrulama
🛡️ Özelleştirilmiş kimlik doğrulama ve doğru 401 Unauthorized yanıtı
🚫 Özelleştirilmiş 403 Forbidden hatası ile yetkilendirilmemiş erişim durumları için kullanıcı deneyimini iyileştirme
📜 Method düzeyinde yetkilendirme ile daha güvenli ve esnek bir yapı
🛠️ Geliştirme profili ile esnek yapılandırma
🔐 Özelleştirilmiş authentication provider ile kimlik doğrulama
📈 Gelişmiş Güvenlik Özellikleri

🔑 Bu projede şunlar yer alıyor:
* Kullanıcı kayıt işlemi sırasında anında refresh token ve access token üretimi.
* Sistemde giriş yapan kullanıcıların eski tokenlerinin geçerliliğinin yitirilmesi ile güvenli oturum yönetimi.
* Token süreleri dolduğunda, kullanıcıların refresh token ile yeni bir access token alabilmesi.
* Method düzeyinde yetkilendirme ile kullanıcıların rollerine göre içerik erişimi sağlanması.
