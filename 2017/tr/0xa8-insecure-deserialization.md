# A8:2017 Güvensiz Ters Serileştirme

| Tehdit etkenleri/Saldırı vektörleri | Güvenlik zafiyeti           | Etkiler               |
| -- | -- | -- |
| Erişim Düzeyi : İstismar Edilebilirlik 1 | Yaygınlık 2 : Tespit Edilebilirlik 2 | Teknik 3 : İş |
| Hazır istismarlar altta yatan istismar kodunda değişiklik yapılmadığında nadiren çalıştığı için ters serileştirme açıklıklarının istismarı daha zor olmaktadır. | Bu açıklık [endüstri anketine](https://owasp.blogspot.com/2017/08/owasp-top-10-2017-project-update.html) dayanarak İlk 10 içerisinde yer almaktadır ve hesaplanabilir bir veriye dayanmamaktadır. Bazı araçlar ters serileştirme açıklıklarını bulabilir, ancak problemin varlığını doğrulamak için genellikle insan faktörü gerekmektedir. Bu problemi tespit etmek ve çözmek için araçlar geliştikçe, ters serileştirme için yaygınlık verisinin de artması beklenmektedir. | Ters serileştirme açıklıklarının etkileri abartılamaz. Bu açıklıklar mümkün olan en ciddi risklerden birisi olan uzaktan kod çalıştırma saldırına yol açabilmektedir. İş etkisi, uygulama ve verinin koruma gereksinimlerine göre değişmektedir. |

## Uygulama Açıklık İçeriyor Mu?

Uygulama ve API'ler, eğer saldırgan tarafından sağlanan zararlı veya değiştirilmiş nesneleri ters serileştiriyorsa, açıklığa sahip olacaktır.

Bu açıklık iki ana saldırı türüyle sonuçlanabilmektedir:

* Ters serileştirme sırasında veya sonrasında davranış değiştirebilen sınıflar uygulamada mevcut olduğunda, saldırganın uygulama mantığını değiştirdiği veya uzaktan kod çalıştırabildiği nesne ve veri yapısı ile ilgili saldırılar.
* Mevcut veri yapılarının kullanıldığı ancak içeriğinin değiştirildiği erişim kontrolü ile ilgili saldırılar gibi tipik veri değiştirme saldırıları.

Serileştirme aşağıdaki amaçlarla uygulamalarda kullanılabilmektedir:

* Uzaktan işlem çağrısı ve işlemler arası iletişim (RPC/IPC)
* Kablo protokolleri, web servisleri, mesaj simsarları
* Ön belleğe alma/Süreklilik
* Veri tabanları, ön bellek sunucuları, dosya sistemleri
* HTTP çerezleri, HTML form parametreleri, API kimlik doğrulama tokenleri

## Nasıl Önlenir

Tek güvenli yapısal çözüm güvenilmeyen kaynaklardan serileştirilmiş nesneleri kabul etmemek veya sadece birincil veri tiplerine izin veren serileştirme ortamlarının kullanımıdır.

Bu mümkün değilse, aşağıdakilerden birisi veya birkaçı düşünülmelidir:

* Zararlı nesne oluşumunu veya veri değişimini engellemek için herhangi bir serileştirilmiş nesne üzerinde dijital imzalar gibi bütünlük kontrollerinin uygulanması.
* Genellikle kod tanımlanabilir bir sınıf seti beklediği için, nesne oluşturmadan önce ters serileştirme sırasında katı tip kısıtlamalarının zorunlu tutulması.
* Mümkün olduğu ölçüde ters serileştirilen kodun izole edilmesi ve düşük yetki gerektiren ortamlarda çalıştırılması.
* Gelen tipin beklenen tip olmadığı gibi ters serileştirme istisnaları ve başarısızlıkları loglanmalı veya ters serileştirme istisna atmalıdır.
* Ters serileştirme yapan konteyner veya sunuculardan gelen ve bunlardan çıkan ağ bağlantılarının kısıtlanması veya izlenmesi.
* Ters serileştirmenin izlenmesi ve bir kullanıcı sürekli ters serileştirme yaptığında alarm üretilmesi.

## Örnek Saldırı Senaryoları

**Senaryo #1**: Bir React uygulaması bir takım Spring Boot mikroservislerini çağırmaktadır. Programcılar fonksiyonel programcılar olarak, kodlarının değişmez olduğundan emin olmaya çalışmıştır. Bunun için buldukları çözüm kullanıcı durum bilgisini nesneleştirmek ve her bir istekte tekrar gönderip almaktır. Saldırgan "R00" Java nesnesi imzasını fark edebilir ve Java Serial Killer aracını kullanarak uygulama sunucusu üzerinde uzaktan kod çalıştırabilir.

**Senaryo #2**: Bir PHP formu, kullanıcının kullanıcı ID değerini, rolünü, parola özetini ve diğer durum bilgilerini taşıyan bir "süper" çerez kaydetmek için PHP nesne serileştirmesini kullanmaktadır: 

`a:4:{i:0;i:132;i:1;s:7:"Mallory";i:2;s:4:"user";i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}`

Saldırgan serileştirilen nesneyi yönetici hakları elde etmek için değiştirebilecektir:

`a:4:{i:0;i:1;i:1;s:5:"Alice";i:2;s:5:"admin";i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}`

## Kaynaklar

### OWASP

* [OWASP Kopya Kağıdı: Ters Serileştirme](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
* [OWASP Proaktif Kontroller: Tüm Girdilerin Doğrulanması](https://owasp.org/www-project-proactive-controls/v3/en/c5-validate-inputs)
* [OWASP Uygulama Güvenliği Doğrulama Standardı: TBA](https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x11-V2-Authentication.md)
* [OWASP AppSecEU 2016: Surviving the Java Deserialization Apocalypse](https://speakerdeck.com/pwntester/surviving-the-java-deserialization-apocalypse)
* [OWASP AppSecUSA 2017: Friday the 13th JSON Attacks](https://speakerdeck.com/pwntester/friday-the-13th-json-attacks)

### Dış Kaynaklar

* [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
* [Java Unmarshaller Security](https://github.com/mbechler/marshalsec)
* [OWASP AppSec Cali 2015: Marshalling Pickles](https://frohoff.github.io/appseccali-marshalling-pickles/)
