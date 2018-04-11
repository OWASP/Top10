# + Veri Metadolojisi ve Veriler

OWASP Projesi Zirvesi'nde, aktif katılımcılar ve topluluk üyeleri, kısmen nicel veri ile kısmen de nitel anketler ile tanımlanan bir sıralama ile 2 yeni açıklık sınıfı ile bir açıklık listelemesi üzerinde ortak karar aldılar.
 
## Endüstri Anketi

Anket için, eskiden "daha yeni çıkmış" olarak belirlenen veya İlk 10 e-posta listesinde 2017 RC1'a geri bildirim olarak gönderilen açıklık kategorilerini topladık. Bunları sıralanmış bir ankete yerleştirdik ve katılımcılardan Owasp İlk 10 - 2017 içerisinde yer alması gerektiğini düşündükleri ilk dört açıklığı sıralamasını istedik. Anket 2 Ağustos - 18 Eylül 2017 tarihleri arasında açık kaldı. 516 cevap toplandı ve açıklıklar sıralandı.

| sıralama | Anket Açıklık Kategorileri | Skor |
| -- | -- | -- |
| 1 | Gizli Bilgilerin İfşası ('Gizlilik İhlali') [CWE-359] | 748 |
| 2 | Kriptografik Eksiklikler [CWE-310/311/312/326/327]| 584 |
| 3 | Güvenilmeyen Verinin Ters Serileştirilmesi [CWE-502] | 514 |
| 4 | Kullanıcı Tarafından Kontrol Edilen Anahtar İle Yetki Kaçağı (IDOR & Path Traversal) [CWE-639] | 493 |
| 5 | Yetersiz Loglama ve İzleme [CWE-223 / CWE-778]| 440 |

Gizli Bilgilerin İfşası açık bir şekilde en yüksek sırada olan açıklıktır, ancak mevcut **A3:2017-Hassas Bilgi İfşası** maddesine ilave bir nokta olarak kolaylıkla uymaktadır. Kriptografik Eksiklikler Hassas Bilgi İfşası kategorisine uyabilmektedir. Güvensiz ters serileştirme üçüncü sırayı almıştır, bu yüzden risk derecelendirmesinden sonra **A8:2017-Güvensiz Ters Serileştirme** olarak İlk 10 listesine eklenmiştir. Dördüncü sırada bulunan Kullanıcı Kontrollü Anahtar **A5:2017-Yetersiz Erişim Kontrolü** kategorisi altında yer almıştır; bu açıklığın ankette yüksek sıralarda çıkması, yetkilendirme açıklıkları ile ilgili çok veri bulunmadığı için dikkat çekicidir. Ankette beşinci sırada yer alan açıklık, İlk 10 listesi için iyi bir madde olduğuna inandığımız ve bu yüzden **A10:2017-Yetersiz Loglama & İzleme** olarak eklenen Yetersiz Loglama ve İzlemedir. Uygulamaların nelerin bir saldırı olabileceğini tanımlayabilmesini gerektiren ve uygun loglama, alarm üretme, yükselme ve cevap verme süreçlerini yürütmek zorunda kaldığı bir noktaya geçtik.

## Açık Veri Talebi

Geleneksel olarak, toplanan ve analiz edilen veri daha çok yaygınlık verisidir: test edilen uygulamalarda kaç tane açıklık bulunmuştur. Bilindiği üzere, araçlar geleneksel olarak bulunan bir açıklığın görüldüğü tüm yerleri raporlarken, insanlar geleneksel olarak birkaç örnek ile beraber tek bir bulgu raporlamaktadır. Bu durum iki türdeki raporlamaların karşılaştırılabilir bir şekilde birleştirilmesini son derece zor kılmaktadır.

2017 için, görülme oranı belirli bir açıklık türünü içeren ve verilen veri seti içerisinde bulunan uygulama sayısı ile hesaplanmıştır. Daha büyük iştirakçilerden gelen veri iki görünüm ile sağlanmıştır. Birincisi bulunan bir açıklığın bulunduğu her bir yerin sayılması ile yapılan geleneksel yaygınlık türündeyken, ikincisi açıklığın (bir veya daha fazla kez) bulunduğu uygulamaların sayısıdır. Mükemmel olmasa da, bu İnsan Destekli Araçlardan ve Araç Destekli İnsanlardan toplanan veriler arasında bir karşılaştırma yapabilme imkanı sunmuştur. Ham veriler ve analiz çalışmasına [Github üzerinden erişebilirsiniz](https://github.com/OWASP/Top10/tree/master/2017/datacall). Bu ilave yapıyı İlk 10 listesinin ileriki sürümleri için genişletmeyi düşünüyoruz.

Veri talebi için kırkdan fazla gönderim aldık ve çoğu yaygınlığa odaklanan ilk veri talebinden geldiği için, 23 iştirakçiden gelen ve yaklaşık olarak 114.000 uygulamayı kapsayan veriyi kullanabildik. Mümkün olduğunda ve iştirakçiler tarafından belirtildiğinde, bir yıllık süre içerisinde bulunan yaygınlık verisini kullandık. Uygulamaların çoğunluğu birbirinden farklıydı, yine de Veracode tarafından verilen yıllık veriler arasında bazı tekrar eden uygulamaların olabileceği ihtimalini de kabul ediyoruz. Kullanılan 23 veri seti ya araç destekli insan testleri olarak belirlenmiştir ya da özel olarak insan destekli araçlar tarafından görülme oranı olarak sağlanmıştır. %100+ olaydaki seçilen verideki anomaliler en fazla %100 olacak şekilde ayarlanmıştır. Görülme oranını hesaplamak için, her bir açıklık türünü içeren toplam uygulamaların yüzdesini hesapladık. Görülme oranı İlk 10 sıralamasındaki nihai riskteki yaygınlık hesaplamasında kullanılmıştır.
