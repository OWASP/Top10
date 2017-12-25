# アプリケーションのセキュリティリスク

## アプリケーションのセキュリティリスクについて
攻撃者はアプリケーションを介して様々な経路で、ビジネスや組織に被害を及ぼします。それぞれの経路は、注意を喚起すべき深刻なリスクやそれほど深刻ではないリスクを表しています。

![0x10-risk-1](images/0x10-risk-1.png)

これらの経路の中には、検出や悪用がしやすいものもあれば、しにくいものもあります。同様に、引き起こされる被害についても、ビジネスに影響がないこともあれば、破産にまで追い込まれることもあります。組織におけるリスクを判断するためにまず、それぞれの「脅威エージェント」、「攻撃手法」、「セキュリティ上の弱点」などに関する可能性を評価し、組織に対する「技術面への影響」と「ビシネス面への影響」を考慮してみてください。最後に、これら全てのファクターに基づき、リスクの全体像を決定してください。


## あなたにとってのリスク

OWASP Top 10は、多様な組織のために、最も重大なウェブアプリケーションセキュリティリスクを特定することに焦点を当てています。これらのリスクに関して、以下に示すOWASP Risk Rating Methodologyに基づいた格付手法により、発生可能性と技術面への影響について評価します。  

![0x10-risk-2](images/0x10-risk-2.png)

[OWASP Risk Rating Methodology](https://www.owasp.org/index.php/OWASP_Risk_Rating_Methodology)では、各リスクに関する発生可能性や影響度を算出するリスク格付方法をアップデートしています。詳細は「リスクに関する注記」を参照してください。
各組織はユニークであるため、侵害において脅威を引き起こすアクター、目標、影響度も各組織でユニークでしょう。
公共の利益団体において公開情報をCMSにより管理している場合や、医療システムにおいてセンシティブな健康記録を管理するために同じようなCMSを利用している場合に、同じソフトウェアであっても脅威を引き起こすアクターやビジネスへの影響は大きく異なります。そのため、脅威エージェントやビジネスへの影響に基づき、組織におけるリスクを理解することが重要です。
Top 10におけるリスクは、理解の促進及び混乱を招くことを避けるため、可能な限りCWEに沿った名称としています。

## 参考資料
### OWASP
* [OWASP Risk Rating Methodology](https://www.owasp.org/index.php/OWASP_Risk_Rating_Methodology)
* [Article on Threat/Risk Modeling](https://www.owasp.org/index.php/Threat_Risk_Modeling)

### その他
* [ISO 31000: Risk Management Std](https://www.iso.org/iso-31000-risk-management.html)
* [ISO 27001: ISMS](https://www.iso.org/isoiec-27001-information-security.html)
* [NIST Cyber Framework (US)](https://www.nist.gov/cybersecurity-framework)
* [ASD Strategic Mitigations (AU)](https://www.asd.gov.au/infosec/mitigationstrategies.htm)
* [NIST CVSS 3.0](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator)
* [Microsoft Threat Modelling Tool](https://www.microsoft.com/en-us/download/details.aspx?id=49168)
