# DiNgoeS

Compare website blocking effectiveness of popular public DNS servers

This tool downloads the latest feed of malicious and deceptive websites
from [hpHosts](https://hosts-file.net/) and looks up whether these websites are
blocked on popular third-party malware-blocking and anti-phishing DNS
services.

## DNS Services Supported

  * [Comodo Secure DNS](https://www.comodo.com/secure-dns/)
  * [Comodo Shield](https://shield.dome.comodo.com/)
  * [IBM Quad 9](https://www.quad9.net/)
  * [Norton ConnectSafe](https://connectsafe.norton.com/configureRouter.html)
  * [Neustar Free Recursive DNS](https://www.neustar.biz/security/dns-services/free-recursive-dns-service)
  * [OpenDNS Home](https://www.opendns.com/)
  * [SafeDNS](https://www.safedns.com/)
  * [Strongarm](https://strongarm.io/)
  * [Yandex.DNS](https://dns.yandex.com/advanced/)

## hpHosts Feeds Supported

  * **PSH** : Sites engaged in Phishing (default)
  * **EMD** : Sites engaged in malware distribution
  * **EXP** : Sites engaged in hosting, development or distribution of exploits

## Install

  * Install requirements with `pip`:

      `$ pip install -r requirements.txt`

## Usage

  * Run DiNgoeS with the following command:

      `$ python dyngoes.py`

  The CSV format report will be available in the same directory. Open in Excel
  or similar for further processing.

## Switches

  * `-o` : CSV report file name
  * `-c` : hpHosts feed: `PSH` (default), `EMD` or `EXP`
  * `-n` : Number of websites from the hpHosts feed to test (default: 500)

## Support

Contact us on Twitter at [@CryptoAUSTRALIA](https://twitter.com/CryptoAustralia)
