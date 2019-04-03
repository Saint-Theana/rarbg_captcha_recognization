#!/bin/bash
#dependency : curl busybox(tr sed grep cat) tesseract
#apt install curl tesseract

ua='Mozilla/5.0 (Linux; Android 7.1.2; ONEPLUS A5010 Build/NJH47F; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/66.0.3359.139 Mobile Safari/537.36'

echo "开始获取验证码"
round(){

data="$1";
referer="https://rarbgprx.org/threat_defence.php?defence=1&r=$r0";

value_c=$(echo $data|grep -o 'value_c = [0-9]*'|sed 's/value_c = //g')
value_sk=$(echo $data|grep -o 'value_sk = [a-zA-Z0-9]*'|sed 's/value_sk = //g')
value_i=$(echo $data|grep -o 'value_i = [0-9]*'|sed 's/value_i = //g')
r1=$(echo $data|grep -o 'value_i+&r=[0-9]*'|tr -cd [0-9])

curl -s -A "$ua" -k "https://rarbgprx.org/threat_defence_ajax.php?sk=$value_sk&cid=$value_c&i=$value_i&r=$r1&_=$(date +%s000)" -H "Referer: https://rarbgprx.org/threat_defence.php?defence=1&r=$r0"

r2=$(echo $data|grep -o 'ref_cookie+\"&r=[0-9]*\"'|tr -cd [0-9])
data=$(curl -s -i -A "$ua" -L -k "https://rarbgprx.org/threat_defence.php?defence=2&sk=$value_sk&cid=$value_c&i=$value_i&ref_cookie=rarbgprx.org&r=$r2" -H "Connection: keep-alive" -H "Upgrade-Insecure-Requests: 1" -H "Referer: $referer" -b "sk=$value_sk")


if [[  $(echo "$data"|grep "Location: /threat_defence.php?defence=nojc2&r=") != "" ]];then
r0=$(echo $data|grep -o "Location: /threat_defence.php?defence=nojc2&r=[0-9]*" |sed 's/.*r=//g')
referer="https://rarbgprx.org/threat_defence.php?defence=1&r=$r0";
fi
if [[  $(echo "$data"|grep "Location: /threat_defence.php?defence=nojc") != "" ]];then
referer="https://rarbgprx.org/threat_defence.php?defence=nojc";
fi


if [[ $(echo "$data"|grep "to retry verifying your browser") != "" ]];then
data=$(curl -s -A "$ua" -k 'https://rarbgprx.org/threat_defence.php?defence=1' -H "Referer: $referer" -b "sk=$value_sk" |tr -d "'")
round "$data";
fi


img_id=$(echo $data|grep -o "threat_captcha.php?cid=[A-Za-z_0-9]*" |sed 's/.*cid=//g')

captcha_id=$(echo $data|grep -o "captcha_id\" value=\"[a-zA-Z0-9]*"|sed 's/.*value=\"//g')


r3=$(echo $data|grep -o '<img src=\"/threat_captcha.php?cid=[0-9_A-Za-z]*&r=[0-9]*'|sed 's/.*r=//g')

r4=$(echo $data|grep -o "\"r\" value=\"[0-9]*" |sed 's/.*value=\"//g')



curl -s -A "$ua" -k "https://rarbgprx.org/threat_captcha.php?cid=$img_id&r=$r3" -H "Referer: https://rarbgprx.org/threat_defence.php?defence=2&sk=$value_sk&cid=$value_c&i=$value_i&ref_cookie=rarbgprx.org&r=$r2" -H "Accept-Encoding: gzip, deflate" -H "Accept-Language: zh-CN,en-US;q=0.9" -H "Accept: image/webp,image/apng,image/*,*/*;q=0.8" -b "sk=$value_sk" >img.png

echo "已获取验证码,开始识别";

tesseract img.png test >/dev/null 2>&1

password=$(cat test.txt|tr -cd [A-Za-z0-9])

echo "提交验证码 $password";

curl -s -A "$ua" -k -L "https://rarbgprx.org/threat_defence.php?defence=2&sk=$value_sk&cid=$value_c&i=$value_i&ref_cookie=rarbgprx.org&r=$r4&solve_string=$password&captcha_id=$captcha_id&submitted_bot_captcha=1" -H "Referer: https://rarbgprx.org/threat_defence.php?defence=2&sk=$value_sk&cid=$value_c&i=$value_i&ref_cookie=rarbgprx.org&r=$r2" -H "Connection: keep-alive" -b "sk=$value_sk" -c rarbg.cookie >/dev/null

cookie=$(cat rarbg.cookie |grep 'skt'|sed 's/.*skt//g'|sed -n 1p|tr -cd '[0-9a-zA-Z]')

if [[ $cookie == "" ]];then
echo 获取cookie失败
else 
echo 获取cookie成功,cookie: stk=$cookie
fi

exit
}

data=$(curl -s -L -i -A "$ua" -k 'https://rarbgprx.org/torrents.php?r=90494378' -H "Connection: keep-alive" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" -H "Upgrade-Insecure-Requests: 1" -H "Accept-Encoding: UTF-8" -H "Accept-Language: zh-CN,en-US;q=0.9" -c rarbg.cookie|tr -d "'")


if [[  $(echo "$data"|grep "Location: /threat_defence.php?defence=1&r=") != "" ]];then
r0=$(echo $data|grep -o "Location: /threat_defence.php?defence=1&r=[0-9]*" |sed 's/.*r=//g')
fi
if [[ $(echo "$data"|grep "Please wait while we try to verify your browser") != "" ]];then
round "$data";
fi


exit


