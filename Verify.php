<?php

/**【友盟+】智能认证 U-Verify（一键登录） 一键登录
 * Class Verify
 */
class Verify
{



    protected $appKey='*********';//阿里云市场购买应用的appKey

    protected $appSecret='*********'; //阿里云市场购买应用的appSecret

    protected $um_appkey='*********'; //友盟的appkey

    /**
     * 一建登录
     * $mobile_token  客户端传的token
     * $um_appkey     友盟appkey
     */
    public function oneclick_login($mobile_token,$um_appkey)
    {
        $host = "https://verify5.market.alicloudapi.com";
        $path = "/api/v1/mobile/info";
        $method = "POST";
        $accept = "application/json";
        $content_type = "application/json; charset=UTF-8";
        $appKey = $this->appKey; //阿里云市场购买应用的appKey
        $appSecret = $this->appSecret; //阿里云市场购买应用的appSecret
        $header["Accept"] = $accept;
        $header["Content-Type"] = $content_type;
        $header["X-Ca-Version"] = "1";
        $header["X-Ca-Signature-Headers"] = "X-Ca-Key,X-Ca-Nonce,X-Ca-Stage,X-Ca-Timestamp,X-Ca-Version";
        $header["X-Ca-Stage"] = "RELEASE";
        $header["X-Ca-Key"] = $appKey; //请求的阿里云AppKey
        $header["X-Ca-Timestamp"] = strval(time() * 1000);
        mt_srand((double) microtime() * 10000);
        $uuid = strtoupper(md5(uniqid(rand(), true)));
        $header["X-Ca-Nonce"] = strval($uuid);
        //Headers
        $headers = "X-Ca-Key:" . $header["X-Ca-Key"] . "\n";
        $headers .= "X-Ca-Nonce:" . $header["X-Ca-Nonce"] . "\n";
        $headers .= "X-Ca-Stage:" . $header["X-Ca-Stage"] . "\n";
        $headers .= "X-Ca-Timestamp:" . $header["X-Ca-Timestamp"] . "\n";
        $headers .= "X-Ca-Version:" . $header["X-Ca-Version"] . "\n";
        //Url
        $url = $path . "?appkey=" . $um_appkey; //appkey为用户在友盟注册的应用分配的appKey,token和phoneNumber是app传过来的值
        //sign
        $str_sign = $method . "\n";
        $str_sign .= $accept . "\n";
        $str_sign .= "\n";
        $str_sign .= $content_type . "\n";
        $str_sign .= "\n";
        $str_sign .= $headers;
        $str_sign .= $url;
        $sign = base64_encode(hash_hmac('sha256', $str_sign, $appSecret, true)); //secret为APP的密钥
        $header['X-Ca-Signature'] = $sign;
        $post_data['token'] = $mobile_token;
        //curl
        $curl_url = $host . $path . "?appkey=" . $um_appkey; //appkey为用户在友盟注册的应用分配的appKey
        $headerArray = array();
        foreach ($header as $k => $v) {
            array_push($headerArray, $k . ":" . $v);
        }
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($curl, CURLOPT_URL, $curl_url);
        curl_setopt($curl, CURLOPT_HTTPHEADER, $headerArray);
        curl_setopt($curl, CURLOPT_FAILONERROR, false);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_TIMEOUT, 10);
        curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 5);
        curl_setopt($curl, CURLOPT_HEADER, true);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($curl, CURLOPT_POST, 1);
        curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($post_data));
        $result = curl_exec($curl);
        // 获得响应结果里的：头大小
        $headerSize = curl_getinfo($curl, CURLINFO_HEADER_SIZE);
        // 根据头大小去获取数据信息
        $header = substr($result,$headerSize);
        curl_close($curl);
        $result=json_decode($header,true);
        if ($result['success']==false){
            return false;
        }else{
            return $result;
        }
    }
}