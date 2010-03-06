(ns oauth.server-test
  (:require [oauth.server :as os]
            [oauth.signature :as sig] :reload-all)
  (:use clojure.test))

(deftest
  #^{:doc "Test parsing of oauth header."} 
  parse-oauth-header
  (is (= (os/parse-oauth-header 
    "OAuth realm=\"http://sp.example.com/\", oauth_consumer_key=\"0685bd9184jfhq22\", oauth_token=\"ad180jjd733klru7\", oauth_signature_method=\"HMAC-SHA1\", oauth_signature=\"wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D\", oauth_timestamp=\"137131200\", oauth_nonce=\"4572616e48616d6d65724c61686176\",oauth_version=\"1.0\"")
    { :oauth_consumer_key "0685bd9184jfhq22"
      :oauth_token "ad180jjd733klru7"
      :oauth_signature_method "HMAC-SHA1"
      :oauth_signature "wOJIO9A2W5mFwDgiDvZbTSMK/PY="
      :oauth_timestamp "137131200"
      :oauth_nonce "4572616e48616d6d65724c61686176"
      :oauth_version "1.0"
    }))
  (is (= (os/parse-oauth-header "Basic realm=\"Secure Area\"") nil))
  (is (= (os/parse-oauth-header "") nil))
  (is (= (os/parse-oauth-header nil) nil))
)

(deftest
  #^{:doc "Test extraction of oauth parameters."} 
  oauth-params
  (is (= (os/oauth-params {:headers {}}) nil))
  (is (= (os/oauth-params {:headers {:authorize "Basic realm=\"Secure Area\""}}) nil))
  (is (= (os/oauth-params {:headers 
    { :authorize "OAuth realm=\"http://sp.example.com/\", oauth_consumer_key=\"0685bd9184jfhq22\", oauth_token=\"ad180jjd733klru7\", oauth_signature_method=\"HMAC-SHA1\", oauth_signature=\"wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D\", oauth_timestamp=\"137131200\", oauth_nonce=\"4572616e48616d6d65724c61686176\",oauth_version=\"1.0\""}}) 
    { :oauth_consumer_key "0685bd9184jfhq22"
      :oauth_token "ad180jjd733klru7"
      :oauth_signature_method "HMAC-SHA1"
      :oauth_signature "wOJIO9A2W5mFwDgiDvZbTSMK/PY="
      :oauth_timestamp "137131200"
      :oauth_nonce "4572616e48616d6d65724c61686176"
      :oauth_version "1.0"
    }))
  )
  
(deftest
  request-method
  (is (= "GET"    (os/request-method {:request-method :get})))
  (is (= "POST"   (os/request-method {:request-method :post})))
  (is (= "PUT"    (os/request-method {:request-method :put})))
  (is (= "DELETE" (os/request-method {:request-method :delete})))
  )

(deftest
  request-uri
  (is (= "http://photos.example.net/photos" (os/request-uri {  :server-name "photos.example.net"
                                                              :uri "/photos"
                                                              :scheme :http })))
  (is (= "https://photos.example.net/photos" (os/request-uri {  :server-name "photos.example.net"
                                                              :uri "/photos"
                                                              :scheme :https }))))
(deftest
  #^{:doc "Test generation of request to base-string"}
  request-base-string
  (is (= (os/request-base-string
    {
      :request-method :get
      :server-name "photos.example.net"
      :uri "/photos"
      :scheme :http
      :params {:file "vacation.jpg" :size "original"}
      :headers { :authorize "OAuth realm=\"http://sp.example.com/\", oauth_consumer_key=\"0685bd9184jfhq22\", oauth_token=\"ad180jjd733klru7\", oauth_signature_method=\"HMAC-SHA1\", oauth_signature=\"wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D\", oauth_timestamp=\"137131200\", oauth_nonce=\"4572616e48616d6d65724c61686176\",oauth_version=\"1.0\""}}
    )
    "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3D0685bd9184jfhq22%26oauth_nonce%3D4572616e48616d6d65724c61686176%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D137131200%26oauth_token%3Dad180jjd733klru7%26oauth_version%3D1.0%26size%3Doriginal"
  )))
  
(defn app [req]
  (if (req :oauth-token)
    {
      :status  200
      :request req
      :headers {"Content-Type" "text/plain"}
      :body    (str "oauth-token=" (req :oauth-token) "&oauth-consumer=" (req :oauth-consumer))}
    {
      :status 401
      :headers {}
      :body ""
    }))

(defn token-finder [consumer token]
  ["kd94hf93k423kf44" "pfkkdhi9sl3r4s00"])
;;   (if (and (= consumer "0685bd9184jfhq22") (= token "ad180jjd733klru7")) 
;;     ["kd94hf93k423kf44" "pfkkdhi9sl3r4s00"] nil
;;     ))

(deftest
  #^{:doc "wrap oauth"}
  wrap-oauth
  (let [oauth-app (os/wrap-oauth app token-finder) ]
    (is (= 401 ((oauth-app {}) :status)))
    (is (= 401 ((oauth-app {:headers { :authorize "Basic realm=\"Secure Area\""}}) :status)))
    (is (= 401 ((oauth-app {:headers { :authorize "OAuth realm=\"http://sp.example.com/\", oauth_consumer_key=\"0685bd9184jfhq22\", oauth_token=\"ad180jjd733klru7\", oauth_signature_method=\"HMAC-SHA1\", oauth_signature=\"fake\", oauth_timestamp=\"137131200\", oauth_nonce=\"4572616e48616d6d65724c61686176\",oauth_version=\"1.0\""}}) :status)))

    (is (= 200 ((oauth-app {
      :request-method :get
      :server-name "photos.example.net"
      :uri "/photos"
      :scheme :http
      :params {:file "vacation.jpg" :size "original"}
      :headers { :authorize "OAuth realm=\"http://sp.example.com/\", oauth_consumer_key=\"dpf43f3p2l4k3l03\", oauth_token=\"nnch734d00sl2jdk\", oauth_signature_method=\"HMAC-SHA1\", oauth_signature=\"tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D\", oauth_timestamp=\"1191242096\", oauth_nonce=\"kllo9940pd9333jh\",oauth_version=\"1.0\""}}) :status)))
  ))
  
(deftest
  #^{:doc "token request"}
  request-token
  (is (= 401 ((os/request-token {} ) :status)))
  (is (= 401 ((os/request-token {:oauth-consumer "consumer" }) :status)))
  (is (= 200 ((os/request-token {:oauth-consumer "consumer" :oauth-params {:oauth_callback "http://blabla.inv/callback"}}) :status)))
  (is (= 200 ((os/request-token {:oauth-consumer "consumer" :oauth-params {:oauth_callback "oob"}}) :status)))
  (is (= "oauth_token=token&oauth_secret=secret&oauth_callback_confirmed=true" ((os/request-token {:oauth-consumer "consumer" :oauth-params {:oauth_callback "http://blabla.inv/callback"}}) :body)))
  )
  