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
      :oauth_signature "wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D"
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
  (is (= (os/oauth-params {:header {}}) nil))
  (is (= (os/oauth-params {:header {:authorize "Basic realm=\"Secure Area\""}}) nil))
  (is (= (os/oauth-params {:header 
    { :authorize "OAuth realm=\"http://sp.example.com/\", oauth_consumer_key=\"0685bd9184jfhq22\", oauth_token=\"ad180jjd733klru7\", oauth_signature_method=\"HMAC-SHA1\", oauth_signature=\"wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D\", oauth_timestamp=\"137131200\", oauth_nonce=\"4572616e48616d6d65724c61686176\",oauth_version=\"1.0\""}}) 
    { :oauth_consumer_key "0685bd9184jfhq22"
      :oauth_token "ad180jjd733klru7"
      :oauth_signature_method "HMAC-SHA1"
      :oauth_signature "wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D"
      :oauth_timestamp "137131200"
      :oauth_nonce "4572616e48616d6d65724c61686176"
      :oauth_version "1.0"
    }))
  )