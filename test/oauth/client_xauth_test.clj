(ns oauth.client-xauth-test
  (:require [oauth.client :as oc]
            [oauth.signature :as sig])
  (:use clojure.test))

(def consumer (oc/make-consumer "JvyS7DO2qd6NNTsXJ4E7zA"
                                "9z6157pUbOBqtbm0A0q4r29Y2EYzIHlUwbF4Cl9c"
                                "https://api.twitter.com/oauth/request_token"
                                "https://api.twitter.com/oauth/access_token"
                                "https://api.twitter.com/oauth/authorize"
                                :hmac-sha1))

(deftest xauth-base-string-test
  (is (= "POST&https%3A%2F%2Fapi.twitter.com%2Foauth%2Faccess_token&oauth_consumer_key%3DJvyS7DO2qd6NNTsXJ4E7zA%26oauth_nonce%3D6AN2dKRzxyGhmIXUKSmp1JcB4pckM8rD3frKMTmVAo%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1284565601%26oauth_version%3D1.0%26x_auth_mode%3Dclient_auth%26x_auth_password%3Dtwitter-xauth%26x_auth_username%3Doauth_test_exec"
         (sig/base-string "POST" "https://api.twitter.com/oauth/access_token"
                          (merge {:x_auth_username "oauth_test_exec"
                                  :x_auth_password "twitter-xauth"
                                  :x_auth_mode "client_auth"}
                                 {:oauth_consumer_key "JvyS7DO2qd6NNTsXJ4E7zA"
                                  :oauth_nonce "6AN2dKRzxyGhmIXUKSmp1JcB4pckM8rD3frKMTmVAo"
                                  :oauth_timestamp "1284565601"
                                  :oauth_version "1.0"
                                  :oauth_signature_method "HMAC-SHA1"})))))

(deftest build-xauth-access-token-request-test
  (is (= {:form-params {:x_auth_username "oauth_test_exec",
                        :x_auth_password "twitter-xauth",
                        :x_auth_mode "client_auth"},
          :headers {"Authorization" "OAuth oauth_consumer_key=\"JvyS7DO2qd6NNTsXJ4E7zA\", oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"1284565601\", oauth_nonce=\"6AN2dKRzxyGhmIXUKSmp1JcB4pckM8rD3frKMTmVAo\", oauth_version=\"1.0\", oauth_signature=\"1L1oXQmawZAkQ47FHLwcOV%2Bkjwc%3D\""}}
         (oc/build-xauth-access-token-request consumer
                                              "oauth_test_exec"
                                              "twitter-xauth"
                                              "6AN2dKRzxyGhmIXUKSmp1JcB4pckM8rD3frKMTmVAo"
                                              1284565601))))
