(ns oauth.client-test
  (:require [oauth.client :as oc]
            [oauth.signature :as sig] :reload-all)
  (:use clojure.test))

(deftest 
    #^{:doc "Test signing of a request."} 
  signature
  (let [c (oc/make-consumer "dpf43f3p2l4k3l03"
                            "kd94hf93k423kf44"
                            nil
                            nil
                            nil
                            :hmac-sha1)]
    (is (= (sig/sign c (sig/base-string "GET"
                                        "http://photos.example.net/photos"
                                        {:oauth_consumer_key "dpf43f3p2l4k3l03"
                                         :oauth_token "nnch734d00sl2jdk"
                                         :oauth_signature_method "HMAC-SHA1"
                                         :oauth_timestamp "1191242096"
                                         :oauth_nonce "kllo9940pd9333jh"
                                         :oauth_version "1.0"
                                         :file "vacation.jpg"
                                         :size "original"})
                     "pfkkdhi9sl3r4s00")
           "tR3+Ty81lMeYAr/Fid0kMTYa/WM="))))

(deftest
    #^{:doc "Test creation of authorization header."}
  authorization-header
  (let [c (oc/make-consumer "GDdmIQH6jhtmLUypg82g"
                            "MCD8BKwGdgPHvAuvgvz4EQpqDAtx89grbuNMRd7Eh98"
                            "https://api.twitter.com/oauth/request_token"
                            "https://api.twitter.com/oauth/access_token"
                            "https://api.twitter.com/oauth/authorize"
                            :hmac-sha1)
        ;; Ensure that the params from Twitter example are used.
        unsigned-params (merge (sig/oauth-params c)
                               {:oauth_callback "http://localhost:3005/the_dance/process_callback?service_provider_id=11"
                                :oauth_consumer_key "GDdmIQH6jhtmLUypg82g"
                                :oauth_nonce "QP70eNmVz8jvdPevU3oJD2AfF7R7odC2XJcn4XlZJqk"
                                :oauth_signature_method "HMAC-SHA1"
                                :oauth_timestamp "1272323042"
                                :oauth_version "1.0"})
        signature (sig/sign c (sig/base-string "POST"
                                               (:request-uri c)
                                               unsigned-params))
        params (assoc unsigned-params
                 :oauth_signature (sig/url-encode signature))]
    #_(is (= (println (oc/authorization-header params))
             "OAuth oauth_nonce=\"QP70eNmVz8jvdPevU3oJD2AfF7R7odC2XJcn4XlZJqk\", oauth_callback=\"http%3A%2F%2Flocalhost%3A3005%2Fthe_dance%2Fprocess_callback%3Fservice_provider_id%3D11\", oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"1272323042\", oauth_consumer_key=\"GDdmIQH6jhtmLUypg82g\", oauth_signature=\"8wUi7m5HFQy76nowoCThusfgB%2BQ%3D\", oauth_version=\"1.0\""))))
           
