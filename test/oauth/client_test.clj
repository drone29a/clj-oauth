(ns oauth.client-test
  (:require [oauth.client :as oc]
            [oauth.signature :as sig] :reload-all)
  (:use clojure.test))

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
                 :oauth_signature signature)]
    ;; Can't easily test this since params are in undefined order in header.
    #_(is (= (oc/authorization-header params)
           "OAuth oauth_nonce=\"QP70eNmVz8jvdPevU3oJD2AfF7R7odC2XJcn4XlZJqk\", oauth_callback=\"http%3A%2F%2Flocalhost%3A3005%2Fthe_dance%2Fprocess_callback%3Fservice_provider_id%3D11\", oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"1272323042\", oauth_consumer_key=\"GDdmIQH6jhtmLUypg82g\", oauth_signature=\"8wUi7m5HFQy76nowoCThusfgB%2BQ%3D\", oauth_version=\"1.0\""))))
           
