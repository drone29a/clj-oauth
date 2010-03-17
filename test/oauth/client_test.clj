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
    (is (= (sig/sign :hmac-sha1 c (sig/base-string "GET"
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
           
