(ns oauth.signature-test
  (:require [oauth.client :as oc]
            [oauth.signature :as sig] :reload-all)
  (:use clojure.test))

(deftest
  signature-methods
  (is (= (sig/signature-methods :hmac-sha1) "HMAC-SHA1"))
  )
  
(deftest
  signature-base-string
  (let [c { :key "dpf43f3p2l4k3l03"
            :secret "kd94hf93k423kf44"
            :signature-method :hmac-sha1}
        t { :token "nnch734d00sl2jdk"
            :secret "pfkkdhi9sl3r4s00"}]
            
    (is (= (sig/base-string "GET"
                "http://photos.example.net/photos"
                {:oauth_consumer_key "dpf43f3p2l4k3l03"
                 :oauth_token "nnch734d00sl2jdk"
                 :oauth_signature_method "HMAC-SHA1"
                 :oauth_timestamp "1191242096"
                 :oauth_nonce "kllo9940pd9333jh"
                 :oauth_version "1.0"
                 :file "vacation.jpg"
                 :size "original"})
                 "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal"
                )
           )
     (is (= (sig/base-string "GET"
                 "http://photos.example.net/photos"
                 c
                 t
                 {:oauth_timestamp "1191242096"
                  :oauth_nonce "kllo9940pd9333jh"
                  :file "vacation.jpg"
                  :size "original"})
                  "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal"
                 )
            )
    ))
           
(deftest 
    #^{:doc "Test signing of a request."} 
  signature
  (let [c { :key "dpf43f3p2l4k3l03"
            :secret "kd94hf93k423kf44"
            :signature-method :hmac-sha1}]
            
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
           
