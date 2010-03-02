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

(deftest 
   #^{:doc "Test verification of signed request."} 
 verify
 (let [c { :key "dpf43f3p2l4k3l03"
           :secret "kd94hf93k423kf44"
           :signature-method :hmac-sha1}]

   (is (sig/verify "tR3+Ty81lMeYAr/Fid0kMTYa/WM=" c (sig/base-string "GET"
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
                   )
          ))
           

(deftest
  #^{:doc "Test encoding."} 
  url-encode
  (is (= "abcABC123"  (sig/url-encode "abcABC123")))
  (is (= "-._~"       (sig/url-encode "-._~")))
  (is (= "%25"        (sig/url-encode "%")))
  (is (= "%2B"        (sig/url-encode "+")))
  (is (= "%20"        (sig/url-encode " ")))
  (is (= "%26%3D%2A"  (sig/url-encode "&=*")))  
  (is (= "%0A"        (sig/url-encode "\u000A"))) 
  (is (= "%20"        (sig/url-encode "\u0020"))) 
  (is (= "%7F"        (sig/url-encode "\u007F"))) 
  (is (= "%C2%80"     (sig/url-encode "\u0080"))) 
  (is (= "%E2%9C%88"  (sig/url-encode "\u2708"))) 
  (is (= "%E3%80%81"  (sig/url-encode "\u3001"))) 
  
  )

(deftest
  #^{:doc "Test decoding."} 
  url-decode
  (is (= (sig/url-decode "abcABC123")  "abcABC123"))
  (is (= (sig/url-decode "-._~")  "-._~"))
  (is (= (sig/url-decode "%25")   "%"))
  (is (= (sig/url-decode "%2B")   "+"))
  (is (= (sig/url-decode "%20")   " "))
  (is (= (sig/url-decode "%26%3D%2A") "&=*")) 
  (is (= (sig/url-decode "%0A"      )   "\u000A"))
  (is (= (sig/url-decode "%20"      )   "\u0020"))
  (is (= (sig/url-decode "%7F"      )   "\u007F"))
  (is (= (sig/url-decode "%C2%80"   )   "\u0080"))
  (is (= (sig/url-decode "%E2%9C%88")   "\u2708"))
  (is (= (sig/url-decode "%E3%80%81")   "\u3001"))


  )
  