(ns oauth.signature-test
  (:require [oauth.client :as oc]
            [oauth.signature :as sig] :reload-all)
  (:use clojure.test))

(def twitter-req-params
     {:oauth_callback "http://localhost:3005/the_dance/process_callback?service_provider_id=11"
      :oauth_consumer_key "GDdmIQH6jhtmLUypg82g"
      :oauth_nonce "QP70eNmVz8jvdPevU3oJD2AfF7R7odC2XJcn4XlZJqk"
      :oauth_signature_method "HMAC-SHA1"
      :oauth_timestamp "1272323042"
      :oauth_version "1.0"})

(deftest
    signature-methods
  (is (= (sig/signature-methods :hmac-sha1) "HMAC-SHA1")))

(deftest
    signature-base-string
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
         "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal"))

  (is (= (sig/base-string "GET"
                          "http://photos.example.net/photos"
                          {:key "dpf43f3p2l4k3l03"
                           :secret "kd94hf93k423kf44"
                           :signature-method :hmac-sha1}
                          {:token "nnch734d00sl2jdk"
                           :secret "pfkkdhi9sl3r4s00"}
                          {:oauth_timestamp "1191242096"
                           :oauth_nonce "kllo9940pd9333jh"
                           :file "vacation.jpg"
                           :size "original"})
         "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal"))

  (is (= (sig/base-string "POST"
                          "https://api.twitter.com/oauth/request_token"
                          {:oauth_callback "http://localhost:3005/the_dance/process_callback?service_provider_id=11"
                           :oauth_consumer_key "GDdmIQH6jhtmLUypg82g"
                           :oauth_nonce "QP70eNmVz8jvdPevU3oJD2AfF7R7odC2XJcn4XlZJqk"
                           :oauth_signature_method "HMAC-SHA1"
                           :oauth_timestamp "1272323042"
                           :oauth_version "1.0"})
         "POST&https%3A%2F%2Fapi.twitter.com%2Foauth%2Frequest_token&oauth_callback%3Dhttp%253A%252F%252Flocalhost%253A3005%252Fthe_dance%252Fprocess_callback%253Fservice_provider_id%253D11%26oauth_consumer_key%3DGDdmIQH6jhtmLUypg82g%26oauth_nonce%3DQP70eNmVz8jvdPevU3oJD2AfF7R7odC2XJcn4XlZJqk%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1272323042%26oauth_version%3D1.0"))

  (is (= (sig/base-string "POST"
                          "https://api.twitter.com/oauth/access_token"
                          {:oauth_consumer_key "GDdmIQH6jhtmLUypg82g"
                           :oauth_nonce "9zWH6qe0qG7Lc1telCn7FhUbLyVdjEaL3MO5uHxn8"
                           :oauth_signature_method "HMAC-SHA1"
                           :oauth_token "8ldIZyxQeVrFZXFOZH5tAwj6vzJYuLQpl0WUEYtWc"
                           :oauth_timestamp "1272323047"
                           :oauth_verifier "pDNg57prOHapMbhv25RNf75lVRd6JDsni1AJJIDYoTY"
                           :oauth_version "1.0"})
         "POST&https%3A%2F%2Fapi.twitter.com%2Foauth%2Faccess_token&oauth_consumer_key%3DGDdmIQH6jhtmLUypg82g%26oauth_nonce%3D9zWH6qe0qG7Lc1telCn7FhUbLyVdjEaL3MO5uHxn8%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1272323047%26oauth_token%3D8ldIZyxQeVrFZXFOZH5tAwj6vzJYuLQpl0WUEYtWc%26oauth_verifier%3DpDNg57prOHapMbhv25RNf75lVRd6JDsni1AJJIDYoTY%26oauth_version%3D1.0"))

  (is (= (sig/base-string "POST"
                          "http://api.twitter.com/1/statuses/update.json"
                          {:oauth_consumer_key "GDdmIQH6jhtmLUypg82g"
                           :oauth_nonce "oElnnMTQIZvqvlfXM56aBLAf5noGD0AQR3Fmi7Q6Y"
                           :oauth_signature_method "HMAC-SHA1"
                           :oauth_timestamp "1272325550"
                           :oauth_version "1.0"
                           :oauth_token "819797-Jxq8aYUDRmykzVKrgoLhXSq67TEa5ruc4GJC2rWimw"
                           :status "setting up my twitter 私のさえずりを設定する"})
         "POST&http%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&oauth_consumer_key%3DGDdmIQH6jhtmLUypg82g%26oauth_nonce%3DoElnnMTQIZvqvlfXM56aBLAf5noGD0AQR3Fmi7Q6Y%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1272325550%26oauth_token%3D819797-Jxq8aYUDRmykzVKrgoLhXSq67TEa5ruc4GJC2rWimw%26oauth_version%3D1.0%26status%3Dsetting%2520up%2520my%2520twitter%2520%25E7%25A7%2581%25E3%2581%25AE%25E3%2581%2595%25E3%2581%2588%25E3%2581%259A%25E3%2582%258A%25E3%2582%2592%25E8%25A8%25AD%25E5%25AE%259A%25E3%2581%2599%25E3%2582%258B"))

  (is (= (sig/base-string "POST"
                          "http://api.twitter.com/1/statuses/update.json"
                          {:key "GDdmIQH6jhtmLUypg82g"
                           :signature-method :hmac-sha1}
                          {:token "819797-Jxq8aYUDRmykzVKrgoLhXSq67TEa5ruc4GJC2rWimw"}
                          {:oauth_nonce "oElnnMTQIZvqvlfXM56aBLAf5noGD0AQR3Fmi7Q6Y"
                           :oauth_timestamp "1272325550"
                           :oauth_version "1.0"
                           :status "setting up my twitter 私のさえずりを設定する"})
         "POST&http%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&oauth_consumer_key%3DGDdmIQH6jhtmLUypg82g%26oauth_nonce%3DoElnnMTQIZvqvlfXM56aBLAf5noGD0AQR3Fmi7Q6Y%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1272325550%26oauth_token%3D819797-Jxq8aYUDRmykzVKrgoLhXSq67TEa5ruc4GJC2rWimw%26oauth_version%3D1.0%26status%3Dsetting%2520up%2520my%2520twitter%2520%25E7%25A7%2581%25E3%2581%25AE%25E3%2581%2595%25E3%2581%2588%25E3%2581%259A%25E3%2582%258A%25E3%2582%2592%25E8%25A8%25AD%25E5%25AE%259A%25E3%2581%2599%25E3%2582%258B")))

(deftest 
    #^{:doc "Test hmac-sha1 signing of a request."} 
  hmac-sha1-signature

  (is (= (sig/sign {:key "dpf43f3p2l4k3l03"
                    :secret "kd94hf93k423kf44"
                    :signature-method :hmac-sha1}
                   (sig/base-string "GET"
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
         "tR3+Ty81lMeYAr/Fid0kMTYa/WM="))

  ;; Taken from Twitter dev example.
  (is (= (sig/sign {:signature-method :hmac-sha1
                    :secret "MCD8BKwGdgPHvAuvgvz4EQpqDAtx89grbuNMRd7Eh98"}
                   (sig/base-string "POST"
                                    "https://api.twitter.com/oauth/request_token"
                                    {:oauth_callback "http://localhost:3005/the_dance/process_callback?service_provider_id=11"
                                     :oauth_consumer_key "GDdmIQH6jhtmLUypg82g"
                                     :oauth_nonce "QP70eNmVz8jvdPevU3oJD2AfF7R7odC2XJcn4XlZJqk"
                                     :oauth_signature_method "HMAC-SHA1"
                                     :oauth_timestamp "1272323042"
                                     :oauth_version "1.0"}))
         "8wUi7m5HFQy76nowoCThusfgB+Q="))

  (is (= (sig/sign {:signature-method :hmac-sha1
                    :secret "MCD8BKwGdgPHvAuvgvz4EQpqDAtx89grbuNMRd7Eh98"}
                   (sig/base-string "POST"
                                    "https://api.twitter.com/oauth/access_token"
                                    {:oauth_consumer_key "GDdmIQH6jhtmLUypg82g"
                                     :oauth_nonce "9zWH6qe0qG7Lc1telCn7FhUbLyVdjEaL3MO5uHxn8"
                                     :oauth_signature_method "HMAC-SHA1"
                                     :oauth_token "8ldIZyxQeVrFZXFOZH5tAwj6vzJYuLQpl0WUEYtWc"
                                     :oauth_timestamp "1272323047"
                                     :oauth_verifier "pDNg57prOHapMbhv25RNf75lVRd6JDsni1AJJIDYoTY"
                                     :oauth_version "1.0"})
                   "x6qpRnlEmW9JbQn4PQVVeVG8ZLPEx6A0TOebgwcuA")
         "PUw/dHA4fnlJYM6RhXk5IU/0fCc="))
  
  (is (= (sig/sign {:signature-method :hmac-sha1
                    :secret "MCD8BKwGdgPHvAuvgvz4EQpqDAtx89grbuNMRd7Eh98"}
                   (sig/base-string "POST"
                                    "http://api.twitter.com/1/statuses/update.json"
                                    {:oauth_consumer_key "GDdmIQH6jhtmLUypg82g"
                                     :oauth_nonce "oElnnMTQIZvqvlfXM56aBLAf5noGD0AQR3Fmi7Q6Y"
                                     :oauth_signature_method "HMAC-SHA1"
                                     :oauth_timestamp "1272325550"
                                     :oauth_token "819797-Jxq8aYUDRmykzVKrgoLhXSq67TEa5ruc4GJC2rWimw"
                                     :oauth_version "1.0"
                                     :status "setting up my twitter 私のさえずりを設定する"})
                   "J6zix3FfA9LofH0awS24M3HcBYXO5nI1iYe8EfBA")
         "yOahq5m0YjDDjfjxHaXEsW9D+X0=")))

(deftest
    #^{:doc "test plaintext signatures"}
  plaintext-signature
  (let [c {:key "dpf43f3p2l4k3l03"
           :secret "kd94hf93k423kf44"
           :signature-method :plaintext}]
    (is (= "kd94hf93k423kf44&" (sig/sign c
                                         (sig/base-string "POST"
                                                          "https://photos.example.net/request_token"
                                                          {:oauth_consumer_key "dpf43f3p2l4k3l03"
                                                           :oauth_signature_method "PLAINTEXT"
                                                           :oauth_timestamp "1191242090"
                                                           :oauth_nonce "hsu94j3884jdopsl"
                                                           :oauth_version "1.0"}))))

    (is (= "kd94hf93k423kf44&hdhd0244k9j7ao03" (sig/sign c
                                                         (sig/base-string "POST"
                                                                          "https://photos.example.net/access_token"
                                                                          {:oauth_consumer_key "dpf43f3p2l4k3l03"
                                                                           :oauth_signature_method "PLAINTEXT"
                                                                           :oauth_timestamp "1191242090"
                                                                           :oauth_token "hh5s93j4hdidpola"
                                                                           :oauth_nonce "hsu94j3884jdopsl"
                                                                           :oauth_verifier "hfdp7dh39dks9884"
                                                                           :oauth_version "1.0"})
                                                         "hdhd0244k9j7ao03")))))

(deftest 
    #^{:doc "Test verification of signed request."} 
  verify
  (let [c { :key "dpf43f3p2l4k3l03"
           :secret "kd94hf93k423kf44"
           :signature-method :hmac-sha1}]

    (is (sig/verify "tR3+Ty81lMeYAr/Fid0kMTYa/WM="
                    c
                    (sig/base-string "GET"
                                     "http://photos.example.net/photos"
                                     {:oauth_consumer_key "dpf43f3p2l4k3l03"
                                      :oauth_token "nnch734d00sl2jdk"
                                      :oauth_signature_method "HMAC-SHA1"
                                      :oauth_timestamp "1191242096"
                                      :oauth_nonce "kllo9940pd9333jh"
                                      :oauth_version "1.0"
                                      :file "vacation.jpg"
                                      :size "original"})
                    "pfkkdhi9sl3r4s00"))
    
    (is (sig/verify "kd94hf93k423kf44&"
                    (assoc c :signature-method :plaintext)
                    (sig/base-string "POST"
                                     "https://photos.example.net/request_token"
                                     {:oauth_consumer_key "dpf43f3p2l4k3l03"
                                      :oauth_signature_method "PLAINTEXT"
                                      :oauth_timestamp "1191242090"
                                      :oauth_nonce "hsu94j3884jdopsl"
                                      :oauth_version "1.0"})))))


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
  (is (= "%E3%80%81"  (sig/url-encode "\u3001"))))

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
  (is (= (sig/url-decode "%E3%80%81")   "\u3001")))

(deftest  
    #^{:doc "url form encode"}
  url-form-encode
  (is (= (sig/url-form-encode {}) ""))
  (is (= (sig/url-form-encode {"hello" "there"}) "hello=there"))
  (is (= (sig/url-form-encode {"hello" "there" "name" "Bill" }) "name=Bill&hello=there"))
  
  (is (= (sig/url-form-encode {:hello "there"}) "hello=there"))
  (is (= (sig/url-form-encode {:hello "there" :name "Bill" }) "name=Bill&hello=there"))

  (is (= (sig/url-form-encode {:hello "there"}) "hello=there"))
  (is (= (sig/url-form-encode {:hello "there" :name "Bill Smith" }) "name=Bill%20Smith&hello=there")))

(deftest
    #^{:doc "normalizing the URL"}
  normalize-url
  (let [normalized "http://example.com/resource"]
    (is (= normalized (sig/normalize "http://example.com/resource")))
    (is (= normalized (sig/normalize "HTTP://Example.com/resource")))
    (is (= normalized (sig/normalize "http://example.com:80/resource")))
    (is (= normalized (sig/normalize "http://example.com/resource?query=foo&bar=baz")))
    (is (= normalized (sig/normalize "http://example.com:80/resource?query=foo&bar=baz")))
    (is (= normalized (sig/normalize "http://example.com:80/resource#fragment")))
    (is (= "http://example.com:99/resource" (sig/normalize "http://example.com:99/resource")))
    (is (= "https://example.com/resource" (sig/normalize "https://example.com:443/resource")))
    (is (= "https://example.com:99/resource" (sig/normalize "https://example.com:99/resource")))))
