(ns oauth.server-test
  (:require [oauth.server :as os]
            [oauth.signature :as sig]
            [oauth.token-store :as store] :reload-all)
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
  #^{:doc "Test parsing of form encoded string."} 
  parse-form-encoded
  (is (= (os/parse-form-encoded "hello=this") { :hello "this"}))
  (is (= (os/parse-form-encoded "hello=") { :hello nil}))
  (is (= (os/parse-form-encoded "hello=this&fun=stuff") { :hello "this" :fun "stuff"}))
  (is (= (os/parse-form-encoded "") {}))
  (is (= (os/parse-form-encoded nil) {}))
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
  (if (or (req :oauth-token)(req :oauth-consumer))
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


(deftest
  #^{:doc "wrap oauth"}
  wrap-oauth
  (let [oauth-app (os/wrap-oauth app :memory) 
        _  (store/store-consumer :memory {:key "dpf43f3p2l4k3l03" :secret "kd94hf93k423kf44"})
        _  (store/store-access-token :memory {:token "nnch734d00sl2jdk" :secret "pfkkdhi9sl3r4s00"})]
    (is (= 401 ((oauth-app {}) :status)))
    (is (= 401 ((oauth-app {:headers { :authorize "Basic realm=\"Secure Area\""}}) :status)))
    (is (= 401 ((oauth-app {:headers { :authorize "OAuth realm=\"http://sp.example.com/\", oauth_consumer_key=\"0685bd9184jfhq22\", oauth_token=\"ad180jjd733klru7\", oauth_signature_method=\"HMAC-SHA1\", oauth_signature=\"fake\", oauth_timestamp=\"137131200\", oauth_nonce=\"4572616e48616d6d65724c61686176\",oauth_version=\"1.0\""}}) :status)))

    ;; 3 legged HMAC-SHA1
    (is (= 200 ((oauth-app {
      :request-method :get
      :server-name "photos.example.net"
      :uri "/photos"
      :scheme :http
      :params {:file "vacation.jpg" :size "original"}
      :headers { :authorize "OAuth realm=\"http://sp.example.com/\", oauth_consumer_key=\"dpf43f3p2l4k3l03\", oauth_token=\"nnch734d00sl2jdk\", oauth_signature_method=\"HMAC-SHA1\", oauth_signature=\"tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D\", oauth_timestamp=\"1191242096\", oauth_nonce=\"kllo9940pd9333jh\",oauth_version=\"1.0\""}}) :status)))

    ;; 3 legged PLAINTEXT
    (is (= 200 ((oauth-app {
      :request-method :get
      :server-name "photos.example.net"
      :uri "/photos"
      :scheme :http
      :params {:file "vacation.jpg" :size "original"}
      :headers { :authorize "OAuth realm=\"http://sp.example.com/\", oauth_consumer_key=\"dpf43f3p2l4k3l03\", oauth_token=\"nnch734d00sl2jdk\", oauth_signature_method=\"PLAINTEXT\", oauth_signature=\"kd94hf93k423kf44%26pfkkdhi9sl3r4s00\", oauth_timestamp=\"1191242096\", oauth_nonce=\"kllo9940pd9333jh\",oauth_version=\"1.0\""}}) :status)))

    ;; 2 legged PLAINTEXT
    (is (= 200 ((oauth-app {
      :request-method :get
      :server-name "photos.example.net"
      :uri "/photos"
      :scheme :http
      :params {:file "vacation.jpg" :size "original"}
      :headers { :authorize "OAuth realm=\"http://sp.example.com/\", oauth_consumer_key=\"dpf43f3p2l4k3l03\", oauth_signature_method=\"PLAINTEXT\", oauth_signature=\"kd94hf93k423kf44%26\", oauth_timestamp=\"1191242096\", oauth_nonce=\"kllo9940pd9333jh\",oauth_version=\"1.0\""}}) :status)))
      
  ))
  
(deftest
  #^{:doc "token request"}
  request-token
  (let [consumer (store/create-consumer :memory)]
    (is (= 401 ((os/request-token :memory {} ) :status)))
    (is (= 401 ((os/request-token :memory {:oauth-consumer consumer }) :status)))
    (is (= 200 ((os/request-token :memory {:oauth-consumer consumer :oauth-params {:oauth_callback "http://blabla.inv/callback"}}) :status)))
    (is (= 200 ((os/request-token :memory {:oauth-consumer consumer :oauth-params {:oauth_callback "oob"}}) :status)))
    (let [token-body ((os/request-token :memory 
                      {:oauth-consumer consumer :oauth-params {:oauth_callback "http://blabla.inv/callback"}}) :body )
          token-params (os/parse-form-encoded token-body)]
      (is (not (nil? token-body)))
      (is (not (nil? token-params)))
      (is (not (nil? (token-params :oauth_token))))
      (is (not (nil? (token-params :oauth_secret))))
      (is (= (token-params :oauth_callback_confirmed) "true"))
      (is (nil? (token-params :oauth_verifier)))
      (let [token (store/get-request-token :memory (token-params :oauth_token))]
        (is (not (nil? token)))
        (is (= (token :token) (token-params :oauth_token)))
        (is (= (token :secret) (token-params :oauth_secret)))
        (is (= (token :consumer) consumer))
        (is (not (nil? (token :verifier))))
        )
    ))
  )
  
;; 
(deftest
  #^{:doc "integrated token request in app using example from http://oauth.net/core/1.0a/#anchor43"}
  integrated-token-request
  (let [oauth-app (os/wrap-oauth (os/oauth-token-manager app :memory ) :memory) 
        _  (store/store-consumer :memory {:key "dpf43f3p2l4k3l03" :secret "kd94hf93k423kf44"})]
    (is (= 401 ((oauth-app {}) :status)))
    (is (= 401 ((oauth-app {:headers { :authorize "Basic realm=\"Secure Area\""}}) :status)))
    (is (= 401 ((oauth-app {:headers { :authorize "OAuth realm=\"https://photos.example.net/\", oauth_consumer_key=\"dpf43f3p2l4k3l03\", oauth_signature_method=\"HMAC-SHA1\", oauth_signature=\"fake\", oauth_timestamp=\"1191242090\", oauth_nonce=\"hsu94j3884jdopsl\", oauth_version=\"1.0\", oauth_callback=\"http%3A%2F%2Fprinter.example.com%2Frequest_token_ready\""}}) :status)))

    (let [ response (oauth-app {
      :request-method :post
      :server-name "photos.example.net"
      :uri "/oauth/request_token"
      :scheme :https
      :headers { :authorize "OAuth realm=\"https://photos.example.net/\", oauth_consumer_key=\"dpf43f3p2l4k3l03\", oauth_signature_method=\"PLAINTEXT\", oauth_signature=\"kd94hf93k423kf44%26\", oauth_timestamp=\"1191242090\", oauth_nonce=\"hsu94j3884jdopsl\", oauth_callback=\"http://printer.example.com/request_token_ready\" oauth_version=\"1.0\""}})
      token-body (response :body)
      _ (println token-body)
      token-params (os/parse-form-encoded (response :body))]
      (is(= 200 (response :status)))
      (is (not (nil? token-body)))
      (is (not (nil? token-params)))
      (is (not (nil? (token-params :oauth_token))))
      (is (not (nil? (token-params :oauth_secret))))
      (is (= (token-params :oauth_callback_confirmed) "true"))
      (is (nil? (token-params :oauth_verifier)))
      (let [token (store/get-request-token :memory (token-params :oauth_token))]
        (is (not (nil? token)))
        (is (= (token :token) (token-params :oauth_token)))
        (is (= (token :secret) (token-params :oauth_secret)))
        (is (= (token :consumer) (store/get-consumer :memory "dpf43f3p2l4k3l03")))
        (is (not (nil? (token :verifier))))
        ))
      
  ))
  

(deftest
  #^{:doc "access token request"}
  access-token
  (let [consumer (store/create-consumer :memory)
        request-token (store/create-request-token :memory consumer "http://test.com/callback")
      ]
    (is (= 401 ((os/access-token :memory {} ) :status)))
    (is (= 401 ((os/access-token :memory { :oauth-consumer consumer }) :status)))
    (is (= 401 ((os/access-token :memory { :oauth-consumer consumer :oauth-token request-token :oauth-params {:oauth_verifier (request-token :verifier)}}) :status)))
    (is (= 401 ((os/access-token :memory { :oauth-consumer consumer :oauth-token request-token :oauth-params {:oauth_verifier (request-token :verifier)}}) :status)))
    (do
      (store/authorize-token :memory (request-token :token))
      (let [request-token (store/get-request-token :memory (request-token :token))]
        (is (= 401 ((os/access-token :memory { :oauth-consumer consumer :oauth-token request-token :oauth-params {} }) :status)))
        (is (= 401 ((os/access-token :memory { :oauth-consumer consumer :oauth-token request-token :oauth-params {:oauth_verifier "fake"}}) :status)))
        (let [ token-response (os/access-token :memory {:oauth-consumer consumer  :oauth-token request-token 
                                :oauth-params {:oauth_verifier (request-token :verifier)}})
               token-params (os/parse-form-encoded (token-response :body))]
          (is (= 200 (token-response :status)))
          (is (not (nil? token-params)))
          (is (not (nil? (token-params :oauth_token))))
          (is (not (nil? (token-params :oauth_secret))))
          (let [token (store/get-access-token :memory (token-params :oauth_token))]
            (is (not (nil? token)))
            (is (= (token :token) (token-params :oauth_token)))
            (is (= (token :secret) (token-params :oauth_secret)))
            (is (= (token :consumer) consumer))
            )    
        ))
        
        )
  ))
  