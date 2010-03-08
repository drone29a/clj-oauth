(ns 
    #^{:author "Pelle Braendgaard"
       :doc "OAuth server library for Clojure."} 
  oauth.server
  (:require [oauth.digest :as digest]
            [oauth.signature :as sig]
            [oauth.token-store :as store])
  (:use [clojure.contrib.str-utils :only [str-join re-split]]
        [clojure.contrib.str-utils2 :only [upper-case]]
        [clojure.contrib.java-utils :only [as-str]])
)


(defn parse-oauth-header 
  "Parses the oauth http header"
  [auth]
  (if (or (= auth nil) 
          (not (re-find #"^OAuth" auth)))
    nil
    (reduce (fn [v c] (conj c v)) {}  ; I know there has to be a simpler way of doing this
      (map (fn [x] {(keyword ( x 1)) (sig/url-decode (x 2))}) 
        (re-seq #"(oauth_[^=, ]+)=\"([^\"]*)\"" auth)))
      )
)

(defn parse-form-encoded [string]
  (if (or (nil? string)
          (= string ""))
    {}
   (reduce 
     (fn [h v] (assoc h (keyword (first v)) (second v))) 
     {} 
     (vec (map #(re-split #"=" %) (re-split #"&" string))))
  ))
  
(defn oauth-params [request]
  (parse-oauth-header ((or (request :headers) {}) :authorize))
)

(defn request-method [request] (upper-case (as-str (request :request-method))))

(defn request-uri [request]
  (str (or (as-str (request :scheme)) "http") "://" (request :server-name) (request :uri)))

(defn request-parameters [request]
  (merge (dissoc (oauth-params request) :oauth_signature) (request :params))
  )
  
(defn request-base-string
  "creates a signature base string from a ring request"
  [request]
  (sig/base-string (request-method request) (request-uri request) (request-parameters request))
)

(defn wrap-oauth
  "Middleware to handle OAuth authentication of requests. If the request is oauth authenticated it adds the following to the request:
    :oauth-token - The oauth token used
    :oauth-consumer - The consumer key used
  Takes a function which will be used to find a token. This accepts the consumer and token parameters
  and should return the responding consumer secret and token secret."
  [handler token-finder]
  (fn [request]
    (let 
       [op (oauth-params request)]
       (if (not (empty? op))
         (let 
           [oauth-consumer (op :oauth_consumer_key)
            oauth-token (op :oauth_token)
            secrets (token-finder oauth-consumer oauth-token)]
            (if (and (not (empty? secrets)) (sig/verify 
                (op :oauth_signature)
                {:secret (first secrets) :signature-method :hmac-sha1}
                (request-base-string request)
                (last secrets)))
                (handler (assoc request :oauth-consumer oauth-consumer :oauth-token oauth-token :oauth-params op)) 
                (handler request)
              )
         )
        (handler request)
       ))
      ))

(defn- token-response [token]
  { :status 200
    :header {}
    :body (sig/url-form-encode token)}
  )

(defn not-allowed []
  { :status 401
    :header {}
    :body nil})
    
(defn request-token
  [store request]
  (if (and 
        (not (nil? (store/get-consumer store (request :oauth-consumer))))
        (not (nil? (request :oauth-params)))
        (not (nil? ((request :oauth-params) :oauth_callback))))
    (let [token (store/create-request-token store (request :oauth-consumer) ((request :oauth-params) :oauth_callback))]
      (token-response {:oauth_token (token :token) :oauth_secret (token :secret) :oauth_callback_confirmed "true"})      
      )
    (not-allowed)
  ))
  
(defn access-token
  [store request]
  (if (and 
        (contains? request :oauth-consumer)
        (contains? request :oauth-token)
        ((request :oauth-token) :authorized)
        (= (request :oauth-consumer) ((request :oauth-token) :consumer))
        (contains? request :oauth-params)
        (contains? (request :oauth-params) :oauth_verifier)
        (= ((request :oauth-params) :oauth_verifier) ((request :oauth-token) :verifier))
        )
    (let [token (store/create-access-token store (request :oauth-consumer) )]
      (token-response {:oauth_token (token :token) :oauth_secret (token :secret)})      
      )
    (not-allowed)
  ))
  
(defn oauth-token-manager
  "App to manage OAuth token requests. Expects wrap-oauth to be applied already. 
  Generates the following routes:
    /oauth/request_token
    /oauth/access_token
    /oauth/authorize
  "
  [handler]
  (fn [request]
    (condp = (:uri request)
        "/oauth/request_token"
          (request-token request)
        "/oauth/access_token"
          (access-token request)
        (handler request)))
  )
