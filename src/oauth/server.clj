(ns 
    #^{:author "Pelle Braendgaard"
       :doc "OAuth server library for Clojure."} 
  oauth.server
  (:require [oauth.digest :as digest]
            [oauth.signature :as sig])
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
                (handler (assoc request :oauth-consumer oauth-consumer :oauth-token oauth-token))
                (handler request)
              )
         )
        (handler request)
       ))
      ))
