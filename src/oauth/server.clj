(ns 
    #^{:author "Pelle Braendgaard"
       :doc "OAuth server library for Clojure."} 
  oauth.server
  (:require [oauth.digest :as digest]
            [oauth.signature :as sig])
)


(defn parse-oauth-header 
  "Parses the oauth http header"
  [auth]
  (if (or (= auth nil) 
          (not (re-find #"^OAuth" auth)))
    nil
    (reduce (fn [v c] (conj c v)) {}  ; I know there has to be a simpler way of doing this
      (map (fn [x] {(keyword ( x 1)) (x 2)}) 
        (re-seq #"(oauth_[^=, ]+)=\"([^\"]*)\"" auth)))
      )
)

(defn oauth-params [request]
  (parse-oauth-header ((request :header) :authorize))
)

(defn wrap-oauth
  "Middleware to handle OAuth authentication of requests. If the request is oauth authenticated it adds the following to the request:
    :oauth_token - The oauth token used
    :oauth_consumer - The consumer key used
  Takes a function which will be used to find a token. This accepts the consumer and token parameters
  and should return the responding consumer secret and token secret."
  [handler token-finder]
  (fn [request]
    (let []
      (handler request))))
