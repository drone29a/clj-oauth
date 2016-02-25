(ns
    #^{:author "Matt Revelle"
       :doc "OAuth client library for Clojure."}
  oauth.client
  (:require [oauth.digest :as digest]
            [oauth.signature :as sig]
            [clj-http.client :as httpclient])
  (:use [clojure.string :only [join split upper-case]]))

(defrecord #^{:doc "OAuth consumer"}
    Consumer [key secret request-uri
              access-uri authorize-uri signature-method])
(defn make-consumer
  "Make a consumer struct map."
  [key secret request-uri access-uri authorize-uri signature-method]
  (Consumer.
          key
          secret
          request-uri
          access-uri
          authorize-uri
          signature-method))

(defn user-approval-uri
  "Builds the URI to the Service Provider where the User will be prompted
to approve the Consumer's access to their account."
  ([consumer token]
   (user-approval-uri consumer token {}))
  ([consumer token extra-params]
   (str (:authorize-uri consumer)
        "?" (httpclient/generate-query-string (merge {:oauth_token token} extra-params)))))

(defn authorization-header
  "OAuth credentials formatted for the Authorization HTTP header."
  ([oauth-params]
     (str "OAuth "
          (join ", "
                (map (fn [[k v]]
                       (str (-> k sig/as-str sig/url-encode)
                            "=\"" (-> v sig/as-str sig/url-encode) "\""))
                     oauth-params))))
  ([oauth-params realm]
     (authorization-header (assoc oauth-params :realm realm))))

(defn form-decode
  "Parse form-encoded bodies from OAuth responses."
  [s]
  (if s
    (into {}
          (map (fn [kv]
                 (let [[k v] (split kv #"=")
                       k (or k "")
                       v (or v "")]
                   [(keyword (sig/url-decode k)) (sig/url-decode v)]))
               (split s #"&")))))

(defn- check-success-response [m]
  (let [code (:status m)]
    (if (or (< code 200)
            (>= code 300))
      (throw (new Exception (str "Got non-success code: " code ". "
                                 "Content: " (:body m))))
      m)))

(defn build-request 
  "Construct request from prepared paramters."
  [oauth-params & [form-params]]
  (let [req (merge
             {:headers {"Authorization" (authorization-header
                                         oauth-params)}}
             (when form-params {:form-params form-params}))]
    req))

(defn post-request-body-decoded [url & [req]]
  (form-decode
   (:body (check-success-response
           (httpclient/post url req)))))

(defn credentials
  "Return authorization credentials needed for access to protected resources.
The key-value pairs returned as a map will need to be added to the
Authorization HTTP header or added as query parameters to the request."
  ([consumer token token-secret request-method request-uri & [request-params]]
     (let [unsigned-oauth-params (sig/oauth-params consumer
                                                   (sig/rand-str 30)
                                                   (sig/msecs->secs (System/currentTimeMillis))
                                                   token)
           unsigned-params (merge request-params
                                  unsigned-oauth-params)
           signature (sig/sign consumer
                               (sig/base-string (-> request-method
                                                    sig/as-str
                                                    upper-case)
                                                request-uri
                                                 unsigned-params)
                               token-secret)]
       (assoc unsigned-oauth-params :oauth_signature signature))))

(defn build-oauth-token-request
  "Used to build actual OAuth request."
  ([consumer uri unsigned-oauth-params & [extra-params token-secret]]
     (let [signature (sig/sign consumer
                               (sig/base-string "POST" uri (merge unsigned-oauth-params extra-params))
                               token-secret)
           oauth-params (assoc unsigned-oauth-params :oauth_signature signature)]
       (build-request oauth-params extra-params))))

(defn request-token
  "Fetch request token for the consumer."
  ([consumer]
     (request-token consumer "oob" nil))
  ([consumer callback-uri]
     (request-token consumer callback-uri nil))
  ([consumer callback-uri extra-params]
     (let [unsigned-params (-> (sig/oauth-params consumer
                                                 (sig/rand-str 30)
                                                 (sig/msecs->secs (System/currentTimeMillis)))
                               (assoc :oauth_callback callback-uri))]
       (post-request-body-decoded (:request-uri consumer) 
                                  (build-oauth-token-request consumer 
                                                             (:request-uri consumer) 
                                                             unsigned-params 
                                                             extra-params)))))

(defn access-token
  "Exchange a request token for an access token.
  When provided with two arguments, this function operates as per OAuth 1.0.
  With three arguments, a verifier is used."
  ([consumer request-token]
     (access-token consumer request-token nil))
  ([consumer request-token verifier]
     (let [unsigned-oauth-params (if verifier
                                   (sig/oauth-params consumer
                                                     (sig/rand-str 30)
                                                     (sig/msecs->secs (System/currentTimeMillis))
                                                     (:oauth_token request-token)
                                                     verifier)
                                   (sig/oauth-params consumer
                                                     (sig/rand-str 30)
                                                     (sig/msecs->secs (System/currentTimeMillis))
                                                     (:oauth_token
                                                      request-token)))
           token-secret (:oauth_token_secret request-token)]
       (post-request-body-decoded (:access-uri consumer) 
                                  (build-oauth-token-request consumer 
                                                             (:access-uri consumer) 
                                                             unsigned-oauth-params 
                                                             nil 
                                                             token-secret)))))
(defn build-xauth-access-token-request
  ([consumer username password nonce timestamp]
   (build-xauth-access-token-request consumer nil username password nonce timestamp))
  ([consumer {token :oauth_token secret :oauth_token_secret} username password nonce timestamp]
   (let [oauth-params (if token
                        (sig/oauth-params consumer nonce timestamp token)
                        (sig/oauth-params consumer nonce timestamp))
         post-params {:x_auth_username username
                      :x_auth_password password
                      :x_auth_mode "client_auth"}
         signature-base (sig/base-string "POST"
                                         (:access-uri consumer)
                                         (merge oauth-params
                                                post-params))
         signature (if secret (sig/sign consumer signature-base secret) (sig/sign consumer signature-base))
         params (assoc oauth-params
                       :oauth_signature signature)]
     (build-request params post-params))))

(defn refresh-token
  "Exchange an expired access token for a new access token."
  [consumer expired-token]
  (let [unsigned-params (assoc (sig/oauth-params consumer
                                                 (:oauth_token expired-token))
                          :oauth_session_handle (:oauth_session_handle expired-token))
        signature (sig/sign consumer
                            (sig/base-string "POST"
                                             (:access-uri consumer)
                                             unsigned-params)
                            (:oauth_token_secret expired-token))
        params (assoc unsigned-params
                 :oauth_signature signature)]
    (post-request-body-decoded (:access-uri consumer)
                               (build-request params {:use-expect-continue false}))))

(defn xauth-access-token
  "Request an access token with a username and password with xAuth."
  [consumer username password]
  (post-request-body-decoded (:access-uri consumer)
                             (build-xauth-access-token-request consumer
                                                               username
                                                               password
                                                               (sig/rand-str 30)
                                                               (sig/msecs->secs (System/currentTimeMillis)))))
