(ns
    #^{:author "Matt Revelle"
       :doc "OAuth client library for Clojure."}
  oauth.client
  (:require [oauth.digest :as digest]
            [oauth.signature :as sig]
            [clj-http.client :as httpclient]
            [clj-http.util :as httputil]
            )
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
  [consumer token]
  (str (:authorize-uri consumer)
       "?" (httpclient/generate-query-string {:oauth_token token})))

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
(defn post-request-body-decoded [url & [req]]
  #_(success-content
     (http/post (:request-uri consumer)
                :headers {"Authorization" (authorization-header params)}
                :parameters (http/map->params {:use-expect-continue false})
                :as :urldecoded))
  (form-decode
   (:body (check-success-response
           (httpclient/post url req)))))

(defn oauth-post-request-decoded [url oauth-params & [form-params]]
  (let [req (merge
             {:headers {"Authorization" (authorization-header
                                         oauth-params)}}
             (if form-params {:form-params form-params}))]
    (post-request-body-decoded url req)))

(defn credentials
  "Return authorization credentials needed for access to protected resources.
The key-value pairs returned as a map will need to be added to the
Authorization HTTP header or added as query parameters to the request."
  ([consumer token token-secret request-method request-uri & [request-params]]
     (let [unsigned-oauth-params (sig/oauth-params consumer token)
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

(defn- get-oauth-token
  ([consumer uri unsigned-params & [token-secret]]
     (let [signature (sig/sign consumer
                               (sig/base-string "POST" uri unsigned-params)
                               token-secret)
           params (assoc unsigned-params :oauth_signature signature)]
       (oauth-post-request-decoded uri params))))

(defn request-token
  "Fetch request token for the consumer."
  ([consumer]
     (request-token consumer nil))

  ([consumer callback-uri]
     (let [unsigned-params (sig/oauth-params consumer)
           unsigned-params (if callback-uri
                             (assoc unsigned-params
                               :oauth_callback callback-uri)
                             unsigned-params)]
       (get-oauth-token consumer (:request-uri consumer) unsigned-params))))

(defn access-token
  "Exchange a request token for an access token.
  When provided with two arguments, this function operates as per OAuth 1.0.
  With three arguments, a verifier is used."
  ([consumer request-token]
     (access-token consumer request-token nil))
  ([consumer request-token verifier]
     (let [unsigned-params (if verifier
                             (sig/oauth-params consumer
                                               (:oauth_token request-token)
                                               verifier)
                             (sig/oauth-params consumer
                                               (:oauth_token
                                                request-token)))
           token-secret (:oauth_token_secret request-token)]
       (get-oauth-token consumer (:access-uri consumer) unsigned-params token-secret))))

(defn xauth-access-token
  "Request an access token with a username and password with xAuth."
  [consumer username password]
  (let [oauth-params (sig/oauth-params consumer)
        post-params {:x_auth_username username
                     :x_auth_password password
                     :x_auth_mode "client_auth"}
        signature (sig/sign consumer
                            (sig/base-string "POST"
                                             (:access-uri consumer)
                                             (merge oauth-params
                                                    post-params)))
        params (assoc oauth-params
                 :oauth_signature signature)]
    (oauth-post-request-decoded (:access-uri consumer)
                                params post-params)))
