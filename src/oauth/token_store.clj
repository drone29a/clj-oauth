(ns 
    #^{:author "Pelle Braendgaard"
       :doc "OAuth Token store"} 
  oauth.token-store
  (:use [oauth.signature :only [rand-str]])  
)

;; Return a Consumer record based on consumer key.
;; If a consumer is returned then it is assumed to be valid
(defmulti get-consumer 
  "Get consumer from store"
  (fn [c _] c))

;; Stores a consumer. The 2 required fields in the map are :key and :secret
(defmulti store-consumer 
  "Stores consumer"
  (fn [c _] c))

;; Return a Request Token record based on a token
;; If a token is returned then it is assumed to be valid. Thus expiry etc should be handled in the store.
(defmulti get-request-token 
  "Get valid request-token from store"
  (fn [c _] c))

;; Stores a Request Token. The 3 required fields in the map are :token, :secret and :callback_url
(defmulti store-request-token 
  "Stores request-token"
  (fn [c _] c))

;; Authorizes a request token. 
(defmulti authorize-token 
  "Revokes a request-token"
  (fn [c _] c))

;; Revokes a request token. Implementations can chose to simply delete record. 
;; However once this is called it should no longer be returned by get-request-token
(defmulti revoke-request-token 
  "Revokes a request-token"
  (fn [c _] c))

;; Return a Request Token record based on a token
;; If a token is returned then it is assumed to be valid. Thus expiry etc should be handled in the store.
(defmulti get-access-token 
  "Get valid access-token from store"
  (fn [c _] c))

;; Stores an Access Token. The 2 required fields in the map are :token and :secret
(defmulti store-access-token 
  "Stores access-token"
  (fn [c _] c))

;; Revokes an access token. Implementations can chose to simply delete record. 
;; However once this is called it should no longer be returned by get-access-token
(defmulti revoke-access-token 
  "Revokes a access-token"
  (fn [c _] c))

(defn new-consumer
  "Creates but doesn't store consumer"
  ([] (new-consumer {}))
  ([params] (assoc params :key (rand-str 20) :secret (rand-str 40)))
  )
  
(defn create-consumer 
  "Creates and stores a consumer"
  ([store] (create-consumer store {}))
  ([store params] (store-consumer store (new-consumer params)))  
  )

(defn new-request-token
  "Creates but doesn't store a request token"
  ([consumer callback_url] (new-request-token consumer callback_url {}))
  ([consumer callback_url params] (assoc params :token (rand-str 20) :secret (rand-str 40) :verifier (rand-str 20) :callback_url callback_url :consumer consumer))
  )

(defn create-request-token 
  "Creates and stores a request token"
  ([store consumer callback_url] (create-request-token store consumer callback_url {}))
  ([store consumer callback_url params] (store-request-token store (new-request-token consumer callback_url params)))  
  )

(defn new-access-token
  "Creates but doesn't store an access token"
  ([consumer ] (new-access-token consumer {}))
  ([consumer params] (assoc params :token (rand-str 20) :secret (rand-str 40) :consumer consumer ))
  )

(defn create-access-token 
  "Creates and stores an access token"
  ([store consumer] (create-access-token store consumer {}))
  ([store consumer params] (store-access-token store (new-access-token consumer params))) 
  )

;; Local in memory implementation
(def memory-consumers (atom {}))

(defmethod get-consumer :memory
  [_ key]
    (@memory-consumers key)
  )

(defmethod store-consumer :memory
  [_ consumer]
    ((swap! memory-consumers assoc (consumer :key) consumer) (consumer :key))
  )

(def memory-request-tokens (atom {}))

(defmethod get-request-token :memory
  [_ token]
    (@memory-request-tokens token)
  )

(defmethod store-request-token :memory
  [_ token]
    ((swap! memory-request-tokens assoc (token :token) token) (token :token))
  )

(defmethod authorize-token :memory
  [_ token]
  (let [rt (@memory-request-tokens token)]
    (swap! memory-request-tokens assoc token (assoc rt :authorized true))
    )
  )
  
(defmethod revoke-request-token :memory
  [_ token]
    (swap! memory-request-tokens dissoc token )
  )

(def memory-access-tokens (atom {}))

(defmethod get-access-token :memory
  [_ token]
    (@memory-access-tokens token)
  )

(defmethod store-access-token :memory
  [_ token]
    ((swap! memory-access-tokens assoc (token :token) token) (token :token))
  )

(defmethod revoke-access-token :memory
  [_ token]
    (swap! memory-access-tokens dissoc token )
  )
