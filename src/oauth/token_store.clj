(ns 
    #^{:author "Pelle Braendgaard"
       :doc "OAuth Token store"} 
  oauth.token-store
)

(defmulti consumer-get 
  "Get consumer from store"
  (fn [c _] c))

(defmulti consumer-put 
  "Stores consumer"
  (fn [c _] c))

(def memory-consumers (atom {}))

(defmethod consumer-get :memory
  [_ key]
    (@memory-consumers key)
  )

(defmethod consumer-put :memory
  [_ consumer]
    ((swap! memory-consumers assoc (consumer :key) consumer) (consumer :key))
  )
