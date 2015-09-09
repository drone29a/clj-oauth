(defproject clj-oauth "1.5.3"
  :url "https://github.com/mattrepl/clj-oauth"
  :license {:name "Eclipse Public License - v 1.0"
            :url "http://www.eclipse.org/legal/epl-v10.html"
            :distribution :repo
            :comments "same as Clojure"}
  :description "OAuth support for Clojure"
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [commons-codec/commons-codec "1.8"]
                 [org.bouncycastle/bcprov-jdk15on "1.50"]
                 [org.bouncycastle/bcpkix-jdk15on "1.50"]
                 [clj-http "1.0.1"]])
