(defproject clj-oauth "1.5.4-SNAPSHOT"
  :url "https://github.com/mattrepl/clj-oauth"
  :license {:name "Eclipse Public License - v 1.0"
            :url "http://www.eclipse.org/legal/epl-v10.html"
            :distribution :repo
            :comments "same as Clojure"}
  :description "OAuth support for Clojure"
  :dependencies [[org.clojure/clojure "1.7.0"]
                 [commons-codec/commons-codec "1.8"]
                 [org.bouncycastle/bcprov-jdk15on "1.54"]
                 [org.bouncycastle/bcpkix-jdk15on "1.54"]
                 [clj-http "1.0.1"]])
