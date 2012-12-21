(ns datomic.codeq.ipa
  (:import (clojure.lang DynamicClassLoader)
           (java.util.jar JarFile)
           (java.net URL URLClassLoader))
  (:require [clojure.java.io :as io]
            [clojure.string :as string]
            [clojure.pprint :refer [pprint]])
  (:refer-clojure :exclude (add-classpath)))

;; call-method pulled from clojure.contrib.reflect, (c) 2010 Stuart Halloway & Contributors
(defn- call-method
  "Calls a private or protected method.

  params is a vector of classes which correspond to the arguments to
  the method e

  obj is nil for static methods, the instance object otherwise.

  The method-name is given a symbol or a keyword (something Named)."
  [klass method-name params obj & args]
  (-> klass (.getDeclaredMethod (name method-name)
                                (into-array Class params))
    (doto (.setAccessible true))
    (.invoke obj (into-array Object args))))

(defprotocol URLClasspath
  "Ability to dynamically add urls to classloaders.

This protocol is an implementation detail.  Use
`modifiable-classloader?` and `add-classpath` or `add-dependencies`
unless you are extending a type to this protocol."
  (^{:private true} can-modify? [this] "Returns true if the given classloader can be modified.")
  (^{:private true} add-url [this url] "add the url to the classpath"))

(extend-type DynamicClassLoader
  URLClasspath
  (can-modify? [this] true)
  (add-url [this url] (.addURL this url)))

(def ^:private url-classloader-base
  {:can-modify? (constantly true)
   :add-url (fn [this url]
              (call-method URLClassLoader 'addURL [URL] this url))})

(extend URLClassLoader URLClasspath url-classloader-base)

(defmacro when-resolves
  [sym & body]
  (when (resolve sym) `(do ~@body)))

(when-resolves sun.misc.Launcher             
  (extend sun.misc.Launcher$ExtClassLoader URLClasspath
    (assoc url-classloader-base
           :can-modify? (constantly false))))

(defn classloader-hierarchy
  "Returns a seq of classloaders, with the tip of the hierarchy first.
   Uses the current thread context ClassLoader as the tip ClassLoader
   if one is not provided."
  ([] (classloader-hierarchy (.. Thread currentThread getContextClassLoader)))
  ([tip]
    (->> tip
      (iterate #(.getParent %))
      (take-while boolean))))

(defn modifiable-classloader?
  "Returns true iff the given ClassLoader is of a type that satisfies
   the URLClasspath protocol, and it can be modified."
  [cl]
  (and (satisfies? URLClasspath cl)
       (can-modify? cl)))

(defn add-classpath
  "A corollary to the (deprecated) `add-classpath` in clojure.core. This implementation
   requires a java.io.File or String path to a jar file or directory, and will attempt
   to add that path to the right classloader (with the search rooted at the current
   thread's context classloader)."
  ([jar-or-dir classloader]
    (add-url classloader (.toURL (io/file jar-or-dir))))
  ([jar-or-dir]
    (let [classloaders (classloader-hierarchy)]
      (if-let [cl (last (filter modifiable-classloader? classloaders))]
        (add-classpath jar-or-dir cl)
        (throw (IllegalStateException. "Could not find a suitable classloader to modify from " classloaders))))))

(defprotocol Extension
  (resolve-extension [this]))

(extend-protocol Extension
  clojure.lang.Symbol
  (resolve-extension [this]
    (require (symbol (namespace this)))
    ((resolve this)))
  clojure.lang.IFn
  (resolve-extension [this] (this))
  String
  (resolve-extension [this]
    (resolve-extension (symbol this)))
  java.io.File
  (resolve-extension [this]
    (add-classpath this)
    (-> (JarFile. this)
        (.getManifest)
        (.getMainAttributes)
        (.getValue "IPA-Extension")
        (string/split #" ")
        (->>
         (mapcat resolve-extension)))))

(defn extensions
  [plugin-syms]
  (mapcat resolve-extension plugin-syms))

(defn extensions-supporting
  [plugins protocol]
  (filter #(satisfies? protocol %) plugins))
