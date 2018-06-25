package main

import (
	"errors"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/boltdb/bolt"
	"github.com/fossoreslp/go-uuid-v4"
	"github.com/julienschmidt/httprouter"
)

var db *bolt.DB

func main() {
	db, err := bolt.Open("keys.db", 0600, bolt.DefaultOptions)
	if err != nil {
		log.Fatalf("Failed to open database: %s\n", err.Error())
	}
	defer db.Close()

	router := httprouter.New()
	router.GET("/getKey/:kid", func(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
		db.View(func(tx *bolt.Tx) error {
			resp := tx.Bucket([]byte("keys")).Get([]byte(params.ByName("kid")))
			if resp == nil {
				w.WriteHeader(404)
				w.Write([]byte("Key not found"))
				return errors.New("Key not found")
			}
			w.WriteHeader(200)
			w.Write(resp)
			return nil
		})
	})
	router.POST("/addKey", func(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
		newKey, err := ioutil.ReadAll(req.Body)
		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte("Could not parse body: " + err.Error()))
		}
		kuuid, err := uuid.New()
		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte("Failed to generate key ID: " + err.Error()))
		}
		kid, _ := kuuid.MarshalBinary()
		db.Update(func(tx *bolt.Tx) error {
			err := tx.Bucket([]byte("keys")).Put(kid, newKey)
			if err != nil {
				w.WriteHeader(500)
				w.Write([]byte("Failed to insert key into database: " + err.Error()))
				return err
			}
			w.WriteHeader(200)
			w.Write(kid)
			return nil
		})
	})
	log.Fatal(http.ListenAndServe(":8080", router))
}
