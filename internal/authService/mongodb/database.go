package mongodb

import (
	"time"
	"context"
	"net/http"
	"encoding/json"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"github.com/NOSTRADA88/authService/internal/authService/config"
	"github.com/NOSTRADA88/authService/internal/authService/logger"
)

func DbInstance() *mongo.Client {
	config := config.AppConfig
	logger := logger.Logger

	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(config.MongoDBURL))
	if err != nil {
		logger.Fatal(err)
	}

	createTTLIndex(client)

	return client
}

var MongoClient *mongo.Client = DbInstance()
const collectionName = "refreshTokens"

func CloseConnection(client *mongo.Client) {
	err := client.Disconnect(context.Background())
	if err != nil {
		logger := logger.Logger
		logger.Fatal(err)
	}
}

func OpenCollection(client *mongo.Client, name string) *mongo.Collection {
	var collection *mongo.Collection = client.Database("cluster0").Collection(name)
	return collection
}

type RefreshToken struct {
	Token string `bson:"token"`
	ExpirationTime time.Time `bson:"expirationTime"`
	GUID int `bson:"guid"`
}

func StoreRefreshToken(client *mongo.Client, refreshTokenString string, guid int, expirationTime int64) error {
	collection := OpenCollection(client, collectionName)

	expirationTimeDate := time.Unix(expirationTime, 0)

	refreshToken := RefreshToken{
		Token: refreshTokenString,
		ExpirationTime: expirationTimeDate,
		GUID: guid,
	}
	
	_, err := collection.ReplaceOne(
		context.Background(),
		bson.M{"guid": guid}, 
		refreshToken, 
		options.Replace().SetUpsert(true),
	)
	
    return err
}

func UpdateTokenPair(client *mongo.Client, w http.ResponseWriter, GUID int) error {
	collection := OpenCollection(client, collectionName)

	refreshToken := new(RefreshToken)

	err := collection.FindOne(context.Background(), bson.M{"guid": GUID}).Decode(refreshToken)
	if err != nil {
		logger.Logger.Printf("Error finding the refresh token: %v\n", err)
		return err
	}
	timeExpirationNew := time.Now().Add(2 * time.Minute)
	if refreshToken.ExpirationTime.Before(time.Now()) {
		logger.Logger.Println("Refresh token expired")
		collection.FindOneAndDelete(context.Background(), bson.M{"guid": GUID})
		accessToken, err := GenerateTokensPair(GUID, timeExpirationNew)
		if err != nil {
			logger.Logger.Println("Error generating tokens pair")
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"message": "Error generating tokens pair", "error": err.Error()})
			return err
		}
		http.SetCookie(w, &http.Cookie{
			Name: "access_token",
			Value: accessToken,
			HttpOnly: true,
			Expires: timeExpirationNew,
		})
		json.NewEncoder(w).Encode(map[string]string{"message": "Token pair was updated due to expire time. New access token is in the cookie"})
		return nil 
	} else {
		accessToken, err := GenerateTokensPair(GUID, timeExpirationNew)
		if err != nil {
			logger.Logger.Println("Error generating tokens pair")
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"message": "Error generating tokens pair", "error": err.Error()})
			return err
		
		}
		http.SetCookie(w, &http.Cookie{
			Name: "access_token",
			Value: accessToken,
			HttpOnly: true,
			Expires: timeExpirationNew,
		})
	}
	
	return nil 
}

func GenerateTokensPair(guid int, expirationDate time.Time) (string, error) {
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"GUID": guid,
		"exp": expirationDate.Unix(),
	})

	accessTokenString, err := accessToken.SignedString([]byte(config.AppConfig.SecretKey))
	if err != nil {
		return "", err
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"GUID": guid,
		"exp": expirationDate.Add(3 * time.Minute).Unix(),
	})
	refreshTokenString, err := refreshToken.SignedString([]byte(config.AppConfig.SecretKey))
	if err != nil {
		return "", err
	}
	errStore := StoreRefreshToken(MongoClient, refreshTokenString, guid, expirationDate.Add(1 * time.Minute).Unix())
	if errStore != nil {
		return "", errStore
	}

	return accessTokenString, nil
}

func createTTLIndex(client *mongo.Client) error {
	collection := OpenCollection(client, collectionName)

	indexModel := mongo.IndexModel {
		Keys: bson.M{
			"expirationTime": 1,
		},
		Options: options.Index().SetExpireAfterSeconds(0),
	}

	_, err := collection.Indexes().CreateOne(context.Background(), indexModel)

	return err
}


