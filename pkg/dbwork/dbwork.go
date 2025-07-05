package dbwork

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var DB DataBase

type DataBase interface {
	CheckCollisionsRefresh(hashRefresh string) error
	AddRefreshToDB(hashRefresh, GUID, userAgent, userIP string) error
	CheckWorkerRefreshAndStopping(refresh, GUID, userAgent string) error
}

type PostgresDataBase struct {
	db *sql.DB
}

type postgresDBParams struct {
	DBName   string `json:"dbName"`
	Host     string `json:"host"`
	User     string `json:"user"`
	Password string `json:"password"`
	SslMode  string `json:"sslmode"`
}

func (postgres *PostgresDataBase) CheckCollisionsRefresh(hashRefresh string) error {
	selectQuery := `SELECT id FROM refresh WHERE refresh_token=$1`

	rows, err := postgres.db.Query(selectQuery, hashRefresh)
	if err != nil {
		return err
	}
	defer rows.Close()

	var refreshInDB string

	for rows.Next() {
		err = rows.Scan(&refreshInDB)
		if err != nil {
			return err
		}
	}

	if refreshInDB == hashRefresh {
		return fmt.Errorf("Совпадение refresh токенов")
	}

	return nil
}

func (postgres *PostgresDataBase) AddRefreshToDB(
	hashRefresh, GUID, userAgent, userIP string,
) error {
	err := postgres.StopWorkerRefresh(GUID)
	if err != nil {
		return err
	}

	insertRefreshQuery := `INSERT INTO refresh
	                       (GUID, refresh_token, worker, user_agent, user_ip, expires_at)
	                       VALUES($1, $2, TRUE, $3, $4, $5);`

	_, err = postgres.db.Exec(
		insertRefreshQuery,
		GUID,
		hashRefresh,
		userAgent,
		userIP,
		time.Now().Add(76*time.Hour),
	)
	log.Println(err)
	if err != nil {
		return err
	}

	return nil
}

func (postgres *PostgresDataBase) CheckWorkerRefreshAndStopping(
	refresh, GUID, userAgent string,
) error {
	selectQuery := `SELECT refresh_token, expires_at, user_agent FROM refresh WHERE GUID=$1 AND worker=TRUE`

	rows, err := postgres.db.Query(selectQuery, GUID)
	if err != nil {
		return err
	}
	defer rows.Close()

	var realRefresh []byte
	var expires_at time.Time
	var userAgentBefore string

	for rows.Next() {
		err = rows.Scan(&realRefresh, &expires_at, &userAgentBefore)
		if err != nil {
			return err
		}
	}

	if userAgent != userAgentBefore {
	}

	if realRefresh == nil {
		return fmt.Errorf("У пользователя отсутствует активный refresh токен")
	}

	err = bcrypt.CompareHashAndPassword(realRefresh, []byte(refresh))
	if err == nil {
		err := postgres.StopWorkerRefresh(GUID)
		if err != nil {
			return err
		}

		if time.Now().After(expires_at) {
			return fmt.Errorf("Время действия refresh токена закончилось")
		}

		return nil
	}

	return fmt.Errorf("Refresh токен не совпал")
}

func (postgres *PostgresDataBase) StopWorkerRefresh(GUID string) error {
	updateQuery := `UPDATE refresh
	                SET worker=FALSE
	                WHERE GUID=$1 AND worker=TRUE`

	_, err := postgres.db.Exec(updateQuery, GUID)
	if err != nil {
		log.Println("WFWWWRG")
		return err
	}

	return nil
}

func InitializationPostgresDB() error {
	configFile, err := os.ReadFile("pkg/dbwork/config.json")
	if err != nil {
		return err
	}

	var config postgresDBParams

	err = json.Unmarshal(configFile, &config)
	if err != nil {
		return err
	}

	connStr := fmt.Sprintf(
		"host=%s dbname=%s user=%s password=%s sslmode=%s",
		config.Host,
		config.DBName,
		config.User,
		config.Password,
		config.SslMode,
	)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return err
	}

	if err = db.Ping(); err != nil {
		return err
	}

	postgres := &PostgresDataBase{db: db}

	err = postgres.verifyTableAndCreate()
	if err != nil {
		return err
	}

	DB = postgres

	return nil
}

func (postgres *PostgresDataBase) verifyTableAndCreate() error {
	exists, err := postgres.verifyTableExists("refresh")
	if err != nil {
		return err
	}

	if !exists {
		createRefreshQuery := `CREATE TABLE refresh(
		id BIGSERIAL PRIMARY KEY,
		GUID VARCHAR,
		refresh_token VARCHAR,
    user_agent VARCHAR,
    user_ip VARCHAR,
    expires_at TIMESTAMP,
		worker BOOLEAN
		);`

		_, err := postgres.db.Exec(createRefreshQuery)
		if err != nil {
			return err
		}
	}
	return nil
}

func (postgres *PostgresDataBase) verifyTableExists(name string) (bool, error) {
	var result string

	rows, err := postgres.db.Query("SELECT to_regclass($1);", "public."+name)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	for rows.Next() && result != name {
		rows.Scan(&result)
	}

	return result == name, rows.Err()
}
