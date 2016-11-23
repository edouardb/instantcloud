package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/dghubble/go-twitter/twitter"
	"github.com/dghubble/oauth1"
	"github.com/jinzhu/gorm"
	_ "github.com/lib/pq"
	scw "github.com/scaleway/scaleway-cli/pkg/api"
	"github.com/urfave/cli"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"os"
	"sort"
	"strings"
	"time"
)

const defaultMaxConnections = 20

var (
	connection *gorm.DB
	Dbs        string
)

type Session struct {
	ScreenName   string
	UserID       int64
	ServerID     string
	State        string
	SessionEndAt time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    *time.Time
}

type AppConfig struct {
	Twitter struct {
		ConsumerKey       string `yaml:"consumer_key"`
		ConsumerSecret    string `yaml:"consumer_secret"`
		AccessToken       string `yaml:"access_token"`
		AccessTokenSecret string `yaml:"access_token_secret"`
		Username          string `yaml:"username"`
		Passphrase        string `yaml:"passphrase"`
	}
	Scw struct {
		AccessKey    string `yaml:"access_key"`
		SecretKey    string `yaml:"secret_key"`
		InstanceType string `yaml:"instance_type"`
		Region       string `yaml:"region"`
		SessionTime  int64  `yaml:"session_time"`
		Image        string `yaml:"image_id"`
		Limit        int    `yaml:"limit"`
	}
	Db struct {
		Host     string `yaml:"host"`
		Port     string `yaml:"port"`
		User     string `yaml:"user"`
		Password string `yaml:"password"`
		DbName   string `yaml:"dbname"`
		SSLMode  string `yaml:"ssl_mode"`
	}

	Messages struct {
		Busy               string `yaml:"busy"`
		FollowMe           string `yaml:"follow_me"`
		StartingInProgress string `yaml:"starting_in_progress"`
		AlreadyHaveSession string `yaml:"already_have_session"`
		ServerReady        string `yaml:"server_ready"`
		DmServerReady      string `yaml:"dm_server_ready"`
	}
}

var StdChars = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")

func NewPassword(length int) string {
	return rand_char(length, StdChars)
}

var log = logrus.New()

func rand_char(length int, chars []byte) string {
	new_pword := make([]byte, length)
	random_data := make([]byte, length+(length/4))
	clen := byte(len(chars))
	maxrb := byte(256 - (256 % len(chars)))
	i := 0
	for {
		if _, err := io.ReadFull(rand.Reader, random_data); err != nil {
			log.WithFields(logrus.Fields{
				"error": err,
			}).Fatal("Failed to rand char")
		}
		for _, c := range random_data {
			if c >= maxrb {
				continue
			}
			new_pword[i] = chars[c%clen]
			i++
			if i == length {
				return string(new_pword)
			}
		}
	}
}

// GetDB is an exported function that
// create or return a gorm DB pointer.
func GetDB() *gorm.DB {
	if connection == nil {
		co, err := gorm.Open("postgres", Dbs)
		if err != nil {
			log.WithFields(logrus.Fields{
				"error": err,
			}).Fatal("Failed to open database connection")
		}

		co.DB().SetMaxIdleConns(defaultMaxConnections / 5)
		co.DB().SetMaxOpenConns(defaultMaxConnections)
		connection = co
	}

	return connection
}

// CreateSession is an exported function that
// creates a new session.
func CreateSession(session *Session) error {
	db := GetDB()

	if err := db.Create(session).Error; err != nil {
		return err
	}
	return nil
}

// UpdateSession is an exported function that
// changes the session state
func UpdateSession(session *Session) error {
	db := GetDB()

	if err := db.Table("sessions").Where("user_id = ?", session.UserID).Updates(map[string]interface{}{"session_end_at": session.SessionEndAt, "state": session.State}).Error; err != nil {
		return err
	}
	return nil
}

// CountActiveSession is an exported function that
// return the number of active session
func CountActiveSession(activeSession *int) error {
	db := GetDB()

	if err := db.Table("sessions").Where("state = ?", "running").Count(&activeSession).Error; err != nil {
		return err
	}
	return nil
}

// GetOutdatedSessions is an exported function that
// returns the list of expired  sessions.
func GetOutdatedSessions(sessions *[]Session) error {
	db := GetDB()

	if err := db.Debug().Unscoped().Where("(deleted_at != null OR session_end_at <= ?) AND state = ?", time.Now(), "running").Find(sessions).Error; err != nil {
		return err
	}
	return nil
}

// DeleteOutdatedSessions is an exported function that
// soft delete outdated sessions
func DeleteOutdatedSession(session *Session) error {
	db := GetDB()
	if err := db.Where("server_id = ?", session.ServerID).Delete(session).Error; err != nil {
		return err
	}
	return nil
}

// GetSessionByUserID is an exported function that
// returns a session based on a user ID.
func GetSessionByUserID(session *Session, userID int64) error {
	db := GetDB()

	if err := db.Where(Session{UserID: userID}).First(session).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return err
		}
		log.WithFields(logrus.Fields{
			"error": err,
		}).Warn("Failed get session associated to user ID")
	}
	return nil
}

// LoadConfig is an exported function that
// bind a configuration file to a configuration struct.
func LoadConfig(configFile *string, appConfig *AppConfig) {
	log.Info("Initialize configuration")

	stream, err := ioutil.ReadFile(*configFile)
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": err,
		}).Fatal("Failed to open configuration file")
	}

	if err := yaml.Unmarshal(stream, &appConfig); err != nil {
		log.WithFields(logrus.Fields{
			"error": err,
		}).Fatal("Failed to unmarshal stream")
	}
	log.Info("Successfully initialize configuration")
}

// SetupTwitter is an exported function that
// configure twitter app and returns a client.
func SetupTwitter(appConfig *AppConfig) *twitter.Client {

	log.Info("Initialize twitter client")

	config := oauth1.NewConfig(appConfig.Twitter.ConsumerKey, appConfig.Twitter.ConsumerSecret)
	token := oauth1.NewToken(appConfig.Twitter.AccessToken, appConfig.Twitter.AccessTokenSecret)

	httpClient := config.Client(oauth1.NoContext, token)
	client := twitter.NewClient(httpClient)

	log.Info("Successfully initialize twitter client")

	return client
}

// Tweet is an exported function that tweet a message.
func Tweet(twitterClient *twitter.Client, message string, tweetRefID *int64) {
	statusParams := twitter.StatusUpdateParams{}
	if tweetRefID != nil {
		statusParams.InReplyToStatusID = *tweetRefID
	}

	if _, _, err := twitterClient.Statuses.Update(fmt.Sprintf("%s (%s)", message, time.Now().Format("2006-01-02 15:04:05")), &statusParams); err != nil {
		log.WithFields(logrus.Fields{
			"error": err,
		}).Warn("Failed to tweet")
	}
}

// DM is an exported function that DM a message
// to the specified user.
func DM(twitterClient *twitter.Client, userID int64, screenName string, message string) {
	params := &twitter.DirectMessageNewParams{
		UserID:     userID,
		ScreenName: screenName,
		Text:       message,
	}
	if _, _, err := twitterClient.DirectMessages.New(params); err != nil {
		log.WithFields(logrus.Fields{
			"error": err,
		}).Warn("Failed to send DM")
	}
}

// CheckFollowMe is an exported function that
// validate the tweet user source follow the account.
func CheckFollowMe(tweet *twitter.Tweet, twitterClient *twitter.Client, appConfig *AppConfig, tweetRefID *int64) bool {
	params := &twitter.FollowerIDParams{
		ScreenName: appConfig.Twitter.Username,
		Count:      5000,
	}

	followerIDs, _, err := twitterClient.Followers.IDs(params)
	if err != nil {
		return true
	}

	for _, ID := range followerIDs.IDs {
		if ID == tweet.User.ID {
			return false
		}
	}
	if err := GetSessionByUserID(&Session{}, tweet.User.ID); err != nil {
		session := &Session{
			UserID:     tweet.User.ID,
			ScreenName: tweet.User.ScreenName,
			State:      "pending",
		}

		if err := CreateSession(session); err != nil {
			return true
		}
	}

	Tweet(
		twitterClient,
		fmt.Sprintf("@%s %s", tweet.User.ScreenName, appConfig.Messages.FollowMe),
		tweetRefID,
	)
	return true
}

// SpawnInstance is an exported function that
// creates & starts a server. It waits the server is booted before sending the credentials.
func SpawnInstance(user *twitter.User, twitterClient *twitter.Client, appConfig *AppConfig, tweetRefID *int64) error {
	var count int
	if err := CountActiveSession(&count); err != nil {
		return err
	}

	if count > appConfig.Scw.Limit {
		return errors.New("Server limit reached")
	}

	s, _ := scw.NewScalewayAPI(appConfig.Scw.AccessKey, appConfig.Scw.SecretKey, "SCW-Twt", appConfig.Scw.Region)
	password := NewPassword(6)
	server := scw.ScalewayServerDefinition{
		Name:           user.ScreenName,
		Image:          &appConfig.Scw.Image,
		Organization:   appConfig.Scw.AccessKey,
		CommercialType: appConfig.Scw.InstanceType,
		Tags:           []string{password},
	}

	id, err := s.PostServer(server)

	session := &Session{
		UserID:     user.ID,
		ScreenName: user.ScreenName,
		ServerID:   id,
		State:      "starting",
	}

	if err != nil {
		return err
	}

	if err := CreateSession(session); err != nil {
		return err
	}

	log.WithFields(logrus.Fields{
		"twitter ID": user.ID,
		"server ID":  id,
	}).Info("Server created")
	Tweet(
		twitterClient,
		fmt.Sprintf("@%s %s", user.ScreenName, appConfig.Messages.StartingInProgress),
		tweetRefID,
	)

	if err := scw.StartServer(s, id, true); err != nil {
		return err

	}
	log.WithFields(logrus.Fields{
		"twitter ID": user.ID,
		"server ID":  id,
	}).Info("Server started")

	server_info, _ := s.GetServer(id)

	now := time.Now()
	session.SessionEndAt = now.Add(time.Duration(appConfig.Scw.SessionTime * 60000000000))
	session.State = "running"

	if err := UpdateSession(session); err != nil {
		return err
	}

	Tweet(
		twitterClient,
		fmt.Sprintf("@%s %s", user.ScreenName, appConfig.Messages.ServerReady),
		tweetRefID,
	)

	DM(
		twitterClient,
		user.ID,
		user.ScreenName,
		fmt.Sprintf("%s %s ubuntu@%s", appConfig.Messages.DmServerReady, password, server_info.PublicAddress.IP),
	)
	return nil
}

// HaveRunningSession is an exported function that
// check if the user have a running session
func CheckRunningSession(userID int64) bool {
	if err := GetSessionByUserID(&Session{}, userID); err != nil {
		return false
	}
	return true
}

// MonitorTwitterStream is an exported function that
// tracks everything that mention @username on twitter.
func MonitorTwitterStream(twitterClient *twitter.Client, appConfig *AppConfig) {
	params := &twitter.StreamUserParams{
		With:          "followings",
		StallWarnings: twitter.Bool(true),
	}

	demux := twitter.NewSwitchDemux()

	demux.Event = func(event *twitter.Event) {
		go func(event *twitter.Event) {
			fmt.Printf("%#v\n", event)
			if event.Event == "follow" {
				var session Session
				if err := GetSessionByUserID(&session, event.Source.ID); err != nil {
					return
				}
				if session.State == "pending" {
					DeleteOutdatedSession(&session)
					if err := SpawnInstance(event.Source, twitterClient, appConfig, nil); err != nil {
						log.WithFields(logrus.Fields{
							"error": err,
						}).Warn("Failed to spawn instance")

						Tweet(
							twitterClient,
							fmt.Sprintf("@%s %s", event.Source.ScreenName, appConfig.Messages.Busy),
							nil,
						)
					}
				}
			}
		}(event)
	}

	demux.Tweet = func(tweet *twitter.Tweet) {
		if res := strings.Contains(strings.ToLower(tweet.Text), appConfig.Twitter.Passphrase); res {
			log.WithFields(logrus.Fields{
				"twitter ID": tweet.User.ID,
				"tweet":      tweet.Text,
			}).Info("New server requested")

			tweetRefID := tweet.ID

			go func(tweet *twitter.Tweet, twitterClient *twitter.Client, appConfig *AppConfig) {
				if res := CheckFollowMe(tweet, twitterClient, appConfig, &tweetRefID); !res {
					if res := CheckRunningSession(tweet.User.ID); !res {
						if err := SpawnInstance(tweet.User, twitterClient, appConfig, &tweetRefID); err != nil {
							log.WithFields(logrus.Fields{
								"error": err,
							}).Warn("Failed to spawn instance")

							Tweet(
								twitterClient,
								fmt.Sprintf("@%s %s", tweet.User.ScreenName, appConfig.Messages.Busy),
								&tweetRefID,
							)

						}
					} else {
						Tweet(
							twitterClient,
							fmt.Sprintf("@%s %s", tweet.User.ScreenName, appConfig.Messages.AlreadyHaveSession),
							&tweetRefID,
						)

						log.WithFields(logrus.Fields{
							"twitter ID": tweet.User.ID,
							"tweet":      tweet.Text,
						}).Info("User already have an active session")

					}
				}
			}(tweet, twitterClient, appConfig)
		}

	}

	stream, err := twitterClient.Streams.User(params)
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": err,
		}).Warn("Failed to initialize streams filter")
	}
	for message := range stream.Messages {
		demux.Handle(message)
	}
}

func MagicCleaner(appConfig *AppConfig) {
	var sessions []Session

	s, _ := scw.NewScalewayAPI(appConfig.Scw.AccessKey, appConfig.Scw.SecretKey, "Gloops", appConfig.Scw.Region)
	if err := GetOutdatedSessions(&sessions); err != nil {
		log.WithFields(logrus.Fields{
			"error": err,
		}).Warn("Failed to fetch outdated session")
	} else {
		if len(sessions) > 0 {
			for _, session := range sessions {
				if err := s.DeleteServerForce(session.ServerID); err != nil {
					log.WithFields(logrus.Fields{
						"error": err,
					}).Warn("Failed to delete outdated session")
				}
				time.Sleep(1 * time.Second)
				DeleteOutdatedSession(&session)
			}
		}
	}
}

// InitDb is an exported function that
// initializes db connection and migration
func InitDb(appConfig *AppConfig) {
	log.Info("Initialize database connection")
	Dbs = fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		appConfig.Db.Host,
		appConfig.Db.Port,
		appConfig.Db.User,
		appConfig.Db.Password,
		appConfig.Db.DbName,
		appConfig.Db.SSLMode,
	)
	log.Info("Successfully initialize database connection")
	db := GetDB()
	log.Info("Start table migrations")
	db.AutoMigrate(
		&Session{},
	)
	log.Info("Table migrations achieved")
}

func main() {
	var config string
	appConfig := AppConfig{}

	app := cli.NewApp()

	app.Name = "instantcloud"
	app.Usage = "An SSD cloud server in seconds!"

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:        "config, c",
			Usage:       "Load configuration from `FILE`",
			Destination: &config,
		},
	}

	sort.Sort(cli.FlagsByName(app.Flags))

	app.Commands = []cli.Command{
		{
			Name:  "run",
			Usage: "Run instantcloud",
			Action: func(c *cli.Context) error {

				LoadConfig(&config, &appConfig)
				InitDb(&appConfig)

				client := SetupTwitter(&appConfig)
				MonitorTwitterStream(client, &appConfig)
				return nil

			},
		},
		{
			Name:  "clean",
			Usage: "Clean outdated sessions",
			Action: func(c *cli.Context) error {

				LoadConfig(&config, &appConfig)
				InitDb(&appConfig)

				MagicCleaner(&appConfig)
				return nil

			},
		},
	}

	app.Run(os.Args)
}
