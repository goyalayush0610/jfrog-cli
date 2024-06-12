package cmd

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var artifactoryServer string
var incrementLevel string
var username string
var apiKey string
var newVersion string

func init() {
	rootCmd.AddCommand(getVersionCmd)
	// Flags for the get version command
	getVersionCmd.Flags().StringVarP(&artifactoryServer, "server", "s", "", "Artifactory Server Host")
	getVersionCmd.Flags().StringVarP(&incrementLevel, "increment", "i", "", "Increment level: release, pre, patch, minor, or major")
	getVersionCmd.Flags().StringVarP(&username, "username", "u", "", "User name")
	getVersionCmd.Flags().StringVarP(&apiKey, "apikey", "k", "", "Api Key")

	rootCmd.AddCommand(publishCmd)
	// Flags for the publish command
	publishCmd.Flags().StringVarP(&artifactoryServer, "server", "s", "", "Artifactory Server Host")
	publishCmd.Flags().StringVarP(&newVersion, "version", "v", "", "Version number")
	publishCmd.Flags().StringVarP(&username, "username", "u", "", "User name")
	publishCmd.Flags().StringVarP(&apiKey, "apikey", "k", "", "Api Key")
}

// getVersionCmd represents the Get Upgraded Version command
var getVersionCmd = &cobra.Command{
	Use:   "get-version",
	Short: "Get upgraded version of a JFrog artifact",
	Run: func(cmd *cobra.Command, args []string) {
		if incrementLevel == "" || artifactoryServer == "" || username == "" || apiKey == "" {
			fmt.Println("Please provide increment level (release, pre, patch, minor, or major), artifactory server, username and api key")
			os.Exit(1)
		}

		if incrementLevel == "release" {
			fmt.Println("v0.0.1")
			return
		}

		artifactoryServerUrl := "https://" + artifactoryServer + "/artifactory"

		repositoryName, err := getModulePath()
		if err != nil {
			fmt.Println("Error fetching module path", err)
			os.Exit(1)
		}

		// Retrieve the current version
		currentVersion, err := getCurrentVersion(artifactoryServerUrl, repositoryName, username, apiKey)
		if err != nil {
			fmt.Println("Error fetching current version:", err)
			os.Exit(1)
		}

		// Increment version based on the provided level
		newVersion, err := incrementVersion(currentVersion, incrementLevel)
		if err != nil {
			fmt.Println("Error incrementing version:", err)
			os.Exit(1)
		}

		fmt.Printf(newVersion)
	},
}

var publishCmd = &cobra.Command{
	Use:   "publish",
	Short: "Publish an upgraded version of a JFrog artifact",
	Run: func(cmd *cobra.Command, args []string) {
		if newVersion == "" || artifactoryServer == "" || username == "" || apiKey == "" {
			fmt.Println("Please provide increment level (patch, minor, or major), artifactory server, username and api key")
			os.Exit(1)
		}

		// Publish the upgraded version
		err := publishNewVersion(artifactoryServer, newVersion, username, apiKey)
		if err != nil {
			fmt.Println("Error publishing new version:", err)
			os.Exit(1)
		}

		fmt.Println("Published upgraded version:", newVersion)
	},
}

func incrementVersion(currentVersion, incrementLevel string) (string, error) {
	parts := strings.Split(currentVersion, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid current version format: %s", currentVersion) // Return the same version if not in semver format (major.minor.patch)
	}

	switch incrementLevel {
	case "pre":
		patch := parts[2]
		newPre, err := getPreReleaseVersion(patch)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s.%s.%s", parts[0], parts[1], newPre), nil
	case "patch":
		patch := parts[2]
		newPatch := fmt.Sprintf("%d", parseVersionNumber(patch)+1)
		return fmt.Sprintf("%s.%s.%s", parts[0], parts[1], newPatch), nil
	case "minor":
		minor := parts[1]
		newMinor := fmt.Sprintf("%d", parseVersionNumber(minor)+1)
		return fmt.Sprintf("%s.%s.0", parts[0], newMinor), nil
	case "major":
		major := parts[0]
		if strings.HasPrefix(major, "v") {
			major = major[1:]
		}
		newMajor := fmt.Sprintf("%d", parseVersionNumber(major)+1)
		return fmt.Sprintf("v%s.0.0", newMajor), nil
	default:
		return "", fmt.Errorf("invalid increment level: %s", incrementLevel)
	}
}

func getPreReleaseVersion(patch string) (string, error) {
	parts := strings.Split(patch, "-")

	// Get current time in UTC
	currentTime := time.Now().Format("20060102150405")

	commitHash, err := getCommitHash()
	if err != nil {
		return "", err
	}

	// Generate pre-release version
	preReleaseVersion := fmt.Sprintf("%s-%s-%s", parts[0], currentTime, commitHash[:7])

	return preReleaseVersion, nil
}

func parseVersionNumber(versionPart string) int {
	parts := strings.Split(versionPart, "-")

	num := 0
	fmt.Sscanf(parts[0], "%d", &num)
	return num
}

func publishNewVersion(artifactoryServer string, newVersion string, username string, apiKey string) error {
	jfrogCommand := fmt.Sprintf("jfrog gp %s --url=%s --user=%s --password=%s", newVersion, artifactoryServer, username, apiKey)

	fmt.Println("Publishing Go artifact...")
	fmt.Println("Running command:", jfrogCommand)

	// Execute the JFrog CLI command
	cmd := exec.Command("sh", "-c", jfrogCommand)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		return err
	}

	return nil
}

type SearchResult struct {
	Results []struct {
		Name string `json:"name"`
	} `json:"results"`
}

func getCurrentGitBranch() (string, error) {
	cmd := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func isLocalBranchSyncedWithRemote(branch string) (bool, error) {
	// Fetch latest changes from the remote repository
	fetchCmd := exec.Command("git", "fetch", "origin", branch)
	if err := fetchCmd.Run(); err != nil {
		return false, err
	}

	// Get the commit hashes of local and remote branches
	localCmd := exec.Command("git", "rev-parse", "HEAD")
	localOutput, err := localCmd.Output()
	if err != nil {
		return false, err
	}
	remoteCmd := exec.Command("git", "rev-parse", fmt.Sprintf("origin/%s", branch))
	remoteOutput, err := remoteCmd.Output()
	if err != nil {
		return false, err
	}

	// Compare the commit hashes to check if they are the same
	return strings.TrimSpace(string(localOutput)) == strings.TrimSpace(string(remoteOutput)), nil
}

func getCurrentVersion(artifactoryServer string, repositoryName string, username string, apiKey string) (string, error) {
	url := fmt.Sprintf("%s/api/search/aql", artifactoryServer)
	payload := fmt.Sprintf(`items.find({ "repo": {"$eq":"go-local"}, "path": {"$match" : "%s/@v"}}).sort({"$desc":["created"]}).limit(1)`, repositoryName)

	client := &http.Client{}
	req, err := http.NewRequest("POST", url, strings.NewReader(payload))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return "", err
	}

	req.Header.Set("Content-Type", "text/plain")

	// Set basic authentication header
	auth := username + ":" + apiKey
	basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
	req.Header.Set("Authorization", basicAuth)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return "", err
	}

	// Parse JSON response to get the latest version
	var searchResult SearchResult
	err = json.Unmarshal(body, &searchResult)
	if err != nil {
		fmt.Println("Error parsing JSON:", err)
		return "", err
	}

	if len(searchResult.Results) > 0 {
		latestVersion := searchResult.Results[0].Name
		// Remove .info extension if present
		// Modify this logic based on the actual structure of the artifact name
		if strings.HasSuffix(latestVersion, ".info") {
			latestVersion = strings.TrimSuffix(latestVersion, ".info")
		}

		// Print the latest version
		return latestVersion, nil
	} else {
		return "", fmt.Errorf("no results found for the specified Go module")
	}
}

func getModulePath() (string, error) {
	cmd := exec.Command("go", "list", "-m")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	currentModule := strings.TrimSpace(string(output))
	return currentModule, nil
}

func getCommitHash() (string, error) {
	// Use Git command to get the latest commit hash
	cmd := exec.Command("git", "rev-parse", "HEAD")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("error getting commit hash: %s", err.Error())
	}

	// Compute SHA-1 hash of the commit hash
	hash := sha1.New()
	hash.Write(output)
	return hex.EncodeToString(hash.Sum(nil)), nil
}
