package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

var artifactoryServer string
var incrementLevel string
var username string
var apiKey string

func init() {
	rootCmd.AddCommand(publishCmd)

	// Flags for the publish command
	publishCmd.Flags().StringVarP(&artifactoryServer, "server", "s", "", "Artifactory Server Host")
	publishCmd.Flags().StringVarP(&incrementLevel, "increment", "i", "", "Increment level: patch, minor, or major")
	publishCmd.Flags().StringVarP(&username, "username", "u", "", "User name")
	publishCmd.Flags().StringVarP(&apiKey, "apikey", "k", "", "Api Key")
}

// publishCmd represents the publish command
var publishCmd = &cobra.Command{
	Use:   "publish",
	Short: "Publish an upgraded version of a JFrog artifact",
	Run: func(cmd *cobra.Command, args []string) {
		if incrementLevel == "" || artifactoryServer == "" || username == "" || apiKey == "" {
			fmt.Println("Please provide increment level (patch, minor, or major), artifactory server, username and api key")
			return
		}

		branch, err := getCurrentGitBranch()
		if err != nil {
			fmt.Println("Error:", err)
			return
		}

		if branch != "master" {
			fmt.Println("Artifacts can be published only from master, please switch to master branch")
			return
		}

		artifactoryServerUrl := "https://" + artifactoryServer + "/artifactory"

		repositoryName, err := getModulePath()
		if err != nil {
			fmt.Println("Error fetching module path", err)
			return
		}

		// Retrieve the current version
		currentVersion, err := getCurrentVersion(artifactoryServerUrl, repositoryName, username, apiKey)
		if err != nil {
			fmt.Println("Error fetching current version:", err)
			return
		}

		fmt.Println("Current Version: ", currentVersion)

		// Increment version based on the provided level
		newVersion := incrementVersion(currentVersion, incrementLevel)

		var option string
		fmt.Printf("Publishing version %s, please confirm (y/n): ", newVersion)
		fmt.Scanln(&option)

		if option != "y" {
			fmt.Println("Aborting!")
			return
		}

		// Publish the upgraded version
		err = publishNewVersion(artifactoryServer, newVersion, username, apiKey)
		if err != nil {
			fmt.Println("Error publishing new version:", err)
			return
		}

		fmt.Println("Published upgraded version:", newVersion)
	},
}

func incrementVersion(currentVersion, incrementLevel string) string {
	parts := strings.Split(currentVersion, ".")
	if len(parts) != 3 {
		return currentVersion // Return the same version if not in semver format (major.minor.patch)
	}

	switch incrementLevel {
	case "patch":
		patch := parts[2]
		newPatch := fmt.Sprintf("%d", parseVersionNumber(patch)+1)
		return fmt.Sprintf("%s.%s.%s", parts[0], parts[1], newPatch)
	case "minor":
		minor := parts[1]
		newMinor := fmt.Sprintf("%d", parseVersionNumber(minor)+1)
		return fmt.Sprintf("%s.%s.0", parts[0], newMinor)
	case "major":
		major := parts[0]
		newMajor := fmt.Sprintf("%d", parseVersionNumber(major)+1)
		return fmt.Sprintf("%s.0.0", newMajor)
	default:
		return currentVersion
	}
}

func parseVersionNumber(versionPart string) int {
	num := 0
	fmt.Sscanf(versionPart, "%d", &num)
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
