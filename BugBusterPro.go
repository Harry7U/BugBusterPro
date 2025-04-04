package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// --- Color Constants ---
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
)

// --- Configuration Struct ---
type Config struct {
	Domain             string
	OutputDir          string
	WordlistPath       string // Path for feroxbuster wordlist
	NucleiTemplatesDir string // Path for Nuclei templates base directory
	Force              bool
	Threads            int // General thread/concurrency hint
	LogFile            *os.File
	Logger             *log.Logger
}

// --- StepInfo Struct ---
type StepInfo struct {
	Name         string
	Description  string
	Command      string
	OutputFile   string // File *expected* to be created by the command's redirection
	RequiresPipe bool   // Flag to indicate if the command uses shell pipes/redirection
	Completed    bool
}

// --- Required Tools ---
// (Keep the list as before, ensuring go, nuclei, feroxbuster, etc. are there)
var requiredTools = []string{
	"go", "subfinder", "httpx", "katana", "waybackurls", "otxurls",
	"feroxbuster", "nuclei", "subzy", "qsreplace", "gf", "bxss",
	"sort", "grep", "cat", "sh", "echo",
}

func main() {
	// --- Command-Line Flags ---
	domain := flag.String("domain", "", "Target domain to scan (required)")
	outputDir := flag.String("output-dir", "output", "Directory to store scan results")

	// --- Wordlist Path Logic ---
	// Start with a basic default, then check preferred locations
	defaultWordlist := "common.txt" // Fallback if no paths found
	// Prioritize user-specified snap path
	snapWordlistPath := "/snap/seclists/current/Discovery/Web-Content/common.txt"
	usrShareSecListsWordlistPath := "/usr/share/seclists/Discovery/Web-Content/common.txt"
	usrShareDirbWordlistPath := "/usr/share/wordlists/dirb/common.txt"

	if _, err := os.Stat(snapWordlistPath); err == nil {
		defaultWordlist = snapWordlistPath
	} else if _, err := os.Stat(usrShareSecListsWordlistPath); err == nil {
		defaultWordlist = usrShareSecListsWordlistPath
	} else if _, err := os.Stat(usrShareDirbWordlistPath); err == nil {
		defaultWordlist = usrShareDirbWordlistPath
	} // else: keep the basic "common.txt" or let the user specify

	wordlistPath := flag.String("wordlist", defaultWordlist, "Path to wordlist for directory brute-forcing")

	// --- Nuclei Templates Path ---
	nucleiTemplatesDir := flag.String("nuclei-templates-dir", "/opt/nuclei-templates/", "Base directory for Nuclei templates")

	force := flag.Bool("force", false, "Force rerun of all steps, even if output files exist")
	threads := flag.Int("threads", 25, "Default number of threads/concurrency for tools")
	flag.Parse()

	if *domain == "" {
		fmt.Println(colorRed + "Error: --domain is required." + colorReset)
		flag.Usage()
		os.Exit(1)
	}

	// --- Create Config ---
	config := Config{
		Domain:             *domain,
		OutputDir:          filepath.Clean(*outputDir),
		WordlistPath:       *wordlistPath,
		NucleiTemplatesDir: *nucleiTemplatesDir, // Store the path
		Force:              *force,
		Threads:            *threads,
	}

	// --- Initialization ---
	if err := initialize(&config); err != nil {
		fmt.Printf(colorRed+"Initialization failed: %v\n"+colorReset, err)
		os.Exit(1)
	}
	defer config.LogFile.Close()

	// --- Check & Install Tools ---
	if !checkAndInstallTools(&config) {
		config.Logger.Println(colorRed + "Required tools check failed. Please install missing tools manually and try again." + colorReset)
		os.Exit(1)
	}

	// --- Create Directories ---
	createDirectories(&config)

	// --- Define Steps ---
	steps := defineSteps(&config)

	// --- Run Steps ---
	runAllSteps(&config, steps)

	// --- Print Summary ---
	printSummary(&config, steps)

	config.Logger.Println(colorGreen + "\nBugBusterPro finished." + colorReset)
}

// --- initialize: Set up logging and print banner ---
func initialize(config *Config) error {
	// Create base output directory first
	err := os.MkdirAll(config.OutputDir, 0755)
	if err != nil {
		return fmt.Errorf("error creating base output directory %s: %v", config.OutputDir, err)
	}

	// Create logs directory
	logsDir := filepath.Join(config.OutputDir, "logs")
	err = os.MkdirAll(logsDir, 0755)
	if err != nil {
		return fmt.Errorf("error creating logs directory %s: %v", logsDir, err)
	}

	// Create log file
	logFileName := filepath.Join(logsDir, fmt.Sprintf("bugbusterpro_%s_%s.log", config.Domain, time.Now().Format("20060102_150405")))
	logFile, err := os.Create(logFileName)
	if err != nil {
		return fmt.Errorf("error creating log file %s: %v", logFileName, err)
	}

	multiWriter := io.MultiWriter(os.Stdout, logFile)
	logger := log.New(multiWriter, "", log.Ldate|log.Ltime|log.Lmicroseconds)

	config.LogFile = logFile
	config.Logger = logger

	printBanner(config) // Print banner AFTER logger is set up

	// Check wordlist existence
	if _, err := os.Stat(config.WordlistPath); os.IsNotExist(err) {
		config.Logger.Printf(colorYellow+"Warning: Specified wordlist '%s' not found. Directory brute-forcing (Step 10) might fail.", config.WordlistPath+colorReset)
		config.Logger.Printf(colorYellow+"Use the --wordlist flag to specify the correct path."+colorReset)
	} else {
         config.Logger.Printf("Using wordlist: %s", config.WordlistPath)
    }

	// Check Nuclei templates directory existence
	if _, err := os.Stat(config.NucleiTemplatesDir); os.IsNotExist(err) {
		config.Logger.Printf(colorYellow+"Warning: Specified Nuclei templates directory '%s' not found. Nuclei scans might fail.", config.NucleiTemplatesDir+colorReset)
		config.Logger.Printf(colorYellow+"Ensure templates are present or use the --nuclei-templates-dir flag. Run 'nuclei -update-templates -td %s' manually if needed.", config.NucleiTemplatesDir+colorReset)
	} else {
         config.Logger.Printf("Using Nuclei templates directory: %s", config.NucleiTemplatesDir)
         config.Logger.Printf(colorYellow+"Note: Ensure Nuclei templates are up-to-date by running: nuclei -update-templates -td %s"+colorReset, config.NucleiTemplatesDir)
    }

	return nil
}

// --- printBanner: Display the tool's banner ---
func printBanner(config *Config) {
	banner := `
██████╗ ██╗   ██╗ ██████╗ ██████╗ ██╗   ██╗███████╗████████╗███████╗██████╗ ██████╗ ██████╗  ██████╗
██╔══██╗██║   ██║██╔════╝ ██╔══██╗██║   ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔═══██╗
██████╔╝██║   ██║██║  ███╗██████╔╝██║   ██║███████╗   ██║   █████╗  ██████╔╝██████╔╝██████╔╝██║   ██║
██╔══██╗██║   ██║██║   ██║██╔══██╗██║   ██║╚════██║   ██║   ██╔══╝  ██╔══██╗██╔═══╝ ██╔══██╗██║   ██║
██████╔╝╚██████╔╝╚██████╔╝██████╔╝╚██████╔╝███████║   ██║   ███████╗██║  ██║██║     ██║  ██║╚██████╔╝
╚═════╝  ╚═════╝  ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝
                                                                                         v1.1.1 (Path Update)
`
	fmt.Println(colorCyan + banner + colorReset)
	config.Logger.Printf("Starting BugBusterPro for domain: %s", config.Domain)
	config.Logger.Printf("Output directory: %s", config.OutputDir)
	// Don't log WordlistPath/NucleiTemplatesDir here, logged in initialize() after checks
	config.Logger.Printf("Force rerun: %t", config.Force)
	config.Logger.Printf("Default Threads/Concurrency: %d", config.Threads)
	config.Logger.Printf("Log file: %s", config.LogFile.Name())
}

// --- checkAndInstallTools: Verify required tools, attempt installation ---
func checkAndInstallTools(config *Config) bool {
	config.Logger.Println(colorYellow + "Checking required tools..." + colorReset)
	allToolsFound := true
	goInstalled := isToolInstalled("go")

	for _, tool := range requiredTools {
		if !isToolInstalled(tool) {
			isGoTool := contains([]string{"subfinder", "httpx", "katana", "waybackurls", "otxurls", "nuclei", "subzy", "qsreplace", "gf", "bxss"}, tool)
			isInstallablePkg := contains([]string{"feroxbuster"}, tool) // Tools potentially installed via package manager

			if tool == "go" {
				config.Logger.Printf(colorRed+"Tool %s not found. Please install Go manually (https://golang.org/doc/install)."+colorReset, tool)
				allToolsFound = false
			} else if isGoTool {
				if !goInstalled {
					config.Logger.Printf(colorRed+"Tool %s not found, and Go is not installed. Cannot install automatically."+colorReset, tool)
					allToolsFound = false
				} else {
					config.Logger.Printf(colorYellow+"Tool %s not found. Attempting installation via 'go install'..."+colorReset, tool)
					if !installTool(config, tool) { // Pass config for nuclei template path
						allToolsFound = false
					}
				}
			} else if isInstallablePkg {
				config.Logger.Printf(colorYellow+"Tool %s not found. Attempting installation via package manager or cargo..."+colorReset, tool)
				if !installTool(config, tool) {
					allToolsFound = false
				}
			} else { // Basic utils
				config.Logger.Printf(colorRed+"Required utility '%s' not found in PATH. Please install it using your system's package manager."+colorReset, tool)
				allToolsFound = false
			}
		} else {
			config.Logger.Printf(colorGreen+"Tool %s found."+colorReset, tool)
		}
	}

	if !allToolsFound {
		config.Logger.Println(colorRed + "One or more required tools are missing or could not be installed." + colorReset)
	} else {
		config.Logger.Println(colorGreen + "All required tools appear to be present." + colorReset)
	}
	return allToolsFound
}

// --- isToolInstalled: Check if command exists in PATH ---
func isToolInstalled(tool string) bool {
	_, err := exec.LookPath(tool)
	return err == nil
}

// --- installTool: Attempt to install a missing tool ---
func installTool(config *Config, tool string) bool {
	config.Logger.Printf("Attempting to install %s...", tool)
	var cmd *exec.Cmd
	installSuccess := false // Flag specifically for package manager success

	// Determine the installation command
	switch tool {
	// --- Go Tools ---
	case "subfinder":
		cmd = exec.Command("go", "install", "-v", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
	case "httpx":
		cmd = exec.Command("go", "install", "-v", "github.com/projectdiscovery/httpx/cmd/httpx@latest")
	case "katana":
		cmd = exec.Command("go", "install", "-v", "github.com/projectdiscovery/katana/cmd/katana@latest")
	case "waybackurls":
		cmd = exec.Command("go", "install", "-v", "github.com/tomnomnom/waybackurls@latest")
	case "otxurls":
		cmd = exec.Command("go", "install", "-v", "github.com/lc/otxurls@latest")
	case "nuclei":
		cmd = exec.Command("go", "install", "-v", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
	case "subzy":
		cmd = exec.Command("go", "install", "-v", "github.com/LukaSikic/subzy@latest")
	case "qsreplace":
		cmd = exec.Command("go", "install", "-v", "github.com/tomnomnom/qsreplace@latest")
	case "gf":
		cmd = exec.Command("go", "install", "-v", "github.com/tomnomnom/gf@latest")
		defer func() { // Show note after potential install attempt
			if isToolInstalled("gf") {
				config.Logger.Printf(colorYellow + "Note: 'gf' installed. Ensure you have gf patterns setup (e.g., from https://github.com/tomnomnom/gf)." + colorReset)
			}
		}()
	case "bxss":
		cmd = exec.Command("go", "install", "-v", "github.com/ethicalhackingplayground/bxss@latest")

	// --- Other Tools (Package Manager / Cargo) ---
	case "feroxbuster":
		pkgManagers := []struct {
			name    string
			updateCmd []string
			installCmd []string
		}{
			{"apt-get", []string{"sudo", "apt-get", "update"}, []string{"sudo", "apt-get", "install", "-y", "feroxbuster"}},
			{"yum", nil, []string{"sudo", "yum", "install", "-y", "feroxbuster"}}, // Assuming EPEL or base repo
			{"dnf", nil, []string{"sudo", "dnf", "install", "-y", "feroxbuster"}},
			{"pacman", []string{"sudo", "pacman", "-Sy"}, []string{"sudo", "pacman", "-S", "--noconfirm", "feroxbuster"}},
		}

		installedViaPkg := false
		for _, pm := range pkgManagers {
			if isToolInstalled(pm.name) {
				config.Logger.Printf("Trying to install feroxbuster using %s...", pm.name)
				// Run update command if specified
				if pm.updateCmd != nil {
					update := exec.Command(pm.updateCmd[0], pm.updateCmd[1:]...)
					runInstallCommand(config, update, tool+" ("+pm.name+" update)") // Log output, don't fail install if update fails
				}
				// Run install command
				install := exec.Command(pm.installCmd[0], pm.installCmd[1:]...)
				if err := runInstallCommand(config, install, tool+" ("+pm.name+" install)"); err == nil {
					installSuccess = true // Mark success
					installedViaPkg = true
					break // Stop checking other package managers
				}
			}
		}

		// If not installed via package manager, try cargo
		if !installedViaPkg {
			if isToolInstalled("cargo") {
				config.Logger.Printf("Trying to install feroxbuster using cargo...")
				cmd = exec.Command("cargo", "install", "feroxbuster")
			} else {
				config.Logger.Printf(colorRed + "Cannot install feroxbuster automatically: No supported package manager found, and cargo is not installed." + colorReset)
				return false
			}
		}
		// If installed via pkg manager, cmd remains nil, installSuccess is true

	default:
		config.Logger.Printf(colorRed+"Unknown tool for installation: %s"+colorReset, tool)
		return false
	}

	// --- Execute the Determined Command (if not installed by package manager) ---
	if cmd != nil {
		// Set necessary environment variables for Go tools
		homeDir, err := os.UserHomeDir()
		if err == nil {
			cmd.Env = append(os.Environ(), "HOME="+homeDir)
			goPath := os.Getenv("GOPATH")
			if goPath == "" {
				goPath = filepath.Join(homeDir, "go")
			}
			goBin := filepath.Join(goPath, "bin")
			cmd.Env = append(cmd.Env, "PATH="+os.Getenv("PATH")+":"+goBin)
		}

		// Run the command (go install, cargo install, etc.)
		if err := runInstallCommand(config, cmd, tool); err != nil {
			return false // Command execution failed
		}
	} else if !installSuccess {
        // This case should ideally not be reached if logic is correct,
        // but indicates no install method was determined or pkg manager failed silently.
         config.Logger.Printf(colorRed+"Failed to determine or execute an installation method for %s."+colorReset, tool)
         return false
    }


	// --- Post-Installation Verification & Actions ---
	time.Sleep(1 * time.Second) // Small delay for filesystem changes
	if isToolInstalled(tool) {
		config.Logger.Printf(colorGreen+"Successfully installed %s"+colorReset, tool)
		// Special action for Nuclei: Update templates in the specified directory
		if tool == "nuclei" {
			config.Logger.Printf(colorYellow+"Running 'nuclei -update-templates -td %s'..." + colorReset, config.NucleiTemplatesDir)
			// Ensure the template dir exists before trying to update into it
			_ = os.MkdirAll(config.NucleiTemplatesDir, 0755)
			updateCmd := exec.Command("nuclei", "-update-templates", "-td", config.NucleiTemplatesDir)
			runInstallCommand(config, updateCmd, "nuclei-templates update") // Log output, don't fail script if update fails
		}
		return true
	} else {
		config.Logger.Printf(colorRed+"Installation of %s seems to have failed (command not found after install attempt). Check logs above."+colorReset, tool)
		return false
	}
}

// runInstallCommand executes installation/utility commands and logs details.
func runInstallCommand(config *Config, cmd *exec.Cmd, logPrefix string) error {
	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb

	config.Logger.Printf("Running command for '%s': %s", logPrefix, cmd.String())
	err := cmd.Run()

	stdoutStr := strings.TrimSpace(outb.String())
	stderrStr := strings.TrimSpace(errb.String())

	if stdoutStr != "" {
		// Log multi-line output cleanly
		scanner := bufio.NewScanner(strings.NewReader(stdoutStr))
		for scanner.Scan() {
			config.Logger.Printf("[%s stdout] %s", logPrefix, scanner.Text())
		}
	}
	if stderrStr != "" {
		scanner := bufio.NewScanner(strings.NewReader(stderrStr))
		for scanner.Scan() {
			// Use Yellow for stderr that might not be critical errors
			config.Logger.Printf(colorYellow+"[%s stderr] %s"+colorReset, logPrefix, scanner.Text())
		}
	}

	if err != nil {
		config.Logger.Printf(colorRed+"Command for '%s' failed: %v"+colorReset, logPrefix, err)
		return err // Propagate the error
	}
	config.Logger.Printf("Command for '%s' completed successfully.", logPrefix)
	return nil
}

// --- createDirectories: Ensure output subdirectories exist ---
func createDirectories(config *Config) {
	dirs := []string{
		"subfinder", "httpx", "urls", "js", "findings", "feroxbuster",
		// "logs" created in initialize()
	}
	config.Logger.Println(colorBlue + "Creating output subdirectories..." + colorReset)
	for _, dir := range dirs {
		dirPath := filepath.Join(config.OutputDir, dir)
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			config.Logger.Printf(colorRed+"Error creating directory %s: %v"+colorReset, dirPath, err)
		} else {
			// config.Logger.Printf("Created/verified directory: %s", dirPath) // Reduce verbosity
		}
	}
     config.Logger.Printf("Output subdirectories checked/created in: %s", config.OutputDir)

}

// --- defineSteps: Configure all scanning steps ---
func defineSteps(config *Config) []StepInfo {
	// Define file paths relative to the output directory
	subfinderOutput := filepath.Join(config.OutputDir, "subfinder", "subdomains.txt")
	httpxOutput := filepath.Join(config.OutputDir, "httpx", "alive.txt") // URLs with scheme
	httpxHostsOutput := filepath.Join(config.OutputDir, "httpx", "alive_hosts.txt") // Just host:port
	urlsDir := filepath.Join(config.OutputDir, "urls")
	katanaOutput := filepath.Join(urlsDir, "katana.txt")
	waybackOutput := filepath.Join(urlsDir, "wayback.txt")
	otxOutput := filepath.Join(urlsDir, "otx.txt")
	allUrlsUnsorted := filepath.Join(urlsDir, "all_urls_unsorted.txt")
	allUrlsSorted := filepath.Join(urlsDir, "all_urls_sorted_unique.txt")
	jsDir := filepath.Join(config.OutputDir, "js")
	jsFileUrls := filepath.Join(jsDir, "js_files.txt")
	findingsDir := filepath.Join(config.OutputDir, "findings")
	secretsOutput := filepath.Join(findingsDir, "potential_secrets.txt")
	jsFindingsOutput := filepath.Join(findingsDir, "js_nuclei_findings.txt")
	feroxbusterDirOutput := filepath.Join(config.OutputDir, "feroxbuster")
	feroxbusterFileOutput := filepath.Join(feroxbusterDirOutput, fmt.Sprintf("feroxbuster_%s.txt", strings.ReplaceAll(config.Domain, ".", "_"))) // Use domain in filename
	xssOutput := filepath.Join(findingsDir, "xss_bxss.txt")
	takeoverOutput := filepath.Join(findingsDir, "takeovers.txt")
	misconfigsOutput := filepath.Join(findingsDir, "misconfigs_nuclei.json")
	nucleiFindingsOutput := filepath.Join(findingsDir, "nuclei_findings.txt")
	lfiOutput := filepath.Join(findingsDir, "lfi_nuclei.json")

	// --- Define Steps with Updated Nuclei commands ---
	steps := []StepInfo{
		{
			Name:        "1. Subdomain Discovery (subfinder)",
			Description: "Discovering subdomains using subfinder",
			Command:     fmt.Sprintf("subfinder -d %s -o %s -all -recursive -silent", config.Domain, subfinderOutput),
			OutputFile:  subfinderOutput,
		},
		{
			Name:        "2. Subdomain Probing (httpx)",
			Description: "Probing discovered subdomains for live HTTP/S servers",
			Command: fmt.Sprintf("cat %s | httpx -ports 80,443,8080,8443,8000,8888 -threads %d -timeout 10 -silent -o %s -output-host-port %s",
				subfinderOutput, config.Threads, httpxOutput, httpxHostsOutput),
			OutputFile:   httpxOutput,
			RequiresPipe: true,
		},
		{
			Name:        "3. URL Collection (Katana)",
			Description: "Crawling live sites for URLs using Katana",
			Command: fmt.Sprintf("katana -list %s -d 5 -jc -kf -c %d -silent -ef woff,css,png,jpg,svg,ico,gif,jpeg,ttf,otf,eot -o %s",
				httpxOutput, config.Threads, katanaOutput),
			OutputFile: katanaOutput,
		},
		{
			Name:        "4. URL Collection (Waybackurls)",
			Description: "Fetching URLs from Wayback Machine archives",
			Command:      fmt.Sprintf("echo %s | waybackurls > %s", config.Domain, waybackOutput),
			OutputFile:   waybackOutput,
			RequiresPipe: true,
		},
		{
			Name:        "5. URL Collection (OTX)",
			Description: "Fetching URLs from AlienVault OTX",
			Command:      fmt.Sprintf("echo %s | otxurls -s > %s", config.Domain, otxOutput),
			OutputFile:   otxOutput,
			RequiresPipe: true,
		},
		{
			Name:        "6. Consolidate & Sort URLs",
			Description: "Combining URLs from all sources, sorting, and removing duplicates",
			Command: fmt.Sprintf("cat %s %s %s > %s && cat %s | sort -u > %s",
				katanaOutput, waybackOutput, otxOutput, allUrlsUnsorted, allUrlsUnsorted, allUrlsSorted),
			OutputFile:   allUrlsSorted,
			RequiresPipe: true,
		},
		{
			Name:        "7. Secret Files Discovery (grep)",
			Description: "Searching consolidated URLs for potentially sensitive file extensions",
			Command: fmt.Sprintf("cat %s | grep -E '\\.(log|txt|config|conf|cfg|ini|yml|yaml|json|sql|db|backup|bak|bkp|old|cache|secret|key|pem|csv|xls|xlsx|gz|tgz|zip|rar|7z)$' > %s",
				allUrlsSorted, secretsOutput),
			OutputFile:   secretsOutput,
			RequiresPipe: true,
		},
		{
			Name:        "8. JavaScript Files Collection (grep)",
			Description: "Extracting JavaScript file URLs from the consolidated list",
			Command: fmt.Sprintf("cat %s | grep -E '\\.js$' > %s",
				allUrlsSorted, jsFileUrls),
			OutputFile:   jsFileUrls,
			RequiresPipe: true,
		},
		{
			Name:        "9. JavaScript Analysis (Nuclei)",
			Description: "Analyzing collected JavaScript files for secrets and vulnerabilities",
			// Added -td flag for template directory
			Command: fmt.Sprintf("nuclei -l %s -td %s -t exposures/,javascript/ -tags js,secret -severity medium,high,critical -c %d -stats -o %s",
				jsFileUrls, config.NucleiTemplatesDir, config.Threads, jsFindingsOutput),
			OutputFile: jsFindingsOutput,
		},
		{
			Name:        "10. Directory Bruteforce (feroxbuster)",
			Description: "Bruteforcing directories and files on live web servers",
			Command: fmt.Sprintf("feroxbuster --stdin --wordlist %s --threads %d --depth 3 --status-codes 200,301,302,401 --filter-status 404,403,500 --silent --output %s < %s",
				config.WordlistPath, config.Threads, feroxbusterFileOutput, httpxHostsOutput),
			OutputFile:   feroxbusterFileOutput,
			RequiresPipe: true,
		},
		{
			Name:        "11. XSS Scan (gf + bxss)",
			Description: "Scanning found URLs for potential XSS vulnerabilities using gf patterns and bxss",
			Command: fmt.Sprintf("cat %s | gf xss | bxss -append -payload '\"<script>alert(1)</script>' -threads %d > %s",
				allUrlsSorted, config.Threads, xssOutput),
			OutputFile:   xssOutput,
			RequiresPipe: true,
		},
		{
			Name:        "12. Subdomain Takeover Check (subzy)",
			Description: "Checking discovered subdomains for potential takeover vulnerabilities",
			Command: fmt.Sprintf("subzy run --targets %s --concurrency %d --hide_fails --verify_ssl --output %s",
				subfinderOutput, config.Threads*2, takeoverOutput),
			OutputFile: takeoverOutput,
		},
		{
			Name:        "13. Misconfig/Exposure Scan (Nuclei)",
			Description: "Scanning live hosts for common misconfigurations and exposures",
			// Added -td flag
			Command: fmt.Sprintf("nuclei -l %s -td %s -tags misconfig,exposure,config,auth-bypass,cors -severity medium,high,critical -rate-limit 150 -c %d -timeout 10 -stats -j -irr -o %s",
				httpxOutput, config.NucleiTemplatesDir, config.Threads, misconfigsOutput),
			OutputFile: misconfigsOutput,
		},
		{
			Name:        "14. CVEs & Tech Scan (Nuclei)",
			Description: "Scanning for known CVEs, technology detection, and OSINT",
			// Added -td flag
			Command: fmt.Sprintf("nuclei -l %s -td %s -tags cve,tech,osint -severity medium,high,critical,info -etags ssl -c %d -stats -o %s",
				httpxOutput, config.NucleiTemplatesDir, config.Threads, nucleiFindingsOutput),
			OutputFile: nucleiFindingsOutput,
		},
		{
			Name:        "15. LFI Scan (gf + qsreplace + Nuclei)",
			Description: "Testing URLs for potential Local File Inclusion vulnerabilities",
			// Added -td flag
			Command: fmt.Sprintf("cat %s | gf lfi | qsreplace '/etc/passwd' | nuclei -td %s -tags lfi,file-inclusion -severity medium,high,critical -c %d -stats -irr -j -o %s",
				allUrlsSorted, config.NucleiTemplatesDir, config.Threads, lfiOutput),
			OutputFile:   lfiOutput,
			RequiresPipe: true,
		},
	}

	return steps
}


// --- runAllSteps: Execute each defined step sequentially ---
func runAllSteps(config *Config, steps []StepInfo) {
	totalSteps := len(steps)
	for i := range steps {
		step := &steps[i]

		config.Logger.Printf(colorCyan+"[%d/%d] Starting: %s"+colorReset, i+1, totalSteps, step.Name)
		config.Logger.Printf(colorBlue+"--> Description: %s"+colorReset, step.Description)
		config.Logger.Printf(colorBlue+"--> Output File: %s"+colorReset, step.OutputFile)

		// Check skip conditions
		outputExists := fileExists(step.OutputFile) // Check existence separately
		outputNotEmpty := isStepCompleted(step.OutputFile) // Checks existence AND size > 0

		if !config.Force && outputNotEmpty {
			config.Logger.Printf(colorYellow+"Skipping: Output file '%s' already exists and is not empty. Use --force to rerun."+colorReset, step.OutputFile)
			step.Completed = true
			config.Logger.Println("---")
			continue
		}
        // If forcing, or file doesn't exist, or file exists but is empty, proceed.
        if config.Force && outputExists {
             config.Logger.Printf(colorYellow+"Note: --force is enabled, rerunning step even though output '%s' exists."+colorReset, step.OutputFile)
        } else if !config.Force && outputExists && !outputNotEmpty {
            config.Logger.Printf(colorYellow+"Note: Output file '%s' exists but is empty. Rerunning step."+colorReset, step.OutputFile)
        }


		// Ensure output directory exists
		outputDir := filepath.Dir(step.OutputFile)
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			config.Logger.Printf(colorRed+"Error: Cannot create output directory '%s' for step %d: %v. Skipping step."+colorReset, outputDir, i+1, err)
			step.Completed = false
			config.Logger.Println("---")
			continue
		}

		// Run the step
		startTime := time.Now()
		err := runStep(config, *step)
		duration := time.Since(startTime)

		// Evaluate result
		if err != nil {
			config.Logger.Printf(colorRed+"Error running step [%d/%d] %s: %v (Duration: %s)"+colorReset, i+1, totalSteps, step.Name, err, duration.Round(time.Second))
			step.Completed = false
			// Check if output file is empty after error
            if fileExists(step.OutputFile) && !isStepCompleted(step.OutputFile) {
                 config.Logger.Printf(colorYellow+"Note: Output file '%s' was created but is empty, likely due to the error."+colorReset, step.OutputFile)
            }
		} else {
			// Step command succeeded (exit 0), now check output file
			if !isStepCompleted(step.OutputFile) {
				// Command ran OK, but no output produced/found
				config.Logger.Printf(colorYellow+"Warning: Step [%d/%d] %s completed without errors, but output file '%s' is missing or empty. Tool might have found nothing. (Duration: %s)"+colorReset, i+1, totalSteps, step.Name, step.OutputFile, duration.Round(time.Second))
				step.Completed = true // Mark as run
			} else {
				// Command ran OK and output file looks good
				config.Logger.Printf(colorGreen+"Success: Step [%d/%d] %s completed successfully. (Duration: %s)"+colorReset, i+1, totalSteps, step.Name, duration.Round(time.Second))
				step.Completed = true
			}
		}
		config.Logger.Println("---") // Separator
	}
}

// --- fileExists: Check if a file exists ---
func fileExists(filePath string) bool {
    _, err := os.Stat(filePath)
    return err == nil // True if exists, false if not exist or other error
}


// --- isStepCompleted: Check if the output file exists and is not empty ---
func isStepCompleted(outputFile string) bool {
	info, err := os.Stat(outputFile)
	if err != nil {
		return false // File doesn't exist or other error
	}
	return info.Size() > 0
}

// --- runStep: Execute a single command step ---
func runStep(config *Config, step StepInfo) error {
	config.Logger.Printf("Executing command: %s", step.Command)

	var cmd *exec.Cmd
	if step.RequiresPipe {
		cmd = exec.Command("sh", "-c", step.Command)
	} else {
		parts := strings.Fields(step.Command)
		if len(parts) == 0 { return fmt.Errorf("empty command") }
		cmd = exec.Command(parts[0], parts[1:]...)
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Start()
	if err != nil {
		if stderr.Len() > 0 { config.Logger.Printf(colorRed+"[stderr] %s"+colorReset, stderr.String()) }
		return fmt.Errorf("failed to start command: %w", err)
	}

	err = cmd.Wait()

	if stderr.Len() > 0 {
		// Log stderr lines individually for better readability
		scanner := bufio.NewScanner(&stderr)
		for scanner.Scan() {
			config.Logger.Printf(colorYellow+"[stderr] %s"+colorReset, scanner.Text())
		}
	}

	if err != nil {
		return fmt.Errorf("command exited with error: %w", err) // Includes exit code info
	}

	return nil // Exit code 0
}

// --- printSummary: Display a summary of the scan results ---
func printSummary(config *Config, steps []StepInfo) {
	config.Logger.Println(colorPurple + "\n===== BugBusterPro Scan Summary =====" + colorReset)
	config.Logger.Printf("Domain: %s", config.Domain)
	config.Logger.Printf("Output Directory: %s", config.OutputDir)
    config.Logger.Printf("Wordlist Used: %s", config.WordlistPath)
    config.Logger.Printf("Nuclei Templates Dir: %s", config.NucleiTemplatesDir)
	config.Logger.Printf("Scan End Time: %s", time.Now().Format("2006-01-02 15:04:05"))

	completedCount := 0
	failedSteps := []string{}
	emptyOutputSteps := []string{}

	config.Logger.Println(colorCyan + "\n--- Step Status ---" + colorReset)
	for i, step := range steps {
		status := ""
		stepRan := step.Completed // Did the step's execution attempt finish?

		if stepRan {
            if isStepCompleted(step.OutputFile) {
                status = colorGreen + "[Completed]" + colorReset
				completedCount++
            } else {
                // Step ran but output is missing/empty
                status = colorYellow + "[Completed (No Output)]" + colorReset
                emptyOutputSteps = append(emptyOutputSteps, fmt.Sprintf("%d. %s (%s)", i+1, step.Name, step.OutputFile))
				completedCount++ // Count as run, but flag it
            }
        } else {
            // Step didn't run successfully (error during execution OR skipped by --force=false logic)
            if !config.Force && isStepCompleted(step.OutputFile) {
                // It was skipped because output existed and force was false
                status = colorYellow + "[Skipped (Output Exists)]" + colorReset
				completedCount++ // Count as completed in a prior run
            } else {
                // It failed during execution
                status = colorRed + "[Failed]" + colorReset
                failedSteps = append(failedSteps, fmt.Sprintf("%d. %s", i+1, step.Name))
            }
        }
		config.Logger.Printf("%s %s", status, step.Name)
	}

	config.Logger.Printf("\nSteps Run/Succeeded/Total: %d/%d", completedCount, len(steps)) // Simplified count

	if len(failedSteps) > 0 {
		config.Logger.Println(colorRed + "\n--- Failed Steps ---" + colorReset)
		for _, failed := range failedSteps {
			config.Logger.Printf("- %s", failed)
		}
		config.Logger.Println(colorRed + "Check the log file for detailed errors." + colorReset)
	}

	if len(emptyOutputSteps) > 0 {
		config.Logger.Println(colorYellow + "\n--- Steps Completed with Missing/Empty Output ---" + colorReset)
		for _, empty := range emptyOutputSteps {
			config.Logger.Printf("- %s", empty)
		}
		config.Logger.Println(colorYellow + "These steps ran without error, but their expected output file is empty or was not created. The tool might not have found anything." + colorReset)
	}

	if len(failedSteps) == 0 && len(emptyOutputSteps) == 0 {
		config.Logger.Println(colorGreen + "\nAll steps completed successfully!" + colorReset)
	} else if len(failedSteps) == 0 && len(emptyOutputSteps) > 0 {
        config.Logger.Println(colorYellow + "\nAll steps ran without errors, but some produced no output. Review the 'No Output' list and logs." + colorReset)
    } else {
		config.Logger.Println(colorYellow + "\nScan finished, but some steps failed. Please review the logs." + colorReset)
	}

	// List significant output files found
	config.Logger.Println(colorCyan + "\n--- Key Output Files (if generated and not empty) ---" + colorReset)
	significantFiles := []string{}
	for _, step := range steps {
		// Only list files that exist and have content
		if isStepCompleted(step.OutputFile) {
			significantFiles = append(significantFiles, step.OutputFile)
		}
	}

	if len(significantFiles) > 0 {
		for _, file := range significantFiles {
			fileInfo, err := os.Stat(file)
			if err == nil {
				config.Logger.Printf("- %s (%.2f KB)", file, float64(fileInfo.Size())/1024.0)
			} else {
				config.Logger.Printf("- %s (Error getting stats: %v)", file, err)
			}
		}
	} else {
		config.Logger.Println("No significant output files were found (or they were empty).")
	}

	config.Logger.Println(colorPurple + "\n===== End of Summary =====" + colorReset)
}

// --- contains: Helper function to check if a string is in a slice ---
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
