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
	Domain       string
	OutputDir    string
	WordlistPath string // Added for feroxbuster wordlist
	Force        bool
	Threads      int // General thread/concurrency hint
	LogFile      *os.File
	Logger       *log.Logger
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
var requiredTools = []string{
	"go", // Need go for installation
	"subfinder",
	"httpx",
	"katana",
	"waybackurls",
	"otxurls",
	"feroxbuster",
	"nuclei",
	"subzy",
	"qsreplace",
	"gf",
	"bxss",
	"sort", // Standard Linux utilities
	"grep",
	"cat",
	"sh",   // Shell is needed for pipes
	"echo", // Used in one step
}

func main() {
	// --- Command-Line Flags ---
	domain := flag.String("domain", "", "Target domain to scan (required)")
	outputDir := flag.String("output-dir", "output", "Directory to store scan results")
	// Default wordlist path - adjust if yours is different
	defaultWordlist := "/usr/share/wordlists/dirb/common.txt"
	// Check common alternative location
	if _, err := os.Stat("/usr/share/seclists/Discovery/Web-Content/common.txt"); err == nil {
		defaultWordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"
	}
	wordlistPath := flag.String("wordlist", defaultWordlist, "Path to wordlist for directory brute-forcing (e.g., feroxbuster)")
	force := flag.Bool("force", false, "Force rerun of all steps, even if output files exist")
	// Reduced default threads for stability/stealth
	threads := flag.Int("threads", 25, "Default number of threads/concurrency for tools")
	flag.Parse()

	if *domain == "" {
		fmt.Println(colorRed + "Error: --domain is required." + colorReset)
		flag.Usage()
		os.Exit(1)
	}

	// --- Create Config ---
	config := Config{
		Domain:       *domain,
		OutputDir:    filepath.Clean(*outputDir), // Clean the path
		WordlistPath: *wordlistPath,
		Force:        *force,
		Threads:      *threads,
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
		os.Exit(1) // Exit if essential tools are missing
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
		// Don't use logger here as it's not initialized yet
		return fmt.Errorf("error creating logs directory %s: %v", logsDir, err)
	}

	// Create log file
	logFileName := filepath.Join(logsDir, fmt.Sprintf("bugbusterpro_%s_%s.log", config.Domain, time.Now().Format("20060102_150405")))
	logFile, err := os.Create(logFileName)
	if err != nil {
		return fmt.Errorf("error creating log file %s: %v", logFileName, err)
	}

	// Create multiwriter to write to both console and file
	multiWriter := io.MultiWriter(os.Stdout, logFile)
	// Use standard log flags
	logger := log.New(multiWriter, "", log.Ldate|log.Ltime|log.Lmicroseconds)

	config.LogFile = logFile
	config.Logger = logger

	// Print banner
	printBanner(config)

	// Check wordlist existence after logger is ready
	if _, err := os.Stat(config.WordlistPath); os.IsNotExist(err) {
		config.Logger.Printf(colorYellow+"Warning: Specified wordlist '%s' not found. Directory brute-forcing (Step 11) might fail or use an empty list.", config.WordlistPath+colorReset)
		config.Logger.Printf(colorYellow+"Use the --wordlist flag to specify the correct path."+colorReset)
	}

	// Add a note about Nuclei templates
	config.Logger.Printf(colorYellow+"Note: Ensure Nuclei templates are installed and up-to-date by running: nuclei -update-templates"+colorReset)

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
                                                                                         v1.1.0 (Updated)
`
	// Use Println directly for banner to avoid log prefixes
	fmt.Println(colorCyan + banner + colorReset)
	config.Logger.Printf("Starting BugBusterPro for domain: %s", config.Domain)
	config.Logger.Printf("Output directory: %s", config.OutputDir)
	config.Logger.Printf("Wordlist path: %s", config.WordlistPath)
	config.Logger.Printf("Force rerun: %t", config.Force)
	config.Logger.Printf("Default Threads/Concurrency: %d", config.Threads)
	config.Logger.Printf("Log file: %s", config.LogFile.Name())
}

// --- checkAndInstallTools: Verify required tools are present, attempt installation if missing ---
func checkAndInstallTools(config *Config) bool {
	config.Logger.Println(colorYellow + "Checking required tools..." + colorReset)
	allToolsFound := true
	goInstalled := isToolInstalled("go") // Check for Go first

	for _, tool := range requiredTools {
		if !isToolInstalled(tool) {
			// Don't try to install go itself, or basic utils
			isGoTool := contains([]string{"subfinder", "httpx", "katana", "waybackurls", "otxurls", "nuclei", "subzy", "qsreplace", "gf", "bxss"}, tool)
			isInstallable := contains([]string{"feroxbuster"}, tool)

			if tool == "go" {
				config.Logger.Printf(colorRed+"Tool %s not found. Please install Go manually (https://golang.org/doc/install)."+colorReset, tool)
				allToolsFound = false // Go is critical for installing others
			} else if isGoTool {
				if !goInstalled {
					config.Logger.Printf(colorRed+"Tool %s not found, and Go is not installed. Cannot install automatically."+colorReset, tool)
					allToolsFound = false
				} else {
					config.Logger.Printf(colorYellow+"Tool %s not found. Attempting installation..."+colorReset, tool)
					if !installTool(config, tool) {
						allToolsFound = false // Mark as failed if install fails
					}
				}
			} else if isInstallable {
				config.Logger.Printf(colorYellow+"Tool %s not found. Attempting installation..."+colorReset, tool)
				if !installTool(config, tool) {
					allToolsFound = false
				}
			} else {
				// Basic utils like cat, grep, sort, sh should usually be present
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
		config.Logger.Println(colorGreen + "All required tools are present." + colorReset)
	}
	return allToolsFound
}

// --- isToolInstalled: Check if a command exists in the system's PATH ---
func isToolInstalled(tool string) bool {
	_, err := exec.LookPath(tool)
	return err == nil
}

// --- installTool: Attempt to install a missing tool ---
// Returns true on success, false on failure.
func installTool(config *Config, tool string) bool {
	config.Logger.Printf("Attempting to install %s...", tool)

	var cmd *exec.Cmd
	installSuccess := false

	switch tool {
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
	case "feroxbuster":
		// Try common package managers first, then cargo
		if isToolInstalled("apt-get") {
			config.Logger.Printf("Trying to install feroxbuster using apt-get...")
			// Use apt-get for potentially non-interactive environments
			cmd = exec.Command("sudo", "apt-get", "update")
			if err := runInstallCommand(config, cmd, tool+" (update)"); err == nil {
				cmd = exec.Command("sudo", "apt-get", "install", "-y", "feroxbuster")
				if err := runInstallCommand(config, cmd, tool); err == nil {
					installSuccess = true
				}
			}
		} else if isToolInstalled("yum") {
			config.Logger.Printf("Trying to install feroxbuster using yum...")
			// Assuming EPEL might be needed or it's in a standard repo
			cmd = exec.Command("sudo", "yum", "install", "-y", "feroxbuster")
			if err := runInstallCommand(config, cmd, tool); err == nil {
				installSuccess = true
			}
		} else if isToolInstalled("dnf") {
			config.Logger.Printf("Trying to install feroxbuster using dnf...")
			cmd = exec.Command("sudo", "dnf", "install", "-y", "feroxbuster")
			if err := runInstallCommand(config, cmd, tool); err == nil {
				installSuccess = true
			}
		} else if isToolInstalled("pacman") {
			config.Logger.Printf("Trying to install feroxbuster using pacman...")
			cmd = exec.Command("sudo", "pacman", "-Sy", "--noconfirm", "feroxbuster")
			if err := runInstallCommand(config, cmd, tool); err == nil {
				installSuccess = true
			}
		} else if isToolInstalled("cargo") {
			config.Logger.Printf("Trying to install feroxbuster using cargo...")
			cmd = exec.Command("cargo", "install", "feroxbuster")
		} else {
			config.Logger.Printf(colorRed+"Cannot install feroxbuster automatically: No supported package manager (apt, yum, dnf, pacman) or cargo found."+colorReset)
			return false // Explicitly return false
		}
		// If package manager worked, cmd will be nil here if installSuccess is true
		if cmd == nil && !installSuccess {
			// Fallback or error if no method chosen/failed
			config.Logger.Printf(colorRed+"Failed to determine installation command for feroxbuster."+colorReset)
			return false
		} else if cmd == nil && installSuccess {
            // Already installed via package manager, skip go install attempt
             config.Logger.Printf(colorGreen+"Successfully installed %s via package manager."+colorReset, tool)
             return true
        }

	case "nuclei":
		cmd = exec.Command("go", "install", "-v", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest") // v3 is current
	case "subzy":
		cmd = exec.Command("go", "install", "-v", "github.com/LukaSikic/subzy@latest")
	case "qsreplace":
		cmd = exec.Command("go", "install", "-v", "github.com/tomnomnom/qsreplace@latest")
	case "gf":
		cmd = exec.Command("go", "install", "-v", "github.com/tomnomnom/gf@latest")
		// Remind user about gf patterns
		defer func() {
			config.Logger.Printf(colorYellow+"Note: 'gf' installed. Ensure you have gf patterns setup (e.g., clone https://github.com/tomnomnom/gf and run 'cp -r examples/* ~/.gf')."+colorReset)
		}()
	case "bxss":
		cmd = exec.Command("go", "install", "-v", "github.com/ethicalhackingplayground/bxss@latest")
	default:
		config.Logger.Printf(colorRed+"Unknown tool for installation: %s"+colorReset, tool)
		return false // Explicitly return false
	}

    // If cmd is not nil, it means we need to run the command (likely go install or cargo)
    if cmd != nil {
        // Set GOPATH and GOBIN potentially, though 'go install' often works without them if go is set up
	    // Set HOME environment variable for Go tools which might rely on ~/.config or similar
	    homeDir, err := os.UserHomeDir()
	    if err == nil {
		    cmd.Env = append(os.Environ(), "HOME="+homeDir)
            // Add GOBIN to PATH for the command's execution context if possible
            goPath := os.Getenv("GOPATH")
            if goPath == "" {
                goPath = filepath.Join(homeDir, "go")
            }
            goBin := filepath.Join(goPath, "bin")
            cmd.Env = append(cmd.Env, "PATH="+os.Getenv("PATH")+":"+goBin)
	    }


	    if err := runInstallCommand(config, cmd, tool); err != nil {
	        return false // Install failed
        }
    }


	// Final check if the tool is now installed
	if isToolInstalled(tool) {
		config.Logger.Printf(colorGreen+"Successfully installed %s"+colorReset, tool)
		// Special case for nuclei: try updating templates after install
		if tool == "nuclei" {
			config.Logger.Printf(colorYellow+"Running 'nuclei -update-templates'..." + colorReset)
			updateCmd := exec.Command("nuclei", "-update-templates")
			runInstallCommand(config, updateCmd, "nuclei-templates") // Log output but don't fail script if this errors
		}
		return true
	} else {
		config.Logger.Printf(colorRed+"Installation of %s seems to have failed (command not found after install attempt)."+colorReset, tool)
		return false
	}
}

// runInstallCommand executes the installation command and logs output/errors.
func runInstallCommand(config *Config, cmd *exec.Cmd, toolName string) error {
	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb

	config.Logger.Printf("Running install command: %s", cmd.String())
	err := cmd.Run()

	stdoutStr := outb.String()
	stderrStr := errb.String()

	if stdoutStr != "" {
		config.Logger.Printf("[%s install stdout]: %s", toolName, stdoutStr)
	}
	if stderrStr != "" {
		config.Logger.Printf("[%s install stderr]: %s", toolName, stderrStr)
	}

	if err != nil {
		config.Logger.Printf(colorRed+"Failed to install/run %s: %v"+colorReset, toolName, err)
		return err
	}
	return nil
}

// --- createDirectories: Ensure necessary output subdirectories exist ---
func createDirectories(config *Config) {
	// Define relative paths within the main output directory
	dirs := []string{
		"subfinder",
		"httpx",
		"urls",
		"js",
		"findings",
		"feroxbuster", // Added specific dir for feroxbuster output
		// "logs" directory is created in initialize()
	}

	config.Logger.Println(colorBlue + "Creating output subdirectories..." + colorReset)
	for _, dir := range dirs {
		dirPath := filepath.Join(config.OutputDir, dir)
		err := os.MkdirAll(dirPath, 0755) // 0755 permissions
		if err != nil {
			// Log error but continue, maybe permissions issue?
			config.Logger.Printf(colorRed+"Error creating directory %s: %v"+colorReset, dirPath, err)
		} else {
			config.Logger.Printf("Created/verified directory: %s", dirPath)
		}
	}
}

// --- defineSteps: Configure all the security scanning steps ---
func defineSteps(config *Config) []StepInfo {
	// Define file paths relative to the output directory
	subfinderOutput := filepath.Join(config.OutputDir, "subfinder", "subdomains.txt")
	httpxOutput := filepath.Join(config.OutputDir, "httpx", "alive.txt") // URLs with scheme
	httpxHostsOutput := filepath.Join(config.OutputDir, "httpx", "alive_hosts.txt") // Just host:port
	urlsDir := filepath.Join(config.OutputDir, "urls")
	katanaOutput := filepath.Join(urlsDir, "katana.txt")
	waybackOutput := filepath.Join(urlsDir, "wayback.txt")
	otxOutput := filepath.Join(urlsDir, "otx.txt")
	allUrlsOutput := filepath.Join(urlsDir, "all_urls_unsorted.txt") // Before sorting
	sortedUrlsOutput := filepath.Join(urlsDir, "all_urls_sorted_unique.txt")
	jsDir := filepath.Join(config.OutputDir, "js")
	jsFileUrls := filepath.Join(jsDir, "js_files.txt")
	findingsDir := filepath.Join(config.OutputDir, "findings")
	secretsOutput := filepath.Join(findingsDir, "potential_secrets.txt")
	jsFindingsOutput := filepath.Join(findingsDir, "js_nuclei_findings.txt")
	// jsKatanaFindingsOutput := filepath.Join(findingsDir, "js_katana_findings.txt") // Merged into jsFindingsOutput
	feroxbusterDirOutput := filepath.Join(config.OutputDir, "feroxbuster") // Directory for output
	feroxbusterFileOutput := filepath.Join(feroxbusterDirOutput, fmt.Sprintf("feroxbuster_%s.txt", config.Domain))
	xssOutput := filepath.Join(findingsDir, "xss_bxss.txt")
	takeoverOutput := filepath.Join(findingsDir, "takeovers.txt")
	misconfigsOutput := filepath.Join(findingsDir, "misconfigs_nuclei.json")
	nucleiFindingsOutput := filepath.Join(findingsDir, "nuclei_findings.txt") // Use .txt for easier viewing/grepping initially
	lfiOutput := filepath.Join(findingsDir, "lfi_nuclei.json")

	// Use config.Threads for relevant flags
	// Use sh -c for commands with pipes or redirection
	// Ensure output files match the OutputFile field

	steps := []StepInfo{
		{
			Name:        "1. Subdomain Discovery (subfinder)",
			Description: "Discovering subdomains using subfinder (passive + recursive)",
			// Use -all for more sources, -recursive for depth
			Command:     fmt.Sprintf("subfinder -d %s -o %s -all -recursive -silent", config.Domain, subfinderOutput),
			OutputFile:  subfinderOutput,
		},
		{
			Name:        "2. Subdomain Probing (httpx)",
			Description: "Probing discovered subdomains for live HTTP/S servers",
			// Output full URLs to alive.txt, host:port to alive_hosts.txt
			// Use - H for adding custom headers if needed later
			// Increased timeout slightly
			Command: fmt.Sprintf("cat %s | httpx -ports 80,443,8080,8443,8000,8888 -threads %d -timeout 10 -silent -o %s -output-host-port %s",
				subfinderOutput, config.Threads, httpxOutput, httpxHostsOutput),
			OutputFile:   httpxOutput, // Main output is the URL list
			RequiresPipe: true,        // Uses cat and pipe
		},
		{
			Name:        "3. URL Collection (Katana)",
			Description: "Crawling live sites for URLs using Katana",
			// -jc for JS parsing, -kf for known files, -d depth, -c concurrency
			// Exclude common non-interesting file types
			// Input is the list of live URLs from httpx
			Command: fmt.Sprintf("katana -list %s -d 5 -jc -kf -c %d -silent -ef woff,css,png,jpg,svg,ico,gif,jpeg,ttf,otf,eot -o %s",
				httpxOutput, config.Threads, katanaOutput),
			OutputFile: katanaOutput,
		},
		{
			Name:        "4. URL Collection (Waybackurls)",
			Description: "Fetching URLs from Wayback Machine archives",
			// Input is the main domain
			Command:      fmt.Sprintf("echo %s | waybackurls > %s", config.Domain, waybackOutput),
			OutputFile:   waybackOutput,
			RequiresPipe: true, // Uses echo and pipe/redirect
		},
		{
			Name:        "5. URL Collection (OTX)",
			Description: "Fetching URLs from AlienVault OTX",
			// Input is the main domain
			Command:      fmt.Sprintf("echo %s | otxurls -s > %s", config.Domain, otxOutput), // Added -s for subdomains
			OutputFile:   otxOutput,
			RequiresPipe: true, // Uses echo and pipe/redirect
		},
		{
			Name:        "6. Consolidate & Sort URLs",
			Description: "Combining URLs from all sources, sorting, and removing duplicates",
			// Combine katana, wayback, otx outputs
			Command: fmt.Sprintf("cat %s %s %s > %s && cat %s | sort -u > %s",
				katanaOutput, waybackOutput, otxOutput, allUrlsOutput, allUrlsOutput, sortedUrlsOutput),
			OutputFile:   sortedUrlsOutput,
			RequiresPipe: true, // Uses cat, redirect, sort
		},
		{
			Name:        "7. Secret Files Discovery (grep)",
			Description: "Searching consolidated URLs for potentially sensitive file extensions",
			// Improved regex, searching the sorted unique list
			Command: fmt.Sprintf("cat %s | grep -E '\\.(log|txt|config|conf|cfg|ini|yml|yaml|json|sql|db|backup|bak|bkp|old|cache|secret|key|pem|csv|xls|xlsx|gz|tgz|zip|rar|7z)$' > %s",
				sortedUrlsOutput, secretsOutput),
			OutputFile:   secretsOutput,
			RequiresPipe: true, // Uses cat and pipe/redirect
		},
		{
			Name:        "8. JavaScript Files Collection (grep)",
			Description: "Extracting JavaScript file URLs from the consolidated list",
			// Search sorted unique list
			Command: fmt.Sprintf("cat %s | grep -E '\\.js$' > %s",
				sortedUrlsOutput, jsFileUrls),
			OutputFile:   jsFileUrls,
			RequiresPipe: true, // Uses cat and pipe/redirect
		},
		{
			Name:        "9. JavaScript Analysis (Nuclei)",
			Description: "Analyzing collected JavaScript files for secrets and vulnerabilities",
			// Use nuclei with relevant JS templates (exposures, secrets)
			// -l points to the list of JS files
			Command: fmt.Sprintf("nuclei -l %s -t exposures/,javascript/ -tags js,secret -severity medium,high,critical -c %d -stats -o %s",
				jsFileUrls, config.Threads, jsFindingsOutput),
			OutputFile: jsFindingsOutput,
		},
		// Step 10 (Katana JS analysis) is effectively covered by Step 9 if Katana finds JS files and they are fed into Nuclei. Removed for redundancy.
		{
			Name:        "10. Directory Bruteforce (feroxbuster)",
			Description: "Bruteforcing directories and files on live web servers",
			// Use the list of live HOSTS:PORT from httpx
			// Use configured wordlist, adjust extensions, add status codes to ignore
			// Output to a specific file in the feroxbuster directory
			Command: fmt.Sprintf("feroxbuster --stdin --wordlist %s --threads %d --depth 3 --status-codes 200,301,302,401 --filter-status 404,403,500 --silent --output %s < %s",
				config.WordlistPath, config.Threads, feroxbusterFileOutput, httpxHostsOutput), // Read targets from stdin
			OutputFile:   feroxbusterFileOutput,
			RequiresPipe: true, // Uses < redirection
		},
		{
			Name:        "11. XSS Scan (gf + bxss)",
			Description: "Scanning found URLs for potential XSS vulnerabilities using gf patterns and bxss",
			// Requires gf patterns to be installed correctly (esp. xss pattern)
			// Use sorted URL list, filter with gf, then test with bxss
			Command: fmt.Sprintf("cat %s | gf xss | bxss -append -payload '\"<script>alert(1)</script>' -threads %d > %s",
				sortedUrlsOutput, config.Threads, xssOutput),
			OutputFile:   xssOutput,
			RequiresPipe: true, // Uses cat, gf, bxss pipes/redirect
		},
		{
			Name:        "12. Subdomain Takeover Check (subzy)",
			Description: "Checking discovered subdomains for potential takeover vulnerabilities",
			// Use the original subfinder output
			// Corrected flag to --output
			Command: fmt.Sprintf("subzy run --targets %s --concurrency %d --hide_fails --verify_ssl --output %s",
				subfinderOutput, config.Threads*2, takeoverOutput), // Subzy might handle more concurrency
			OutputFile: takeoverOutput,
		},
		{
			Name:        "13. Misconfig/Exposure Scan (Nuclei)",
			Description: "Scanning live hosts for common misconfigurations and exposures",
			// Use alive URLs list, relevant nuclei templates/tags
			// Output in JSON format for potential parsing later
			Command: fmt.Sprintf("nuclei -l %s -tags misconfig,exposure,config,auth-bypass,cors -severity medium,high,critical -rate-limit 150 -c %d -timeout 10 -stats -j -irr -o %s",
				httpxOutput, config.Threads, misconfigsOutput),
			OutputFile: misconfigsOutput,
		},
		{
			Name:        "14. CVEs & Tech Scan (Nuclei)",
			Description: "Scanning for known CVEs, technology detection, and OSINT",
			// Use alive URLs list, relevant tags
			Command: fmt.Sprintf("nuclei -l %s -tags cve,tech,osint -severity medium,high,critical,info -etags ssl -c %d -stats -o %s",
				httpxOutput, config.Threads, nucleiFindingsOutput),
			OutputFile: nucleiFindingsOutput,
		},
		{
			Name:        "15. LFI Scan (gf + qsreplace + Nuclei)",
			Description: "Testing URLs for potential Local File Inclusion vulnerabilities",
			// Filter URLs likely to have parameters, replace values, test with Nuclei LFI templates
			Command: fmt.Sprintf("cat %s | gf lfi | qsreplace '/etc/passwd' | nuclei -tags lfi,file-inclusion -severity medium,high,critical -c %d -stats -irr -j -o %s",
				sortedUrlsOutput, config.Threads, lfiOutput),
			OutputFile:   lfiOutput,
			RequiresPipe: true, // Uses cat, gf, qsreplace, nuclei pipes/redirect
		},
	}

	return steps
}

// --- runAllSteps: Execute each defined step sequentially ---
func runAllSteps(config *Config, steps []StepInfo) {
	totalSteps := len(steps)
	for i := range steps { // Use index access to modify steps[i].Completed
		step := &steps[i] // Get a pointer to modify the slice element

		config.Logger.Printf(colorCyan+"[%d/%d] Starting: %s"+colorReset, i+1, totalSteps, step.Name)
		config.Logger.Printf(colorBlue+"--> Description: %s"+colorReset, step.Description)
		config.Logger.Printf(colorBlue+"--> Output File: %s"+colorReset, step.OutputFile)

		// Check if step should be skipped
		if !config.Force && isStepCompleted(step.OutputFile) {
			config.Logger.Printf(colorYellow+"Skipping: Output file '%s' already exists and is not empty. Use --force to rerun."+colorReset, step.OutputFile)
			step.Completed = true
			continue
		}

		// Ensure output directory exists before running the command
		outputDir := filepath.Dir(step.OutputFile)
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			config.Logger.Printf(colorRed+"Error: Cannot create output directory '%s' for step %d: %v. Skipping step."+colorReset, outputDir, i+1, err)
			step.Completed = false // Mark as not completed
			continue              // Skip to next step
		}

		// Run the step
		startTime := time.Now()
		err := runStep(config, *step) // Pass the value
		duration := time.Since(startTime)

		if err != nil {
			config.Logger.Printf(colorRed+"Error running step [%d/%d] %s: %v (Duration: %s)"+colorReset, i+1, totalSteps, step.Name, err, duration.Round(time.Second))
			step.Completed = false // Mark as failed

			// Check if the output file exists but might be empty due to error
			info, statErr := os.Stat(step.OutputFile)
			if statErr == nil && info.Size() == 0 {
				config.Logger.Printf(colorYellow+"Note: Output file '%s' was created but is empty, likely due to the error."+colorReset, step.OutputFile)
			} else if statErr != nil && !os.IsNotExist(statErr) {
				config.Logger.Printf(colorYellow+"Note: Could not check status of output file '%s': %v"+colorReset, step.OutputFile, statErr)
			}

		} else {
			// Check if output file was actually created and has content
			if !isStepCompleted(step.OutputFile) {
				config.Logger.Printf(colorYellow+"Warning: Step [%d/%d] %s completed without errors, but output file '%s' is missing or empty. (Duration: %s)"+colorReset, i+1, totalSteps, step.Name, step.OutputFile, duration.Round(time.Second))
				// Consider it 'completed' in terms of execution, but maybe not successfully in terms of output.
				// Keep Completed = true for now, but this indicates a potential issue with the command itself.
				step.Completed = true
			} else {
				config.Logger.Printf(colorGreen+"Success: Step [%d/%d] %s completed successfully. (Duration: %s)"+colorReset, i+1, totalSteps, step.Name, duration.Round(time.Second))
				step.Completed = true
			}
		}
		config.Logger.Println("---") // Separator between steps
	}
}

// --- isStepCompleted: Check if the output file exists and is not empty ---
func isStepCompleted(outputFile string) bool {
	info, err := os.Stat(outputFile)
	if err != nil {
		return false // File doesn't exist or other error
	}
	// Consider a file with zero size as not *successfully* completed in terms of output
	return info.Size() > 0
}

// --- runStep: Execute a single command step ---
func runStep(config *Config, step StepInfo) error {
	config.Logger.Printf("Executing command: %s", step.Command)

	var cmd *exec.Cmd
	// Use sh -c ONLY if the command requires pipes or redirection
	if step.RequiresPipe {
		cmd = exec.Command("sh", "-c", step.Command)
	} else {
		// Simple command, split manually (basic split is fine here as complex cases use sh -c)
		parts := strings.Fields(step.Command)
		if len(parts) == 0 {
			return fmt.Errorf("empty command")
		}
		cmd = exec.Command(parts[0], parts[1:]...)
	}

	// Capture stderr for logging errors
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	// We don't capture stdout here because for piped/redirected commands,
	// 'sh -c' handles writing to the step.OutputFile directly.
	// For simple commands, their own '-o' flags handle output.

	// Start the command
	err := cmd.Start()
	if err != nil {
		// Log stderr if available even if start fails
		if stderr.Len() > 0 {
			config.Logger.Printf(colorRed+"[stderr] %s"+colorReset, stderr.String())
		}
		return fmt.Errorf("failed to start command: %w", err)
	}

	// Wait for the command to finish
	err = cmd.Wait()

	// Log stderr if there was any error output, regardless of exit code
	if stderr.Len() > 0 {
		config.Logger.Printf(colorYellow+"[stderr] %s"+colorReset, stderr.String())
	}

	if err != nil {
		// Return the error including exit code information
		return fmt.Errorf("command exited with error: %w", err)
	}

	// Command finished successfully (exit code 0)
	return nil
}

// --- printSummary: Display a summary of the scan results ---
func printSummary(config *Config, steps []StepInfo) {
	config.Logger.Println(colorPurple + "\n===== BugBusterPro Scan Summary =====" + colorReset)
	config.Logger.Printf("Domain: %s", config.Domain)
	config.Logger.Printf("Output Directory: %s", config.OutputDir)
	config.Logger.Printf("Scan End Time: %s", time.Now().Format("2006-01-02 15:04:05"))

	completedCount := 0
	failedSteps := []string{}
	emptyOutputSteps := []string{}

	config.Logger.Println(colorCyan + "\n--- Step Status ---" + colorReset)
	for i, step := range steps {
		status := colorRed + "[Failed/Skipped]" + colorReset
		if step.Completed {
			// Further check if the output file is valid
			if isStepCompleted(step.OutputFile) {
				status = colorGreen + "[Completed]" + colorReset
				completedCount++
			} else {
				// Completed execution but no output file
				status = colorYellow + "[Completed (No Output)]" + colorReset
				completedCount++ // Count it as run, but flag it
				emptyOutputSteps = append(emptyOutputSteps, fmt.Sprintf("%d. %s (%s)", i+1, step.Name, step.OutputFile))
			}
		} else {
			// Didn't complete execution (error or skipped due to force=false and existing file initially)
			// Check if it was skipped initially vs failed during run
			if !config.Force && isStepCompleted(step.OutputFile) {
				// This case shouldn't happen if logic is right, but as a safeguard
				status = colorYellow + "[Skipped (Output Exists)]" + colorReset
				completedCount++ // It was effectively completed in a prior run
			} else {
				failedSteps = append(failedSteps, fmt.Sprintf("%d. %s", i+1, step.Name))
			}
		}
		config.Logger.Printf("%s %s", status, step.Name)
	}

	config.Logger.Printf("\nSteps Run/Total: %d/%d", completedCount, len(steps))

	if len(failedSteps) > 0 {
		config.Logger.Println(colorRed + "\n--- Failed/Skipped Steps ---" + colorReset)
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
		config.Logger.Println(colorYellow + "These steps ran without error, but their expected output file is empty or was not created. The respective tool might not have found anything, or there could be an issue with the tool/command itself." + colorReset)
	}

	if completedCount == len(steps) && len(failedSteps) == 0 && len(emptyOutputSteps) == 0 {
		config.Logger.Println(colorGreen + "\nAll steps completed successfully!" + colorReset)
	} else {
		config.Logger.Println(colorYellow + "\nScan finished, but some steps failed or produced no output. Please review the logs." + colorReset)
	}

	// List significant output files found
	config.Logger.Println(colorCyan + "\n--- Key Output Files (if generated) ---" + colorReset)
	significantFiles := []string{}
	for _, step := range steps {
		// Only list files that were expected to be created and actually exist with content
		if step.Completed && isStepCompleted(step.OutputFile) {
			significantFiles = append(significantFiles, step.OutputFile)
		}
	}

	if len(significantFiles) > 0 {
		for _, file := range significantFiles {
			fileInfo, err := os.Stat(file)
			if err == nil {
				config.Logger.Printf("- %s (%.2f KB)", file, float64(fileInfo.Size())/1024.0)
			} else {
				config.Logger.Printf("- %s (Error getting stats: %v)", file, err) // Should not happen if isStepCompleted passed
			}
		}
	} else {
		config.Logger.Println("No significant output files were generated or found.")
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
