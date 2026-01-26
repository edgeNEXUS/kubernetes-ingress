package edge

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"

	"github.com/edgeNEXUS/kubernetes-ingress/internal/metrics/collectors"

	"github.com/golang/glog"
)

const (
	ReloadForEndpointsUpdate     = true  // ReloadForEndpointsUpdate means that is caused by an endpoints update.
	ReloadForOtherUpdate         = false // ReloadForOtherUpdate means that a reload is caused by an update for a resource(s) other than endpoints.
	TLSSecretFileMode            = 0o600 // TLSSecretFileMode defines the default filemode for files with TLS Secrets.
	JWKSecretFileMode            = 0o644 // JWKSecretFileMode defines the default filemode for files with JWK Secrets.
	configFileMode               = 0o644
	jsonFileForOpenTracingTracer = "/var/lib/edgenexus-manager/tracer-config.json"
	edgeBinaryPath               = "/edgenexus-manager"
	edgeBinaryPathDebug          = "/edgenexus-manager"

	appProtectPluginStartCmd = "/usr/share/ts/bin/bd-socket-plugin"
	appProtectAgentStartCmd  = "/opt/app_protect/bin/bd_agent"

	// appPluginParams is the configuration of App-Protect plugin
	appPluginParams = "tmm_count 4 proc_cpuinfo_cpu_mhz 2000000 total_xml_memory 307200000 total_umu_max_size 3129344 sys_max_account_id 1024 no_static_config"

	// appProtectDebugLogConfigFileContent holds the content of the file to be written when Edgenexus debug is enabled. It will enable Edgenexus App Protect debug logs
	appProtectDebugLogConfigFileContent = "MODULE = IO_PLUGIN;\nLOG_LEVEL = TS_INFO | TS_DEBUG;\nFILE = 2;\nMODULE = ECARD_POLICY;\nLOG_LEVEL = TS_INFO | TS_DEBUG;\nFILE = 2;\n"

	// appProtectLogConfigFileName is the location of the Edgenexus App Protect logging configuration file
	appProtectLogConfigFileName = "/etc/app_protect/bd/logger.cfg"
)

// The Manager interface updates Edgenexus configuration, starts, reloads and quits Edgenexus,
// updates 'Edgenexus +' upstream servers.
type Manager interface {
	CreateMainConfig(content []byte)
	CreateConfig(name string, content []byte)
	DeleteConfig(name string)
	CreateStreamConfig(name string, content []byte)
	DeleteStreamConfig(name string)
	CreateTLSPassthroughHostsConfig(content []byte)
	CreateSecret(name string, content []byte, mode os.FileMode) string
	DeleteSecret(name string)
	CreateAppProtectResourceFile(name string, content []byte)
	DeleteAppProtectResourceFile(name string)
	ClearAppProtectFolder(name string)
	GetFilenameForSecret(name string) string
	CreateDHParam(content string) (string, error)
	CreateOpenTracingTracerConfig(content string) error
	Start(done chan error)
	Version() string
	Reload(isEndpointsUpdate bool) error
	Quit()
	UpdateConfigVersionFile(openTracing bool)
	//	SetPlusClients(plusClient *client.EdgeClient, plusConfigVersionCheckClient *http.Client)
	//	UpdateServersInPlus(upstream string, servers []string, config ServerConfig) error
	//	UpdateStreamServersInPlus(upstream string, servers []string) error
	SetOpenTracing(openTracing bool)
	AppProtectAgentStart(apaDone chan error, debug bool)
	AppProtectAgentQuit()
	AppProtectPluginStart(appDone chan error)
	AppProtectPluginQuit()
}

// LocalManager updates Edgenexus configuration, starts, reloads and quits Edgenexus,
// updates 'Edgenexus +' upstream servers. It assumes that Edgenexus is running in the same container.
type LocalManager struct {
	confdPath                   string
	streamConfdPath             string
	secretsPath                 string
	mainConfFilename            string
	configVersionFilename       string
	debug                       bool
	dhparamFilename             string
	tlsPassthroughHostsFilename string
	verifyConfigGenerator       *verifyConfigGenerator
	verifyClient                *verifyClient
	configVersion               int
	//	plusClient                   *client.EdgeClient
	plusConfigVersionCheckClient *http.Client
	metricsCollector             collectors.ManagerCollector
	OpenTracing                  bool
	appProtectPluginPid          int
	appProtectAgentPid           int
}

// NewLocalManager creates a LocalManager.
func NewLocalManager(confPath string, debug bool, mc collectors.ManagerCollector, timeout time.Duration) *LocalManager {
	verifyConfigGenerator, err := newVerifyConfigGenerator()
	if err != nil {
		glog.Fatalf("error instantiating a verifyConfigGenerator: %v", err)
	}

	manager := LocalManager{
		confdPath:                   path.Join(confPath, "conf.d"),
		streamConfdPath:             path.Join(confPath, "stream-conf.d"),
		secretsPath:                 path.Join(confPath, "secrets"),
		dhparamFilename:             path.Join(confPath, "secrets", "dhparam.pem"),
		mainConfFilename:            path.Join(confPath, "edge.yaml"),
		configVersionFilename:       path.Join(confPath, "config-version.yaml"),
		tlsPassthroughHostsFilename: path.Join(confPath, "tls-passthrough-hosts.yaml"),
		debug:                       debug,
		verifyConfigGenerator:       verifyConfigGenerator,
		configVersion:               0,
		verifyClient:                newVerifyClient(timeout),
		metricsCollector:            mc,
	}

	return &manager
}

// CreateMainConfig creates the main Edgenexus configuration file. If the file already exists, it will be overridden.
func (lm *LocalManager) CreateMainConfig(content []byte) {
	glog.V(3).Infof("Writing main config to %v", lm.mainConfFilename)
	glog.V(3).Infof(string(content))

	err := createFileAndWrite(lm.mainConfFilename, content)
	if err != nil {
		glog.Fatalf("Failed to write main config: %v", err)
	}
}

// CreateConfig creates a configuration file. If the file already exists, it will be overridden.
func (lm *LocalManager) CreateConfig(name string, content []byte) {
	createConfig(lm.getFilenameForConfig(name), content)
}

func createConfig(filename string, content []byte) {
	glog.V(3).Infof("Writing config to %v", filename)
	glog.V(3).Info(string(content))

	err := createFileAndWrite(filename, content)
	if err != nil {
		glog.Fatalf("Failed to write config to %v: %v", filename, err)
	}
}

// DeleteConfig deletes the configuration file from the conf.d folder.
func (lm *LocalManager) DeleteConfig(name string) {
	deleteConfig(lm.getFilenameForConfig(name))
}

func deleteConfig(filename string) {
	glog.V(3).Infof("Deleting config from %v", filename)

	if err := os.Remove(filename); err != nil {
		glog.Warningf("Failed to delete config from %v: %v", filename, err)
	}
}

func (lm *LocalManager) getFilenameForConfig(name string) string {
	return path.Join(lm.confdPath, name+".yaml")
}

// CreateStreamConfig creates a configuration file for stream module.
// If the file already exists, it will be overridden.
func (lm *LocalManager) CreateStreamConfig(name string, content []byte) {
	createConfig(lm.getFilenameForStreamConfig(name), content)
}

// DeleteStreamConfig deletes the configuration file from the stream-conf.d folder.
func (lm *LocalManager) DeleteStreamConfig(name string) {
	deleteConfig(lm.getFilenameForStreamConfig(name))
}

func (lm *LocalManager) getFilenameForStreamConfig(name string) string {
	return path.Join(lm.streamConfdPath, name+".yaml")
}

// CreateTLSPassthroughHostsConfig creates a configuration file with mapping between TLS Passthrough hosts and
// the corresponding unix sockets.
// If the file already exists, it will be overridden.
func (lm *LocalManager) CreateTLSPassthroughHostsConfig(content []byte) {
	glog.V(3).Infof("Writing TLS Passthrough Hosts config file to %v", lm.tlsPassthroughHostsFilename)
	createConfig(lm.tlsPassthroughHostsFilename, content)
}

// CreateSecret creates a secret file with the specified name, content and mode. If the file already exists,
// it will be overridden.
func (lm *LocalManager) CreateSecret(name string, content []byte, mode os.FileMode) string {
	filename := lm.GetFilenameForSecret(name)

	glog.V(3).Infof("Writing secret to %v", filename)

	createFileAndWriteAtomically(filename, lm.secretsPath, mode, content)

	return filename
}

// DeleteSecret the file with the secret.
func (lm *LocalManager) DeleteSecret(name string) {
	filename := lm.GetFilenameForSecret(name)

	glog.V(3).Infof("Deleting secret from %v", filename)

	if err := os.Remove(filename); err != nil {
		glog.Warningf("Failed to delete secret from %v: %v", filename, err)
	}
}

// GetFilenameForSecret constructs the filename for the secret.
func (lm *LocalManager) GetFilenameForSecret(name string) string {
	return path.Join(lm.secretsPath, name)
}

// CreateDHParam creates the servers dhparam.pem file. If the file already exists, it will be overridden.
func (lm *LocalManager) CreateDHParam(content string) (string, error) {
	glog.V(3).Infof("Writing dhparam file to %v", lm.dhparamFilename)

	err := createFileAndWrite(lm.dhparamFilename, []byte(content))
	if err != nil {
		return lm.dhparamFilename, fmt.Errorf("Failed to write dhparam file from %v: %w", lm.dhparamFilename, err)
	}

	return lm.dhparamFilename, nil
}

// CreateAppProtectResourceFile writes contents of An App Protect resource to a file
func (lm *LocalManager) CreateAppProtectResourceFile(name string, content []byte) {
	glog.V(3).Infof("Writing App Protect Resource to %v", name)
	err := createFileAndWrite(name, content)
	if err != nil {
		glog.Fatalf("Failed to write App Protect Resource to %v: %v", name, err)
	}
}

// DeleteAppProtectResourceFile removes an App Protect resource file from storage
func (lm *LocalManager) DeleteAppProtectResourceFile(name string) {
	// This check is done to avoid errors in case eg. a policy is referenced, but it never became valid.
	if _, err := os.Stat(name); !os.IsNotExist(err) {
		if err := os.Remove(name); err != nil {
			glog.Fatalf("Failed to delete App Protect Resource from %v: %v", name, err)
		}
	}
}

// ClearAppProtectFolder clears contents of a config folder
func (lm *LocalManager) ClearAppProtectFolder(name string) {
	files, err := ioutil.ReadDir(name)
	if err != nil {
		glog.Fatalf("Failed to read the App Protect folder %s: %v", name, err)
	}
	for _, file := range files {
		lm.DeleteAppProtectResourceFile(fmt.Sprintf("%s/%s", name, file.Name()))
	}
}

// Start starts Edgenexus.
func (lm *LocalManager) Start(done chan error) {
	glog.V(3).Info("Starting EdgeNEXUS Manager")

	binaryFilename := getBinaryFileName(lm.debug)
	cmd := exec.Command(binaryFilename)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		glog.Fatalf("Failed to start EdgeNEXUS Manager: %v", err)
	}

	go func() {
		done <- cmd.Wait()
	}()
	err := lm.verifyClient.WaitForCorrectVersion(lm.configVersion)
	if err != nil {
		glog.Fatalf("Could not get newest config version: %v", err)
	}
}

// Reload reloads Edgenexus.
func (lm *LocalManager) Reload(isEndpointsUpdate bool) error {
	// write a new config version
	lm.configVersion++
	lm.UpdateConfigVersionFile(lm.OpenTracing)

	glog.V(3).Infof("Reloading EdgeNEXUS Manager with configVersion: %v", lm.configVersion)

	t1 := time.Now()

	binaryFilename := getBinaryFileName(lm.debug)
	if err := shellOut(fmt.Sprintf("%v -s %v", binaryFilename, "reload")); err != nil {
		lm.metricsCollector.IncEdgeReloadErrors()
		return fmt.Errorf("EdgeNEXUS Manager reload failed: %w", err)
	}
	err := lm.verifyClient.WaitForCorrectVersion(lm.configVersion)
	if err != nil {
		lm.metricsCollector.IncEdgeReloadErrors()
		return fmt.Errorf("could not get newest config version: %w", err)
	}

	lm.metricsCollector.IncEdgeReloadCount(isEndpointsUpdate)

	t2 := time.Now()
	lm.metricsCollector.UpdateLastReloadTime(t2.Sub(t1))
	return nil
}

// Quit shutdowns Edgenexus gracefully.
func (lm *LocalManager) Quit() {
	glog.V(3).Info("Quitting EdgeNEXUS Manager")

	binaryFilename := getBinaryFileName(lm.debug)
	if err := shellOut(fmt.Sprintf("%v -s %v", binaryFilename, "quit")); err != nil {
		glog.Fatalf("Failed to quit EdgeNEXUS Manager: %v", err)
	}
}

// Version returns Edgenexus version
func (lm *LocalManager) Version() string {
	binaryFilename := getBinaryFileName(lm.debug)
	out, err := exec.Command(binaryFilename, "-v").CombinedOutput()
	if err != nil {
		glog.Fatalf("Failed to get EdgeNEXUS Manager version: %v", err)
	}
	return string(out)
}

// UpdateConfigVersionFile writes the config version file.
func (lm *LocalManager) UpdateConfigVersionFile(openTracing bool) {
	cfg, err := lm.verifyConfigGenerator.GenerateVersionConfig(lm.configVersion, openTracing)
	if err != nil {
		glog.Fatalf("Error generating config version content: %v", err)
	}

	glog.V(3).Infof("Writing config version to %v", lm.configVersionFilename)
	glog.V(3).Info(string(cfg))

	createFileAndWriteAtomically(lm.configVersionFilename, path.Dir(lm.configVersionFilename), configFileMode, cfg)
}

// CreateOpenTracingTracerConfig creates a json configuration file for the OpenTracing tracer with the content of the string.
func (lm *LocalManager) CreateOpenTracingTracerConfig(content string) error {
	glog.V(3).Infof("Writing OpenTracing tracer config file to %v", jsonFileForOpenTracingTracer)
	err := createFileAndWrite(jsonFileForOpenTracingTracer, []byte(content))
	if err != nil {
		return fmt.Errorf("Failed to write config file: %w", err)
	}

	return nil
}

// SetOpenTracing sets the value of OpenTracing for the Manager
func (lm *LocalManager) SetOpenTracing(openTracing bool) {
	lm.OpenTracing = openTracing
}

// AppProtectAgentStart starts the AppProtect agent
func (lm *LocalManager) AppProtectAgentStart(apaDone chan error, debug bool) {
	if debug {
		glog.V(3).Info("Starting AppProtect Agent in debug mode")
		err := os.Remove(appProtectLogConfigFileName)
		if err != nil {
			glog.Fatalf("Failed removing App Protect Log configuration file")
		}
		err = createFileAndWrite(appProtectLogConfigFileName, []byte(appProtectDebugLogConfigFileContent))
		if err != nil {
			glog.Fatalf("Failed Writing App Protect Log configuration file")
		}
	}
	glog.V(3).Info("Starting AppProtect Agent")

	cmd := exec.Command(appProtectAgentStartCmd)
	if err := cmd.Start(); err != nil {
		glog.Fatalf("Failed to start AppProtect Agent: %v", err)
	}
	lm.appProtectAgentPid = cmd.Process.Pid
	go func() {
		apaDone <- cmd.Wait()
	}()
}

// AppProtectAgentQuit gracefully ends AppProtect Agent.
func (lm *LocalManager) AppProtectAgentQuit() {
	glog.V(3).Info("Quitting AppProtect Agent")
	killcmd := fmt.Sprintf("kill %d", lm.appProtectAgentPid)
	if err := shellOut(killcmd); err != nil {
		glog.Fatalf("Failed to quit AppProtect Agent: %v", err)
	}
}

// AppProtectPluginStart starts the AppProtect plugin.
func (lm *LocalManager) AppProtectPluginStart(appDone chan error) {
	glog.V(3).Info("Starting AppProtect Plugin")
	startupParams := strings.Fields(appPluginParams)
	cmd := exec.Command(appProtectPluginStartCmd, startupParams...)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stdout
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "LD_LIBRARY_PATH=/usr/lib64/bd")

	if err := cmd.Start(); err != nil {
		glog.Fatalf("Failed to start AppProtect Plugin: %v", err)
	}
	lm.appProtectPluginPid = cmd.Process.Pid
	go func() {
		appDone <- cmd.Wait()
	}()
}

// AppProtectPluginQuit gracefully ends AppProtect Agent.
func (lm *LocalManager) AppProtectPluginQuit() {
	glog.V(3).Info("Quitting AppProtect Plugin")
	killcmd := fmt.Sprintf("kill %d", lm.appProtectPluginPid)
	if err := shellOut(killcmd); err != nil {
		glog.Fatalf("Failed to quit AppProtect Plugin: %v", err)
	}
}

func getBinaryFileName(debug bool) string {
	if debug {
		return edgeBinaryPathDebug
	}
	return edgeBinaryPath
}
