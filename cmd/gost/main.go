package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/f4nff/gost"
	"github.com/go-log/log"
)

var (
	options route
	routes  []route
)

func init() {
	gost.SetLogger(&gost.LogLogger{})

	var (
		configureFile string
		printVersion  bool
	)

	flag.Var(&options.ChainNodes, "F", "forward address, can make a forward chain")
	flag.Var(&options.ServeNodes, "L", "listen address, can listen on multiple ports")
	flag.StringVar(&configureFile, "C", "", "configure file")
	flag.BoolVar(&options.Debug, "D", false, "enable debug log")
	flag.BoolVar(&printVersion, "V", false, "print version")
	flag.Parse()

	if printVersion {
		fmt.Fprintf(os.Stderr, "gost %s (%s)\n", gost.Version, runtime.Version())
		os.Exit(0)
	}

	if len(options.ServeNodes) > 0 {
		routes = append(routes, options)
	}
	gost.Debug = options.Debug

	if err := loadConfigureFile(configureFile); err != nil {
		log.Log(err)
		os.Exit(1)
	}

	if flag.NFlag() == 0 || len(routes) == 0 {
		flag.PrintDefaults()
		os.Exit(0)
	}

}

func main() {
	// generate random self-signed certificate.
	cert, err := gost.GenCertificate()
	if err != nil {
		log.Log(err)
		os.Exit(1)
	}
	gost.DefaultTLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	for _, route := range routes {
		if err := route.serve(); err != nil {
			log.Log(err)
			os.Exit(1)
		}
	}

	select {}
}

type route struct {
	ChainNodes, ServeNodes stringList
	Retries                int
	Debug                  bool
}

func (r *route) initChain() (*gost.Chain, error) {
	chain := gost.NewChain()
	chain.Retries = r.Retries

	gid := 1 // group ID

	for _, ns := range r.ChainNodes {
		ngroup := gost.NewNodeGroup()
		ngroup.ID = gid
		gid++

		// parse the base node
		nodes, err := parseChainNode(ns)
		if err != nil {
			return nil, err
		}

		nid := 1 // node ID

		for i := range nodes {
			nodes[i].ID = nid
			nid++
		}
		ngroup.AddNode(nodes...)

		// parse peer nodes if exists
		peerCfg, err := loadPeerConfig(nodes[0].Get("peer"))
		if err != nil {
			log.Log(err)
		}
		peerCfg.Validate()
		ngroup.Options = append(ngroup.Options,
			gost.WithFilter(&gost.FailFilter{
				MaxFails:    peerCfg.MaxFails,
				FailTimeout: time.Duration(peerCfg.FailTimeout) * time.Second,
			}),
			gost.WithStrategy(parseStrategy(peerCfg.Strategy)),
		)

		for _, s := range peerCfg.Nodes {
			nodes, err = parseChainNode(s)
			if err != nil {
				return nil, err
			}

			for i := range nodes {
				nodes[i].ID = nid
				nid++
			}

			ngroup.AddNode(nodes...)
		}

		chain.AddNodeGroup(ngroup)
	}

	return chain, nil
}

func parseChainNode(ns string) (nodes []gost.Node, err error) {
	node, err := gost.ParseNode(ns)
	if err != nil {
		return
	}

	users, err := parseUsers(node.Get("secrets"))
	if err != nil {
		return
	}
	if node.User == nil && len(users) > 0 {
		node.User = users[0]
	}
	serverName, sport, _ := net.SplitHostPort(node.Addr)
	if serverName == "" {
		serverName = "localhost" // default server name
	}

	rootCAs, err := loadCA(node.Get("ca"))
	if err != nil {
		return
	}
	tlsCfg := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: !node.GetBool("secure"),
		RootCAs:            rootCAs,
	}
	wsOpts := &gost.WSOptions{}
	wsOpts.EnableCompression = node.GetBool("compression")
	wsOpts.ReadBufferSize = node.GetInt("rbuf")
	wsOpts.WriteBufferSize = node.GetInt("wbuf")
	wsOpts.UserAgent = node.Get("agent")

	var tr gost.Transporter
	switch node.Transport {
	case "tls":
		tr = gost.TLSTransporter()
	case "mtls":
		tr = gost.MTLSTransporter()
	case "ws":
		tr = gost.WSTransporter(wsOpts)
	case "mws":
		tr = gost.MWSTransporter(wsOpts)
	case "wss":
		tr = gost.WSSTransporter(wsOpts)
	case "mwss":
		tr = gost.MWSSTransporter(wsOpts)
	default:
		tr = gost.TCPTransporter()
	}

	var connector gost.Connector
	switch node.Protocol {
	case "socks", "socks5":
		connector = gost.SOCKS5Connector(node.User)
	case "socks4":
		connector = gost.SOCKS4Connector()
	case "socks4a":
		connector = gost.SOCKS4AConnector()
	case "forward":
		connector = gost.ForwardConnector()
	case "http":
		fallthrough
	default:
		node.Protocol = "http" // default protocol is HTTP
		connector = gost.HTTPConnector(node.User)
	}

	timeout := node.GetInt("timeout")
	node.DialOptions = append(node.DialOptions,
		gost.TimeoutDialOption(time.Duration(timeout)*time.Second),
	)

	// 获取参数,提交给F参数
	wsOpts.HandshakeTimeout = time.Duration(node.GetInt("HandshakeTimeout")) * time.Second	
	
	handshakeOptions := []gost.HandshakeOption{
		gost.AddrHandshakeOption(node.Addr),
		gost.HostHandshakeOption(node.Host),
		gost.UserHandshakeOption(node.User),
		gost.TLSConfigHandshakeOption(tlsCfg),
		gost.IntervalHandshakeOption(time.Duration(node.GetInt("ping")) * time.Second),
		gost.TimeoutHandshakeOption(time.Duration(timeout) * time.Second),
		gost.RetryHandshakeOption(node.GetInt("retry")),
		// fixed 2018-04-25
		gost.WSOptionsHandshakeOption(wsOpts),
	}
	node.Client = &gost.Client{
		Connector:   connector,
		Transporter: tr,
	}

	ips := parseIP(node.Get("ip"), sport)
	for _, ip := range ips {
		node.Addr = ip
		node.HandshakeOptions = append(handshakeOptions, gost.AddrHandshakeOption(ip))
		nodes = append(nodes, node)
	}
	if len(ips) == 0 {
		node.HandshakeOptions = handshakeOptions
		nodes = []gost.Node{node}
	}

	return
}

func (r *route) serve() error {
	chain, err := r.initChain()
	if err != nil {
		return err
	}

	for _, ns := range r.ServeNodes {
		node, err := gost.ParseNode(ns)
		if err != nil {
			return err
		}
		users, err := parseUsers(node.Get("secrets"))
		if err != nil {
			return err
		}
		if node.User != nil {
			users = append(users, node.User)
		}
		certFile, keyFile := node.Get("cert"), node.Get("key")
		tlsCfg, err := tlsConfig(certFile, keyFile)
		if err != nil && certFile != "" && keyFile != "" {
			return err
		}

		wsOpts := &gost.WSOptions{}
		wsOpts.EnableCompression = node.GetBool("compression")
		wsOpts.ReadBufferSize = node.GetInt("rbuf")
		wsOpts.WriteBufferSize = node.GetInt("wbuf")

		var ln gost.Listener
		switch node.Transport {
		case "tls":
			ln, err = gost.TLSListener(node.Addr, tlsCfg)
		case "mtls":
			ln, err = gost.MTLSListener(node.Addr, tlsCfg)
		case "ws":
			wsOpts.WriteBufferSize = node.GetInt("wbuf")
			ln, err = gost.WSListener(node.Addr, wsOpts)
		case "mws":
			ln, err = gost.MWSListener(node.Addr, wsOpts)
		case "wss":
			ln, err = gost.WSSListener(node.Addr, tlsCfg, wsOpts)
		case "mwss":
			ln, err = gost.MWSSListener(node.Addr, tlsCfg, wsOpts)
		case "tcp":
			// Directly use SSH port forwarding if the last chain node is forward+ssh
			ln, err = gost.TCPListener(node.Addr)
		case "rtcp":
			// Directly use SSH port forwarding if the last chain node is forward+ssh
			ln, err = gost.TCPRemoteForwardListener(node.Addr, chain)
		case "udp":
			ln, err = gost.UDPDirectForwardListener(node.Addr, time.Duration(node.GetInt("ttl"))*time.Second)
		case "rudp":
			ln, err = gost.UDPRemoteForwardListener(node.Addr, chain, time.Duration(node.GetInt("ttl"))*time.Second)
		default:
			ln, err = gost.TCPListener(node.Addr)
		}
		if err != nil {
			return err
		}

		var whitelist, blacklist *gost.Permissions
		if node.Values.Get("whitelist") != "" {
			if whitelist, err = gost.ParsePermissions(node.Values.Get("whitelist")); err != nil {
				return err
			}
		}
		if node.Values.Get("blacklist") != "" {
			if blacklist, err = gost.ParsePermissions(node.Values.Get("blacklist")); err != nil {
				return err
			}
		}

		var handlerOptions []gost.HandlerOption

		handlerOptions = append(handlerOptions,
			gost.AddrHandlerOption(node.Addr),
			gost.ChainHandlerOption(chain),
			gost.UsersHandlerOption(users...),
			gost.TLSConfigHandlerOption(tlsCfg),
			gost.WhitelistHandlerOption(whitelist),
			gost.BlacklistHandlerOption(blacklist),
		)
		var handler gost.Handler
		switch node.Protocol {
//		case "http2":
//			handler = gost.HTTP2Handler(handlerOptions...)
		case "socks", "socks5":
			handler = gost.SOCKS5Handler(handlerOptions...)
		case "socks4", "socks4a":
			handler = gost.SOCKS4Handler(handlerOptions...)
//		case "ss":
//			handler = gost.ShadowHandler(handlerOptions...)
		case "http":
			handler = gost.HTTPHandler(handlerOptions...)
		case "tcp":
			handler = gost.TCPDirectForwardHandler(node.Remote, handlerOptions...)
		case "rtcp":
			handler = gost.TCPRemoteForwardHandler(node.Remote, handlerOptions...)
		case "udp":
			handler = gost.UDPDirectForwardHandler(node.Remote, handlerOptions...)
		case "rudp":
			handler = gost.UDPRemoteForwardHandler(node.Remote, handlerOptions...)
		default:
			// start from 2.5, if remote is not empty, then we assume that it is a forward tunnel.
			if node.Remote != "" {
				handler = gost.TCPDirectForwardHandler(node.Remote, handlerOptions...)
			} else {
				handler = gost.AutoHandler(handlerOptions...)
			}
		}

		srv := &gost.Server{Listener: ln}
		go srv.Serve(handler)
	}

	return nil
}

// Load the certificate from cert and key files, will use the default certificate if the provided info are invalid.
func tlsConfig(certFile, keyFile string) (*tls.Config, error) {
	if certFile == "" {
		certFile = "cert.pem"
	}
	if keyFile == "" {
		keyFile = "key.pem"
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}

func loadCA(caFile string) (cp *x509.CertPool, err error) {
	if caFile == "" {
		return
	}
	cp = x509.NewCertPool()
	data, err := ioutil.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	if !cp.AppendCertsFromPEM(data) {
		return nil, errors.New("AppendCertsFromPEM failed")
	}
	return
}

func loadConfigureFile(configureFile string) error {
	if configureFile == "" {
		return nil
	}
	content, err := ioutil.ReadFile(configureFile)
	if err != nil {
		return err
	}
	var cfg struct {
		route
		Routes []route
	}
	if err := json.Unmarshal(content, &cfg); err != nil {
		return err
	}

	if len(cfg.route.ServeNodes) > 0 {
		routes = append(routes, cfg.route)
	}
	for _, route := range cfg.Routes {
		if len(route.ServeNodes) > 0 {
			routes = append(routes, route)
		}
	}
	gost.Debug = cfg.Debug

	return nil
}

type stringList []string

func (l *stringList) String() string {
	return fmt.Sprintf("%s", *l)
}
func (l *stringList) Set(value string) error {
	*l = append(*l, value)
	return nil
}

func parseUsers(authFile string) (users []*url.Userinfo, err error) {
	if authFile == "" {
		return
	}

	file, err := os.Open(authFile)
	if err != nil {
		return
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		s := strings.SplitN(line, " ", 2)
		if len(s) == 1 {
			users = append(users, url.User(strings.TrimSpace(s[0])))
		} else if len(s) == 2 {
			users = append(users, url.UserPassword(strings.TrimSpace(s[0]), strings.TrimSpace(s[1])))
		}
	}

	err = scanner.Err()
	return
}

func parseIP(s string, port string) (ips []string) {
	if s == "" {
		return
	}
	if port == "" {
		port = "8080" // default port
	}

	file, err := os.Open(s)
	if err != nil {
		ss := strings.Split(s, ",")
		for _, s := range ss {
			s = strings.TrimSpace(s)
			if s != "" {
				if !strings.Contains(s, ":") {
					s = s + ":" + port
				}
				ips = append(ips, s)
			}

		}
		return
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, ":") {
			line = line + ":" + port
		}
		ips = append(ips, line)
	}
	return
}

type peerConfig struct {
	Strategy    string   `json:"strategy"`
	Filters     []string `json:"filters"`
	MaxFails    int      `json:"max_fails"`
	FailTimeout int      `json:"fail_timeout"`
	Nodes       []string `json:"nodes"`
}

func loadPeerConfig(peer string) (config peerConfig, err error) {
	if peer == "" {
		return
	}
	content, err := ioutil.ReadFile(peer)
	if err != nil {
		return
	}
	err = json.Unmarshal(content, &config)
	return
}

func (cfg *peerConfig) Validate() {
	if cfg.MaxFails <= 0 {
		cfg.MaxFails = 1
	}
	if cfg.FailTimeout <= 0 {
		cfg.FailTimeout = 30 // seconds
	}
}

func parseStrategy(s string) gost.Strategy {
	switch s {
	case "random":
		return &gost.RandomStrategy{}
	case "fifo":
		return &gost.FIFOStrategy{}
	case "round":
		fallthrough
	default:
		return &gost.RoundStrategy{}

	}
}
