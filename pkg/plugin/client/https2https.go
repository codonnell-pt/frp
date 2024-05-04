// Copyright 2019 fatedier, fatedier@gmail.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !frps

package plugin

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/fatedier/golib/pool"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/transport"
	"github.com/fatedier/frp/pkg/util/log"
	netpkg "github.com/fatedier/frp/pkg/util/net"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

func init() {
	Register(v1.PluginHTTPS2HTTPS, NewHTTPS2HTTPSPlugin)
}

type HTTPS2HTTPSPlugin struct {
	opts *v1.HTTPS2HTTPSPluginOptions

	l *Listener
	s *http.Server
}

func NewHTTPS2HTTPSPlugin(options v1.ClientPluginOptions) (Plugin, error) {
	opts := options.(*v1.HTTPS2HTTPSPluginOptions)

	listener := NewProxyListener()

	p := &HTTPS2HTTPSPlugin{
		opts: opts,
		l:    listener,
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.Header["X-Forwarded-For"] = r.In.Header["X-Forwarded-For"]
			r.SetXForwarded()
			req := r.Out
			req.URL.Scheme = "https"
			req.URL.Host = p.opts.LocalAddr
			if p.opts.HostHeaderRewrite != "" {
				req.Host = p.opts.HostHeaderRewrite
			}
			for k, v := range p.opts.RequestHeaders.Set {
				req.Header.Set(k, v)
			}
		},
		Transport:  tr,
		BufferPool: pool.NewBuffer(32 * 1024),
		ErrorLog:   stdlog.New(log.NewWriteLogger(log.WarnLevel, 2), "", 0),
	}

	p.s = &http.Server{
		Handler:           rp,
		ReadHeaderTimeout: 60 * time.Second,
	}

	var (
		tlsConfig *tls.Config
		err       error
	)
	if opts.CrtPath != "" || opts.KeyPath != "" {
		tlsConfig, err = p.genTLSConfig()
	} else {
		tlsConfig, err = transport.NewServerTLSConfig("", "", "")
		tlsConfig.InsecureSkipVerify = true
	}
	if err != nil {
		return nil, fmt.Errorf("gen TLS config error: %v", err)
	}
	ln := tls.NewListener(listener, tlsConfig)

	go func() {
		_ = p.s.Serve(ln)
	}()
	return p, nil
}

func (p *HTTPS2HTTPSPlugin) genTLSConfig() (*tls.Config, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion("eu-west-2"))
	if err != nil {
		log.Errorf("unable to load SDK config, do you have the env set ?, %v", err)
	}

	client := ssm.NewFromConfig(cfg)

	certParam := "arn:aws:ssm:eu-west-2:956880242582:parameter/paythru/sslcerts/wildcard.tunnels.paythrutools.com/cert.pem"
	keyParam := "arn:aws:ssm:eu-west-2:956880242582:parameter/paythru/sslcerts/wildcard.tunnels.paythrutools.com/privkey.pem"

	result, err := client.GetParameter(context.TODO(), &ssm.GetParameterInput{
		Name:           &certParam,
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		log.Errorf("unable to get cert, %v", err)
	}
	certValue := *result.Parameter.Value

	result, err = client.GetParameter(context.TODO(), &ssm.GetParameterInput{
		Name:           &keyParam,
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		log.Errorf("unable to get key, %v", err)
	}
	keyValue := *result.Parameter.Value

	cert, err := tls.X509KeyPair([]byte(certValue), []byte(keyValue))
	if err != nil {
		return nil, err
	}

	config := &tls.Config{Certificates: []tls.Certificate{cert}}
	return config, nil
}

func (p *HTTPS2HTTPSPlugin) Handle(conn io.ReadWriteCloser, realConn net.Conn, extra *ExtraInfo) {
	wrapConn := netpkg.WrapReadWriteCloserToConn(conn, realConn)
	if extra.SrcAddr != nil {
		wrapConn.SetRemoteAddr(extra.SrcAddr)
	}
	_ = p.l.PutConn(wrapConn)
}

func (p *HTTPS2HTTPSPlugin) Name() string {
	return v1.PluginHTTPS2HTTPS
}

func (p *HTTPS2HTTPSPlugin) Close() error {
	return p.s.Close()
}
